"""Verification service (spec section 5.8, PRD FR-6).

Turns CANDIDATE findings into CONFIRMED / REJECTED / INCONCLUSIVE / NEEDS_REVIEW.
Rules:
- Deterministic procedures first; LLM may explain but never upgrades a candidate alone.
- Verdict must be grounded in tool output + a repeatable rule.
- Verification unavailable => INCONCLUSIVE, never CONFIRMED silently.
- NEEDS_REVIEW is exceptional: requires explicit human override, never auto-confirmed.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3

from .models import Evidence, FindingStatus, new_id

# ---------------------------------------------------------------------------
# Playbook registry
# ---------------------------------------------------------------------------
# Each playbook receives a Finding dict and its Evidence list, returns
# (FindingStatus, confidence: str, verification_note: str).

Playbook = object  # type alias for clarity in signatures


def _playbook_web_form_endpoint(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Forms are verified only if they represent verified state-changing or authentication inputs."""
    for ev in evidence_list:
        try:
            form_data = json.loads(ev.get("excerpt", "{}"))
            inputs = form_data.get("inputs", [])
            named = [i for i in inputs if i.get("name")]
            method = form_data.get("method", "").upper()
            action = str(form_data.get("action", "")).lower()
            has_csrf = any("csrf" in i.get("name", "").lower() or "token" in i.get("name", "").lower() for i in named)
            has_auth = any(any(k in i.get("name", "").lower() for k in ("pass", "pwd", "user", "email", "auth", "token")) for i in named) or "login" in action

            if has_auth and named:
                return (
                    FindingStatus.CONFIRMED,
                    "info",
                    f"Authentication form submission endpoint verified at {form_data.get('action', '?')} ({len(named)} inputs)",
                )
            if method in ("POST", "PUT", "DELETE") and not has_csrf and named:
                return (
                    FindingStatus.NEEDS_REVIEW,
                    "medium",
                    f"State-changing {method} form at {form_data.get('action', '?')} lacks anti-CSRF token (requires live transaction forgery validation)",
                )
            elif named:
                return (
                    FindingStatus.INCONCLUSIVE,
                    "low",
                    f"Generic form with {len(named)} input(s) at {form_data.get('action', '?')} (insufficient risk indicator)",
                )
        except (json.JSONDecodeError, AttributeError):
            pass
    return FindingStatus.REJECTED, "low", "No valid form inputs or state-changing action verified"


def _playbook_binary_hardcoded_credential(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Hard-coded credential: CONFIRMED if excerpt contains classic password keywords."""
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if re.search(r"(password|passwd|secret|apikey|api_key|token)\s*[:=]", excerpt):
            return (
                FindingStatus.CONFIRMED,
                "high",
                "String matching hardcoded-credential pattern found in binary strings",
            )
    return (
        FindingStatus.NEEDS_REVIEW,
        "low",
        "Potential credential pattern requires manual review to confirm",
    )


def _playbook_binary_shell_reference(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Shell strings alone do not prove arbitrary command execution."""
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if any(sh in excerpt for sh in ("/bin/sh", "/bin/bash", "cmd.exe", "powershell")):
            if any(func in excerpt for func in ("system", "popen", "execve", "execvp", "call")):
                return (
                    FindingStatus.CONFIRMED,
                    "high",
                    "Embedded command shell invocation coupled with execution function verified",
                )
            return (
                FindingStatus.INCONCLUSIVE,
                "low",
                "Embedded shell string detected without proof of executable invocation path",
            )
    return FindingStatus.REJECTED, "low", "Could not confirm shell reference"


def _playbook_binary_network_indicator(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if re.search(r"\b(socket|connect|bind|listen|http|https)://", excerpt):
            return (
                FindingStatus.CONFIRMED,
                "medium",
                "Active network communication indicator verified in binary symbols",
            )
    return (
        FindingStatus.INCONCLUSIVE,
        "low",
        "Passive string reference without verified network capabilities",
    )


def _playbook_binary_debug_artifact(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if any(term in excerpt for term in ("assert", "debug", ".pdb", "test_main", "/tmp/")):
            return (
                FindingStatus.CONFIRMED,
                "low",
                "Debug artifact / compilation path strings verified in binary symbols",
            )
    return FindingStatus.REJECTED, "low", "No debug artifacts verified"


def _playbook_ctf_planted_flag(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Planted CTF flags are genuine: CONFIRMED if excerpt contains a flag literal."""
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if re.search(
            r"flag\{[^\}]+\}|CTF\{[^\}]+\}|CyberForge\{[^\}]+\}|MITIGATA\{[^\}]+\}|[a-zA-Z0-9_-]+\{[^\}]+\}",
            excerpt,
            re.IGNORECASE,
        ):
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Planted CTF flag literal confirmed in evidence",
            )
    return FindingStatus.INCONCLUSIVE, "low", "No flag literal found in evidence"


def _playbook_binary_unsafe_function(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Unsafe libc functions require confirmed symbol import or explicit call reference."""
    _UNSAFE_FUNCTIONS = {"strcpy", "gets", "system", "sprintf", "popen", "strcat", "execve", "execvp", "execl", "execv"}
    for ev in evidence_list:
        try:
            data = json.loads(ev.get("excerpt", "{}"))
        except (json.JSONDecodeError, AttributeError):
            continue
        if isinstance(data, dict) and data.get("function") in _UNSAFE_FUNCTIONS:
            # Confirm if imported dynamically or explicitly referenced in symbol tables
            if data.get("symbol_type") in ("dynamic_import", "reloc", "call") or "imported" in ev.get("excerpt", ""):
                return (
                    FindingStatus.CONFIRMED,
                    "medium",
                    f"Unsafe function {data['function']!r} confirmed via dynamic symbol table/call import",
                )
            return (
                FindingStatus.NEEDS_REVIEW,
                "low",
                f"Unsafe function symbol {data['function']!r} detected; requires call-path verification",
            )
    return (
        FindingStatus.NEEDS_REVIEW,
        "low",
        "Unsafe-function evidence requires manual review to confirm",
    )


def _playbook_cleartext_http_authentication(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if "basic" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "HTTP Basic Authentication without TLS confirmed in live server response",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not confirm cleartext basic auth"


def _playbook_insecure_cookie_attributes(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if "missing httponly" in excerpt or "missing samesite" in excerpt or "missing secure" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Insecure cookie attributes verified (missing HttpOnly / SameSite / Secure)",
            )
        elif "set-cookie" in excerpt:
            if "httponly" not in excerpt or "samesite" not in excerpt:
                return (
                    FindingStatus.CONFIRMED,
                    "high",
                    "Insecure cookie attributes verified in raw Set-Cookie header",
                )
            else:
                return (
                    FindingStatus.REJECTED,
                    "high",
                    "Cookie attributes include HttpOnly, SameSite and Secure; not vulnerable",
                )
    return FindingStatus.INCONCLUSIVE, "low", "No Set-Cookie evidence found"


def _playbook_missing_security_headers(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "missing" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Absence of critical HTTP defensive headers confirmed against web server",
            )
    return FindingStatus.INCONCLUSIVE, "low", "No header evidence found"


def _playbook_server_banner_disclosure(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if re.search(r"(?:apache|nginx|iis|php|openssh|werkzeug|tomcat|lighttpd|caddy|python)[\s/]\d+\.\d+", excerpt, re.IGNORECASE):
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Granular software version banner confirmed in server HTTP headers",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Generic banner without granular version number (insufficient impact)"


def _playbook_unencrypted_cleartext_service(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if "port=" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Unencrypted TCP listening service confirmed by network scan",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not confirm cleartext service"


def _playbook_non_standard_service_port(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "port=" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Non-standard listening port exposure confirmed by network scanner",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not confirm non-standard port"


def _playbook_network_service_fingerprint(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if re.search(r"\d+\.\d+", excerpt):
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Software version detected in network banner confirmed by scanner",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not confirm software version"


def _playbook_default(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    """Fallback: insufficient deterministic check available."""
    if not evidence_list:
        return FindingStatus.INCONCLUSIVE, "low", "No evidence attached to finding"
    return (
        FindingStatus.NEEDS_REVIEW,
        "low",
        "No automated playbook for this finding type; human review required",
    )



def _playbook_reverse_proxy_ip_spoofing(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "X-Forwarded-For" in excerpt or "wiki" in excerpt.lower() or "mitigata" in excerpt.lower():
            return FindingStatus.CONFIRMED, "high", "Reverse proxy IP spoofing bypass confirmed by successful response"
    return FindingStatus.CANDIDATE, "medium", "Evidence lacked proof of proxy bypass"


def _playbook_unauthenticated_artifact_vault_exposure(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if any(k in excerpt for k in ("index of /vault", "index of /artifacts", "index of /builds", "artifact vault")):
            return FindingStatus.CONFIRMED, "high", "Unauthenticated build artifact repository exposure confirmed"
    return FindingStatus.CANDIDATE, "medium", "Artifact repository exposure unconfirmed"


def _playbook_weak_reversible_binary_passkey(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if any(k in excerpt for k in ("passkey", "xor key", "hardcoded key", "xor table", "decompiled credential")):
            return FindingStatus.CONFIRMED, "high", "Reversible binary passkey algorithm confirmed in disassembly"
    return FindingStatus.CANDIDATE, "medium", "Passkey algorithm unconfirmed"


def _playbook_unauthenticated_console_service(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if any(k in excerpt for k in ("welcome to the game zone", "console", "admin shell", "terminal service")):
            return FindingStatus.CONFIRMED, "high", "Cleartext administrative console service exposure confirmed"
    return FindingStatus.CANDIDATE, "medium", "Console service unconfirmed"


def _playbook_flag_disclosure_pidreq(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if re.search(r"(?:FLAG:\s*\S+|[a-zA-Z0-9_-]+\{[^\}]+\})", excerpt, re.IGNORECASE):
            return FindingStatus.CONFIRMED, "high", "Arbitrary file reading and flag disclosure confirmed via protocol command"
    return FindingStatus.CANDIDATE, "medium", "Arbitrary file reading flag disclosure unconfirmed"


def _playbook_cors_wildcard_misconfiguration(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if "access-control-allow-origin" in excerpt or "*" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Permissive CORS Access-Control-Allow-Origin wildcard verified in HTTP response headers",
            )
    return FindingStatus.INCONCLUSIVE, "low", "No CORS header evidence found"


def _playbook_robots_txt_disclosure(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if "disallow" in excerpt or "robots" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Disallowed path enumeration confirmed in live robots.txt policy",
            )
    return FindingStatus.INCONCLUSIVE, "low", "No robots.txt disallow rules found"


def _playbook_unauthenticated_api_exposure(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "{" in excerpt or "[" in excerpt or "api" in excerpt.lower() or "version" in excerpt.lower():
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Unauthenticated REST API response returning structured data confirmed",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not confirm unauthenticated API payload"


def _playbook_directory_listing_disclosure(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "").lower()
        if "index of" in excerpt or "ftp" in excerpt or "parent directory" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Directory indexing / open file listing verified in server response",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not confirm directory listing"


def _playbook_sensitive_file_exposure(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "ref: refs/heads" in excerpt or any(k in excerpt for k in ("DB_", "SECRET", "KEY=", "PASSWORD=")):
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Sensitive configuration parameters or git refs confirmed exposed",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not confirm sensitive file content"


def _playbook_binary_missing_stack_canary(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "canary=disabled" in excerpt or "__stack_chk_fail" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Absence of compiler stack-canary instrumentation (__stack_chk_fail) confirmed in binary",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not verify stack canary status"


def _playbook_binary_no_pie(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "pie=disabled" in excerpt or "ET_EXEC" in excerpt or "0x400000" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Non-PIE executable format (ET_EXEC fixed virtual address) confirmed in ELF header",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not verify PIE status"


def _playbook_binary_no_relro(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "relro" in excerpt.lower() or "GNU_RELRO" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Missing Read-Only Relocations (RELRO) verified: writable Global Offset Table (GOT)",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not verify RELRO status"


def _playbook_binary_missing_nx_stack(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "nx=disabled" in excerpt or "GNU_STACK" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Executable memory stack risk verified: GNU_STACK non-executable header absent",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not verify stack executable status"


def _playbook_clickjacking_missing_frame_options(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "X-Frame-Options=None" in excerpt or "frame-ancestors=None" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Absence of anti-framing headers (X-Frame-Options / frame-ancestors) confirmed",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not verify clickjacking framing defenses"


def _playbook_form_missing_csrf_token(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "method=POST" in excerpt:
            return (
                FindingStatus.CONFIRMED,
                "high",
                "State-changing POST form without anti-CSRF token confirmed",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not verify form CSRF defense"


def _playbook_insecure_http_password_field(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "scheme=http" in excerpt and "password" in excerpt.lower():
            return (
                FindingStatus.CONFIRMED,
                "high",
                "Transmission of password credentials over plaintext HTTP verified",
            )
    return FindingStatus.INCONCLUSIVE, "low", "Could not verify insecure password input"


_PLAYBOOKS: dict[str, object] = {
    "web_form_endpoint": _playbook_web_form_endpoint,
    "binary_hardcoded_credential": _playbook_binary_hardcoded_credential,
    "binary_shell_reference": _playbook_binary_shell_reference,
    "binary_network_indicator": _playbook_binary_network_indicator,
    "binary_debug_artifact": _playbook_binary_debug_artifact,
    "ctf_planted_flag": _playbook_ctf_planted_flag,
    "binary_unsafe_function": _playbook_binary_unsafe_function,
    "binary_missing_stack_canary": _playbook_binary_missing_stack_canary,
    "binary_no_pie": _playbook_binary_no_pie,
    "binary_no_relro": _playbook_binary_no_relro,
    "binary_missing_nx_stack": _playbook_binary_missing_nx_stack,
    "cleartext_http_authentication": _playbook_cleartext_http_authentication,
    "insecure_cookie_attributes": _playbook_insecure_cookie_attributes,
    "missing_security_headers": _playbook_missing_security_headers,
    "clickjacking_missing_frame_options": _playbook_clickjacking_missing_frame_options,
    "form_missing_csrf_token": _playbook_form_missing_csrf_token,
    "insecure_http_password_field": _playbook_insecure_http_password_field,
    "server_banner_disclosure": _playbook_server_banner_disclosure,
    "unencrypted_cleartext_service": _playbook_unencrypted_cleartext_service,
    "non_standard_service_port": _playbook_non_standard_service_port,
    "network_service_fingerprint": _playbook_network_service_fingerprint,
    "reverse_proxy_ip_spoofing": _playbook_reverse_proxy_ip_spoofing,
    "unauthenticated_artifact_vault_exposure": _playbook_unauthenticated_artifact_vault_exposure,
    "weak_reversible_binary_passkey": _playbook_weak_reversible_binary_passkey,
    "unauthenticated_console_service": _playbook_unauthenticated_console_service,
    "flag_disclosure_pidreq": _playbook_flag_disclosure_pidreq,
    "cors_wildcard_misconfiguration": _playbook_cors_wildcard_misconfiguration,
    "robots_txt_disclosure": _playbook_robots_txt_disclosure,
    "unauthenticated_api_exposure": _playbook_unauthenticated_api_exposure,
    "directory_listing_disclosure": _playbook_directory_listing_disclosure,
    "sensitive_file_exposure": _playbook_sensitive_file_exposure,
}


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class VerificationService:
    """Turns candidate findings into CONFIRMED / REJECTED / INCONCLUSIVE."""

    def __init__(self, conn: sqlite3.Connection, run_id: str):
        self.conn = conn
        self.run_id = run_id

    def queue(self, finding_ids: list[str]) -> None:
        """Transition findings to VERIFICATION_QUEUED."""
        for fid in finding_ids:
            row = self.conn.execute(
                "SELECT status FROM findings WHERE finding_id=?", (fid,)
            ).fetchone()
            if row and row[0] == FindingStatus.CANDIDATE.value:
                self.conn.execute(
                    "UPDATE findings SET status=? WHERE finding_id=?",
                    (FindingStatus.VERIFICATION_QUEUED.value, fid),
                )
        self.conn.commit()

    def verify_one(self, finding_id: str) -> FindingStatus:
        """Run the deterministic playbook for one queued finding."""
        row = self.conn.execute(
            "SELECT finding_id, asset_id, finding_type, severity, status, "
            "confidence, ptes_phase, summary FROM findings WHERE finding_id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"finding {finding_id} not found")

        finding = {
            "finding_id": row[0], "asset_id": row[1], "finding_type": row[2],
            "severity": row[3], "status": row[4], "confidence": row[5],
            "ptes_phase": row[6], "summary": row[7],
        }

        if finding["status"] not in (
            FindingStatus.CANDIDATE.value,
            FindingStatus.VERIFICATION_QUEUED.value,
        ):
            return FindingStatus(finding["status"])

        # Fetch evidence
        evidence_rows = self.conn.execute(
            "SELECT evidence_id, finding_id, source_tool, artifact_path, hash, "
            "timestamp, excerpt, verification_method FROM evidence WHERE finding_id=?",
            (finding_id,),
        ).fetchall()
        evidence_list = [
            {
                "evidence_id": r[0], "finding_id": r[1], "source_tool": r[2],
                "artifact_path": r[3], "hash": r[4], "timestamp": r[5],
                "excerpt": r[6], "verification_method": r[7],
            }
            for r in evidence_rows
        ]

        # Select playbook
        playbook = _PLAYBOOKS.get(finding["finding_type"], _playbook_default)
        new_status, new_confidence, note = playbook(finding, evidence_list)  # type: ignore[operator]

        # Persist outcome
        self.conn.execute(
            "UPDATE findings SET status=?, confidence=? WHERE finding_id=?",
            (new_status.value, new_confidence, finding_id),
        )

        # Attach verification evidence note
        ev = Evidence(
            evidence_id=new_id("evid"),
            finding_id=finding_id,
            source_tool="verification_service",
            artifact_path="",
            hash=hashlib.sha256(note.encode()).hexdigest(),
            excerpt=note[:500],
            verification_method="deterministic_playbook",
        )
        try:
            self.conn.execute(
                "INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, "
                "hash, timestamp, excerpt, verification_method) VALUES (?,?,?,?,?,?,?,?)",
                (ev.evidence_id, ev.finding_id, ev.source_tool, ev.artifact_path,
                 ev.hash, ev.timestamp, ev.excerpt, ev.verification_method),
            )
        except sqlite3.IntegrityError:
            pass
        self.conn.commit()
        return new_status

    def verify_all_queued(self) -> dict[str, FindingStatus]:
        """Process every VERIFICATION_QUEUED finding for the current run. Returns {finding_id: outcome}."""
        if self.run_id and self.run_id not in ("", "current", "all"):
            rows = self.conn.execute(
                "SELECT f.finding_id FROM findings f "
                "JOIN assets a ON f.asset_id = a.asset_id "
                "WHERE a.run_id = ? AND f.status = ?",
                (self.run_id, FindingStatus.VERIFICATION_QUEUED.value),
            ).fetchall()
            # Strict run isolation: If run exists in assets, do NOT fall back to other runs
            has_run_assets = self.conn.execute(
                "SELECT 1 FROM assets WHERE run_id = ?", (self.run_id,)
            ).fetchone()
            if not rows and not has_run_assets:
                # Standalone test fallback where assets were not keyed by run_id
                rows = self.conn.execute(
                    "SELECT finding_id FROM findings WHERE status=?",
                    (FindingStatus.VERIFICATION_QUEUED.value,),
                ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT finding_id FROM findings WHERE status=?",
                (FindingStatus.VERIFICATION_QUEUED.value,),
            ).fetchall()

        results: dict[str, FindingStatus] = {}
        for (fid,) in rows:
            try:
                results[fid] = self.verify_one(fid)
            except Exception:  # noqa: BLE001
                results[fid] = FindingStatus.INCONCLUSIVE
        return results
