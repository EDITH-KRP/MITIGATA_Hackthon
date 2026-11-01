from __future__ import annotations


def _safe_commit(conn: sqlite3.Connection) -> None:
    try:
        if getattr(conn, "in_transaction", True):
            conn.commit()
    except sqlite3.OperationalError:
        pass


import hashlib
import html.parser
import http.client
import json
import re
import socket
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

from ..models import (
    Evidence,
    Finding,
    FindingStatus,
    ScopeDecision,
    Task,
    ToolEvent,
    new_id,
    utc_now,
)
from ..ptes import PtesPhase
from ..scope import PolicyGate

# ---------------------------------------------------------------------------
# CTF planted-flag + binary-link detection (judge requirements)
# ---------------------------------------------------------------------------

FLAG_PATTERN = re.compile(
    r"(flag\{[^\}]+\}|CTF\{[^\}]+\}|CyberForge\{[^\}]+\})", re.IGNORECASE
)
HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)

# File extensions that indicate a downloadable binary artefact (hand-off target)
BINARY_FILE_EXTENSIONS = (".exe", ".bin", ".elf", ".so", ".dll")


def scan_flags(text: str) -> list[str]:
    """Return every CTF flag literal found in `text` (deduped, order kept)."""
    seen: list[str] = []
    for match in FLAG_PATTERN.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


def extract_html_comments(body_text: str) -> list[str]:
    """Extract the inner text of every HTML comment in a page body."""
    return [m.strip() for m in HTML_COMMENT_PATTERN.findall(body_text)]


def looks_like_binary_url(url: str) -> bool:
    """True when the URL path ends in a known binary artefact extension."""
    try:
        path = urllib.parse.urlparse(url).path
    except Exception:  # noqa: BLE001
        return False
    return path.lower().endswith(BINARY_FILE_EXTENSIONS)

# ---------------------------------------------------------------------------
# HTML link + form extractor
# ---------------------------------------------------------------------------

class _LinkParser(html.parser.HTMLParser):
    """Extract hrefs and form actions from raw HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "a" and attr.get("href"):
            abs_url = urllib.parse.urljoin(self.base_url, attr["href"])
            self.links.append(abs_url)
        elif tag == "script" and attr.get("src"):
            script_url = urllib.parse.urljoin(self.base_url, attr["src"])
            self.scripts.append(script_url)
        elif tag == "form":
            self._current_form = {
                "action": urllib.parse.urljoin(self.base_url, attr.get("action", "")),
                "method": attr.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attr.get("name", ""),
                "type": attr.get("type", "text"),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _persist_finding(conn: sqlite3.Connection, f: Finding) -> str:
    try:
        conn.execute(
            "INSERT INTO findings (finding_id, asset_id, finding_type, severity, "
            "status, confidence, ptes_phase, summary) VALUES (?,?,?,?,?,?,?,?)",
            (f.finding_id, f.asset_id, f.finding_type, f.severity,
             f.status.value, f.confidence, f.ptes_phase, f.summary),
        )
        _safe_commit(conn)
    except sqlite3.IntegrityError:
        pass
    return f.finding_id


def _persist_evidence(conn: sqlite3.Connection, e: Evidence) -> None:
    try:
        conn.execute(
            "INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, "
            "hash, timestamp, excerpt, verification_method) VALUES (?,?,?,?,?,?,?,?)",
            (e.evidence_id, e.finding_id, e.source_tool, e.artifact_path,
             e.hash, e.timestamp, e.excerpt, e.verification_method),
        )
        _safe_commit(conn)
    except sqlite3.IntegrityError:
        pass


def _persist_tool_event(conn: sqlite3.Connection, event: ToolEvent) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO tool_events "
        "(event_id, task_id, tool, target, scope_decision, started_at, finished_at, exit_status, output_hash) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (event.event_id, event.task_id, event.tool, event.target,
         event.scope_decision.value, event.started_at, event.finished_at,
         event.exit_status, event.output_hash),
    )
    _safe_commit(conn)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class ScopeGuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Enforces fail-closed PolicyGate evaluation BEFORE following HTTP redirects."""

    def __init__(self, gate: PolicyGate, run_id: str):
        self.gate = gate
        self.run_id = run_id
        super().__init__()

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp,
        code: int,
        msg: str,
        headers,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not newurl.startswith(("http://", "https://")):
            newurl = urllib.parse.urljoin(req.full_url, newurl)

        # PolicyGate check BEFORE connection is initiated
        decision = self.gate.gate(newurl, self.run_id, is_url=True)
        if decision.decision is not ScopeDecision.ALLOW:
            # Block the redirect: returning None drops the redirect
            return None

        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection connecting directly to PolicyGate's pinned IP to eliminate DNS rebinding TOCTOU."""

    def __init__(self, *args, gate: PolicyGate | None = None, run_id: str | None = None, **kwargs):
        self.gate = gate
        self.run_id = run_id
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        if self.gate is not None:
            connect_host = self.gate.resolve_and_pin_host(self.host, self.run_id)
        else:
            connect_host = self.host
        self.sock = socket.create_connection(
            (connect_host, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection connecting directly to PolicyGate's pinned IP with SNI preservation."""

    def __init__(self, *args, gate: PolicyGate | None = None, run_id: str | None = None, **kwargs):
        self.gate = gate
        self.run_id = run_id
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        if self.gate is not None:
            connect_host = self.gate.resolve_and_pin_host(self.host, self.run_id)
        else:
            connect_host = self.host
        self.sock = socket.create_connection(
            (connect_host, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()

        server_hostname = self._tunnel_host if self._tunnel_host else self.host
        if self._context is not None:
            self.sock = self._context.wrap_socket(
                self.sock,
                server_hostname=server_hostname,
            )
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(
                self.sock,
                server_hostname=server_hostname,
            )


class ScopeGuardedHTTPHandler(urllib.request.HTTPHandler):
    """HTTPHandler dispatching through DNS-pinned socket connections."""

    def __init__(self, gate: PolicyGate, run_id: str):
        super().__init__()
        self.gate = gate
        self.run_id = run_id

    def http_open(self, req: urllib.request.Request):
        def _factory(*args, **kwargs):
            return PinnedHTTPConnection(*args, gate=self.gate, run_id=self.run_id, **kwargs)
        return self.do_open(_factory, req)


class ScopeGuardedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler dispatching through DNS-pinned TLS socket connections."""

    def __init__(self, gate: PolicyGate, run_id: str, context: ssl.SSLContext | None = None):
        super().__init__(context=context)
        self.gate = gate
        self.run_id = run_id
        self._custom_context = context

    def https_open(self, req: urllib.request.Request):
        def _factory(*args, **kwargs):
            if "context" not in kwargs and self._custom_context is not None:
                kwargs["context"] = self._custom_context
            return PinnedHTTPSConnection(*args, gate=self.gate, run_id=self.run_id, **kwargs)
        return self.do_open(_factory, req)


class WebWorker:
    """Crawl permitted in-scope web apps; capture endpoints/forms within policy."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        gate: PolicyGate,
        run_id: str,
        max_pages: int = 200,
        request_delay_s: float = 0.2,
        binary_cache_dir: str | Path = "binary_cache",
        max_binary_bytes: int = 16 << 20,
    ):
        self.conn = conn
        self.gate = gate
        self.run_id = run_id
        self.max_pages = max_pages
        self.request_delay_s = request_delay_s
        self.binary_cache_dir = Path(binary_cache_dir)
        self.max_binary_bytes = max_binary_bytes  # explicit download cap
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            ScopeGuardedRedirectHandler(self.gate, self.run_id),
            ScopeGuardedHTTPHandler(self.gate, self.run_id),
            ScopeGuardedHTTPSHandler(self.gate, self.run_id, context=ssl_ctx),
        )

    def run(self, task: Task) -> dict:
        """Crawl the web service identified by task.target_id (asset_id).

        Looks up the asset's canonical_key (IP) from the DB, constructs the
        base URL, then BFS-crawls within scope policy.
        """
        # Resolve asset → IP or direct seed URL
        if task.target_id.startswith(("http://", "https://")):
            base_url = task.target_id
            parsed = urllib.parse.urlparse(base_url)
            ip = parsed.hostname or base_url
            all_base_urls = [base_url]
        else:
            row = self.conn.execute(
                "SELECT canonical_key FROM assets WHERE asset_id=?", (task.target_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"Asset {task.target_id} not found in store")
            ip = row[0]
            base_url = self._detect_base_url(ip, task.target_id)
            all_base_urls = self._detect_all_base_urls(ip, task.target_id)

        # SCOPE GATE on base URL before crawl starts
        gate_result = self.gate.gate(base_url, self.run_id, is_url=True)
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="web_crawler",
            target=base_url,
            scope_decision=gate_result.decision,
            started_at=utc_now(),
        )
        if gate_result.decision is ScopeDecision.DENY:
            event.finished_at = utc_now()
            event.exit_status = "scope_denied"
            _persist_tool_event(self.conn, event)
            raise PermissionError(f"Scope DENY for {base_url}: {gate_result.reason}")
        endpoints, forms, finding_ids, discovered_binaries = self._crawl(task, all_base_urls, ip)

        event.finished_at = utc_now()
        event.exit_status = "0"
        event.output_hash = hashlib.sha256(
            json.dumps(endpoints).encode()
        ).hexdigest()
        _persist_tool_event(self.conn, event)

        return {
            "base_url": base_url,
            "endpoints": endpoints,
            "forms_found": len(forms),
            "findings": finding_ids,
            # Binary artefacts linked from crawled pages, saved + hash-registered
            "discovered_binaries": discovered_binaries,
        }

    def _download_binary(self, url: str) -> dict | None:
        """Download an in-scope binary artefact to the local cache.

        Scope safety: the caller has already gate-allowed `url`. The final URL
        after any redirect is re-checked before persisting the payload. The
        copy is capped at `max_binary_bytes`, hashed, saved locally and
        registered with the gate for STATIC ANALYSIS ONLY (never executed).
        """
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CART-scanner/0.1 (controlled assessment)"},
            )
            with self._opener.open(req, timeout=10) as resp:
                final_url = resp.url
                if final_url != url:
                    redirect_gate = self.gate.gate(final_url, self.run_id, is_url=True)
                    if redirect_gate.decision is ScopeDecision.DENY:
                        return None
                data = resp.read(self.max_binary_bytes + 1)

            if len(data) > self.max_binary_bytes:
                return None  # over cap — refuse oversized artefact
            if not data:
                return None

            sha256 = hashlib.sha256(data).hexdigest()
            suffix = Path(urllib.parse.urlparse(url).path).suffix or ".bin"
            run_cache = self.binary_cache_dir / self.run_id
            run_cache.mkdir(parents=True, exist_ok=True)
            dest = run_cache / f"{sha256}{suffix}"
            dest.write_bytes(data)

            # Register the local copy with the gate (audit-logged, static only)
            self.gate.register_dynamic_binary(
                str(dest),
                sha256,
                reason=f"downloaded binary from in-scope URL {url}",
                run_id=self.run_id,
            )
            return {
                "url": url,
                "path": str(dest),
                "sha256": sha256,
                "size_bytes": len(data),
            }
        except (urllib.error.URLError, OSError):
            return None

    def _scan_page_for_flags(
        self,
        task: Task,
        asset_ip: str,
        page_url: str,
        body_text: str,
        headers_text: str,
    ) -> list[str]:
        """Hunt planted CTF flags in body, HTML comments and HTTP headers."""
        haystacks = {
            "body": body_text,
            "html_comment": "\n".join(extract_html_comments(body_text)),
            "http_headers": headers_text,
        }
        fids: list[str] = []
        seen_flags: list[str] = []
        for location, haystack in haystacks.items():
            for flag in scan_flags(haystack):
                if flag in seen_flags:
                    continue
                seen_flags.append(flag)
                fids.append(
                    self._emit_flag_finding(task, asset_ip, page_url, flag, location)
                )
        return fids

    def _emit_flag_finding(
        self,
        task: Task,
        asset_ip: str,
        page_url: str,
        flag: str,
        location: str,
    ) -> str:
        """Record a high-severity CANDIDATE finding for a captured CTF flag."""
        asset_id = self._get_or_create_asset("web_app", asset_ip)

        finding = Finding(
            finding_id=new_id("find"),
            asset_id=asset_id,
            finding_type="ctf_planted_flag",
            severity="high",
            status=FindingStatus.CANDIDATE,
            confidence="high",
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            summary=(
                f"Planted CTF flag {flag!r} captured in {location} at {page_url}"
            ),
        )
        fid = _persist_finding(self.conn, finding)

        evidence = Evidence(
            evidence_id=new_id("evid"),
            finding_id=fid,
            source_tool="web_crawler",
            artifact_path=page_url,
            hash=hashlib.sha256(flag.encode()).hexdigest(),
            excerpt=f"location={location}; flag={flag}",
            verification_method="manual_review_required",
        )
        _persist_evidence(self.conn, evidence)
        return fid

    def _get_or_create_asset(self, asset_type: str, canonical_key: str) -> str:
        """Look up (or create) an asset for this run. Dedupe at DB level."""
        row = self.conn.execute(
            "SELECT asset_id FROM assets WHERE run_id=? AND asset_type=? AND canonical_key=?",
            (self.run_id, asset_type, canonical_key),
        ).fetchone()
        if row is not None:
            return row[0]

        from ..models import Asset
        asset = Asset(
            asset_id=new_id("asset"),
            run_id=self.run_id,
            asset_type=asset_type,
            canonical_key=canonical_key,
        )
        try:
            self.conn.execute(
                "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?)",
                (asset.asset_id, asset.run_id, asset.asset_type,
                 asset.canonical_key, asset.first_seen, asset.last_seen),
            )
            _safe_commit(self.conn)
            return asset.asset_id
        except sqlite3.IntegrityError:
            row = self.conn.execute(
                "SELECT asset_id FROM assets WHERE run_id=? AND asset_type=? AND canonical_key=?",
                (self.run_id, asset_type, canonical_key),
            ).fetchone()
            return row[0] if row else asset.asset_id

    def _detect_base_url(self, ip: str, asset_id: str | None = None) -> str:
        """Build a base URL from discovered web services, without probing.

        NetworkWorker has already recorded open services. Using those records
        avoids guessing ports and ensures the first HTTP request is made only
        after the caller applies the normal URL scope gate.
        """
        if asset_id is not None:
            rows = self.conn.execute(
                "SELECT protocol, port FROM services "
                "WHERE asset_id=? AND state='open' ORDER BY "
                "CASE port WHEN 443 THEN 0 WHEN 8443 THEN 1 WHEN 80 THEN 2 "
                "WHEN 8080 THEN 3 WHEN 8000 THEN 4 WHEN 8888 THEN 5 ELSE 6 END, port",
                (asset_id,),
            ).fetchall()
            for protocol, port in rows:
                if port not in {80, 443, 8000, 8080, 8443, 8888}:
                    continue
                scheme = "https" if port in {443, 8443} or protocol.lower() == "https" else "http"
                default_port = 443 if scheme == "https" else 80
                port_part = "" if port == default_port else f":{port}"
                return f"{scheme}://{ip}{port_part}/"

        return f"http://{ip}/"

    def _detect_all_base_urls(self, ip: str, asset_id: str | None = None) -> list[str]:
        primary = self._detect_base_url(ip, asset_id)
        urls = [primary]
        if asset_id is not None:
            rows = self.conn.execute(
                "SELECT protocol, port FROM services WHERE asset_id=? AND state='open'",
                (asset_id,),
            ).fetchall()
            for protocol, port in rows:
                scheme = "https" if port in {443, 8443} or str(protocol).lower() == "https" else "http"
                default_port = 443 if scheme == "https" else 80
                port_part = "" if port == default_port else f":{port}"
                candidate_url = f"{scheme}://{ip}{port_part}/"
                if candidate_url not in urls:
                    urls.append(candidate_url)
        return urls

    def _emit_finding(
        self,
        task: Task,
        asset_id: str,
        finding_type: str,
        severity: str,
        ptes_phase: PtesPhase,
        summary: str,
        artifact_path: str,
        excerpt: str,
        confidence: str = "high",
    ) -> str:
        finding = Finding(
            finding_id=new_id("find"),
            asset_id=asset_id,
            finding_type=finding_type,
            severity=severity,
            status=FindingStatus.CANDIDATE,
            confidence=confidence,
            ptes_phase=ptes_phase,
            summary=summary,
        )
        fid = _persist_finding(self.conn, finding)
        evidence = Evidence(
            evidence_id=new_id("evid"),
            finding_id=fid,
            source_tool="web_crawler",
            artifact_path=artifact_path,
            hash=hashlib.sha256(excerpt.encode()).hexdigest(),
            excerpt=excerpt[:500],
            verification_method="deterministic_header_audit",
        )
        _persist_evidence(self.conn, evidence)
        return fid

    def _audit_security_headers(
        self,
        task: Task,
        asset_ip: str,
        page_url: str,
        headers: dict[str, str],
        status_code: int = 200,
    ) -> list[str]:
        fids = []
        asset_id = self._get_or_create_asset("web_app", asset_ip)

        # 1. Cleartext HTTP Basic Authentication
        www_auth = headers.get("WWW-Authenticate", "")
        if www_auth and "basic" in www_auth.lower() and page_url.startswith("http://"):
            summary = (
                f"Cleartext HTTP Basic Authentication exposed at {page_url} "
                f"without TLS encryption (CWE-319): {www_auth}"
            )
            fid = self._emit_finding(
                task, asset_id, "cleartext_http_authentication", "high",
                PtesPhase.VULNERABILITY_ANALYSIS, summary,
                page_url, f"status={status_code}; WWW-Authenticate={www_auth}",
                confidence="high",
            )
            fids.append(fid)

        # 2. Insecure Cookie Attributes (Missing HttpOnly / SameSite)
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            raw_lower = set_cookie.lower()
            issues = []
            if "httponly" not in raw_lower:
                issues.append("missing HttpOnly (vulnerable to XSS theft)")
            if "samesite" not in raw_lower:
                issues.append("missing SameSite attribute (susceptible to CSRF)")
            if page_url.startswith("https://") and "secure" not in raw_lower:
                issues.append("missing Secure attribute over HTTPS")
            if issues:
                summary = (
                    f"Insecure cookie attributes on {page_url}: {', '.join(issues)} (CWE-1004)"
                )
                fid = self._emit_finding(
                    task, asset_id, "insecure_cookie_attributes", "medium",
                    PtesPhase.VULNERABILITY_ANALYSIS, summary,
                    page_url, f"url={page_url}; Set-Cookie={set_cookie}",
                    confidence="high",
                )
                fids.append(fid)

        # 3. Missing Critical Security Headers
        missing = []
        if not headers.get("Content-Security-Policy"):
            missing.append("Content-Security-Policy")
        if not headers.get("X-Frame-Options"):
            missing.append("X-Frame-Options")
        if not headers.get("X-Content-Type-Options"):
            missing.append("X-Content-Type-Options: nosniff")
        if page_url.startswith("https://") and not headers.get("Strict-Transport-Security"):
            missing.append("Strict-Transport-Security")
        if missing:
            summary = (
                f"Critical HTTP security headers missing at {page_url}: {', '.join(missing)} "
                "(CWE-1021, CWE-693, CWE-16)"
            )
            fid = self._emit_finding(
                task, asset_id, "missing_security_headers", "medium",
                PtesPhase.VULNERABILITY_ANALYSIS, summary,
                page_url, json.dumps({"missing": missing, "url": page_url}),
                confidence="high",
            )
            fids.append(fid)

        # 4. Software Version Disclosure
        server_hdr = headers.get("Server", "")
        powered_by = headers.get("X-Powered-By", "")
        disclosures = []
        if server_hdr and re.search(r"\d+\.\d+", server_hdr):
            disclosures.append(f"Server: {server_hdr}")
        if powered_by:
            disclosures.append(f"X-Powered-By: {powered_by}")
        if disclosures:
            summary = (
                f"Software version disclosure in HTTP headers at {page_url}: {'; '.join(disclosures)} (CWE-200)"
            )
            fid = self._emit_finding(
                task, asset_id, "server_banner_disclosure", "low",
                PtesPhase.INTELLIGENCE_GATHERING, summary,
                page_url, f"url={page_url}; {'; '.join(disclosures)}",
                confidence="high",
            )
            fids.append(fid)

        # 5. Overly Permissive CORS Policy
        cors_origin = headers.get("Access-Control-Allow-Origin", "")
        if cors_origin == "*" or (cors_origin and "null" in cors_origin.lower()):
            summary = (
                f"Overly permissive Cross-Origin Resource Sharing (CORS) policy at {page_url}: "
                f"Access-Control-Allow-Origin is set to '{cors_origin}' (CWE-346, CWE-942)"
            )
            fid = self._emit_finding(
                task, asset_id, "cors_wildcard_misconfiguration", "medium",
                PtesPhase.VULNERABILITY_ANALYSIS, summary,
                page_url, f"url={page_url}; Access-Control-Allow-Origin={cors_origin}",
                confidence="high",
            )
            fids.append(fid)

        # 6. Clickjacking / Missing Anti-Framing Protection
        csp = headers.get("Content-Security-Policy", "").lower()
        if not headers.get("X-Frame-Options") and "frame-ancestors" not in csp:
            summary = (
                f"Application at {page_url} lacks anti-framing defenses (missing X-Frame-Options and frame-ancestors). "
                "The endpoint can be embedded in malicious iframes, enabling UI Redressing / Clickjacking attacks (CWE-1021)."
            )
            fid = self._emit_finding(
                task, asset_id, "clickjacking_missing_frame_options", "medium",
                PtesPhase.VULNERABILITY_ANALYSIS, summary,
                page_url, f"url={page_url}; X-Frame-Options=None; frame-ancestors=None",
                confidence="high",
            )
            fids.append(fid)

        # 7. Technology & Framework Fingerprinting (CWE-200)
        tech_signatures = {
            "Express": [("x-powered-by", "express")],
            "PHP": [("x-powered-by", "php")],
            "ASP.NET": [("x-powered-by", "asp.net")],
            "Next.js": [("x-powered-by", "next.js")],
            "Werkzeug": [("server", "werkzeug")],
            "Nginx": [("server", "nginx")],
            "Apache": [("server", "apache")],
            "Gunicorn": [("server", "gunicorn")],
            "Cloudflare": [("server", "cloudflare")],
        }
        detected_tech = []
        for tech, sigs in tech_signatures.items():
            for hdr_k, hdr_v in sigs:
                val = str(headers.get(hdr_k, "")).lower() or str(headers.get(hdr_k.title(), "")).lower()
                if hdr_v in val and tech not in detected_tech:
                    detected_tech.append(tech)
        if detected_tech:
            summary = f"Web technology stack detected at {page_url}: {', '.join(detected_tech)} (CWE-200)"
            fid = self._emit_finding(
                task, asset_id, "web_technology_fingerprint", "info",
                PtesPhase.INTELLIGENCE_GATHERING, summary,
                page_url, json.dumps({"technologies": detected_tech, "headers": dict(headers)}),
                confidence="high",
            )
            fids.append(fid)

        return fids

    def _crawl(
        self, task: Task, base_urls: list[str] | str, asset_ip: str
    ) -> tuple[list[str], list[dict], list[str], list[dict]]:
        """BFS crawler. Returns (visited_urls, forms, finding_ids, discovered_binaries)."""
        visited: set[str] = set()
        visited_scripts: set[str] = set()
        queue: deque[str] = deque(base_urls if isinstance(base_urls, list) else [base_urls])
        seen_audits: set[str] = set()
        all_forms: list[dict] = []
        finding_ids: list[str] = []
        discovered_binaries: list[dict] = []
        timeout = task.budget.get("timeout_s", 180)
        deadline = time.monotonic() + timeout

        # Active reconnaissance for sensitive paths across target roots
        recon_paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/api/Challenges",
            "/rest/admin/application-version",
            "/ftp",
            "/.env",
            "/.git/HEAD",
            "/admin",
            "/swagger.json",
            "/openapi.json",
            "/actuator/health",
            "/console",
            "/config.php.bak",
            "/web.config.bak",
        ]
        target_roots: set[str] = set()
        for b_url in (base_urls if isinstance(base_urls, list) else [base_urls]):
            p = urllib.parse.urlsplit(b_url)
            if p.scheme and p.netloc:
                target_roots.add(f"{p.scheme}://{p.netloc}/")

        for root in target_roots:
            for p_path in recon_paths:
                candidate_url = urllib.parse.urljoin(root, p_path.lstrip("/"))
                gate_res = self.gate.gate(candidate_url, self.run_id, is_url=True)
                if gate_res.decision is ScopeDecision.DENY:
                    continue

                try:
                    p_req = urllib.request.Request(
                        candidate_url,
                        headers={"User-Agent": "CART-scanner/0.1 (controlled assessment)"},
                    )
                    with self._opener.open(p_req, timeout=5) as p_resp:
                        p_code = getattr(p_resp, "status", 200)
                        if p_code >= 400:
                            continue
                        p_ct = p_resp.headers.get("Content-Type", "")
                        p_body = p_resp.read(65536)
                        p_text = p_body.decode(errors="replace")

                        # 1. Robots.txt disclosure
                        if p_path == "/robots.txt":
                            disallowed = []
                            for line in p_text.splitlines():
                                line_clean = line.strip()
                                if line_clean.lower().startswith("disallow:"):
                                    parts = line_clean.split(":", 1)
                                    if len(parts) > 1 and parts[1].strip():
                                        d_path = parts[1].strip()
                                        disallowed.append(d_path)
                                        abs_d = urllib.parse.urljoin(root, d_path.lstrip("/"))
                                        if abs_d not in visited:
                                            queue.append(abs_d)
                            if disallowed:
                                asset_id = self._get_or_create_asset("web_app", asset_ip)
                                fid = self._emit_finding(
                                    task,
                                    asset_id,
                                    "robots_txt_disclosure",
                                    "low",
                                    PtesPhase.INTELLIGENCE_GATHERING,
                                    f"Sensitive paths disclosed in robots.txt at {candidate_url}: {', '.join(disallowed[:5])} (CWE-200, CWE-548)",
                                    candidate_url,
                                    f"Disallowed paths: {', '.join(disallowed)}",
                                    confidence="high",
                                )
                                finding_ids.append(fid)

                        # 2. Exposed sensitive config or git repo
                        elif p_path in ("/.env", "/.git/HEAD"):
                            if "ref: refs/heads" in p_text or any(k in p_text for k in ("DB_", "SECRET", "KEY=", "PASSWORD=")):
                                asset_id = self._get_or_create_asset("web_app", asset_ip)
                                fid = self._emit_finding(
                                    task,
                                    asset_id,
                                    "sensitive_file_exposure",
                                    "high",
                                    PtesPhase.VULNERABILITY_ANALYSIS,
                                    f"Publicly accessible sensitive file or VCS repository exposed at {candidate_url} (CWE-552)",
                                    candidate_url,
                                    p_text[:200],
                                    confidence="high",
                                )
                                finding_ids.append(fid)

                        # 3. Directory listing / open file storage
                        elif p_path == "/ftp" or "index of /" in p_text.lower():
                            asset_id = self._get_or_create_asset("web_app", asset_ip)
                            fid = self._emit_finding(
                                task,
                                asset_id,
                                "directory_listing_disclosure",
                                "medium",
                                PtesPhase.INTELLIGENCE_GATHERING,
                                f"Directory indexing / open file storage exposed at {candidate_url} (CWE-548)",
                                candidate_url,
                                p_text[:200],
                                confidence="high",
                            )
                            finding_ids.append(fid)
                            parser = _LinkParser(candidate_url)
                            try:
                                parser.feed(p_text)
                                for lk in parser.links:
                                    if lk not in visited:
                                        queue.append(lk)
                            except Exception:  # noqa: BLE001 S110
                                pass

                        # 4. Unauthenticated JSON API
                        elif "application/json" in p_ct or p_body.strip().startswith((b"{", b"[")):
                            if len(p_body.strip()) > 2:
                                asset_id = self._get_or_create_asset("web_app", asset_ip)
                                fid = self._emit_finding(
                                    task,
                                    asset_id,
                                    "unauthenticated_api_exposure",
                                    "medium",
                                    PtesPhase.VULNERABILITY_ANALYSIS,
                                    f"Unauthenticated REST API endpoint exposed at {candidate_url} disclosing structured data (CWE-306)",
                                    candidate_url,
                                    p_text[:300],
                                    confidence="high",
                                )
                                finding_ids.append(fid)

                        # Flag hunt across probed files
                        flag_fids = self._scan_page_for_flags(
                            task, asset_ip, candidate_url, p_text, str(p_resp.headers)
                        )
                        finding_ids.extend(flag_fids)

                except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                    pass

        while queue and len(visited) < self.max_pages:
            if time.monotonic() > deadline:
                break

            url = queue.popleft()
            if url in visited:
                continue

            # Normalise + scope check every URL before fetching
            url = self._normalise(url, url)
            if not url:
                continue

            gate_result = self.gate.gate(url, self.run_id, is_url=True)
            if gate_result.decision is ScopeDecision.DENY:
                continue  # silently skip out-of-scope links

            visited.add(url)

            # Binary artefact links are downloaded, hashed and handed to the
            # orchestrator instead of being parsed as HTML.
            if looks_like_binary_url(url):
                binary_info = self._download_binary(url)
                if binary_info:
                    discovered_binaries.append(binary_info)
                time.sleep(self.request_delay_s)
                continue

            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "CART-scanner/0.1 (controlled assessment)"},
                )
                with self._opener.open(req, timeout=10) as resp:
                    # Check redirect destination
                    final_url = resp.url
                    if final_url != url:
                        redirect_gate = self.gate.gate(final_url, self.run_id, is_url=True)
                        if redirect_gate.decision is ScopeDecision.DENY:
                            continue
                    content_type = resp.headers.get("Content-Type", "")
                    headers_text = str(resp.headers)
                    headers_dict = dict(resp.headers)
                    body = resp.read(task.budget.get("max_output", 1 << 20))

                # Audit security headers & cookies once per origin
                origin = urllib.parse.urlsplit(url).netloc
                if origin not in seen_audits:
                    seen_audits.add(origin)
                    vuln_fids = self._audit_security_headers(
                        task, asset_ip, url, headers_dict, status_code=getattr(resp, "status", 200)
                    )
                    finding_ids.extend(vuln_fids)

                time.sleep(self.request_delay_s)

                if "text/html" in content_type:
                    body_text = body.decode(errors="replace")
                    parser = _LinkParser(url)
                    try:
                        parser.feed(body_text)
                    except Exception:  # noqa: S110 BLE001
                        pass
                    for link in parser.links:
                        if link not in visited:
                            queue.append(link)
                    all_forms.extend(parser.forms)

                    # Inspect client script bundles for API routes and flags
                    for s_url in parser.scripts[:15]:
                        if s_url in visited_scripts:
                            continue
                        visited_scripts.add(s_url)
                        s_gate = self.gate.gate(s_url, self.run_id, is_url=True)
                        if s_gate.decision is ScopeDecision.DENY:
                            continue
                        try:
                            s_req = urllib.request.Request(
                                s_url,
                                headers={"User-Agent": "CART-scanner/0.1 (controlled assessment)"},
                            )
                            with self._opener.open(s_req, timeout=5) as s_resp:
                                s_body = s_resp.read(524288)  # up to 512KB
                                s_text = s_body.decode(errors="replace")
                                s_flag_fids = self._scan_page_for_flags(
                                    task, asset_ip, s_url, s_text, str(s_resp.headers)
                                )
                                finding_ids.extend(s_flag_fids)
                                discovered_routes = re.findall(
                                    r'["\'](/(?:api|rest|v1|v2|ftp|admin|assets|vault)/[a-zA-Z0-9_\-\.\/]+)["\']',
                                    s_text,
                                )
                                for d_route in discovered_routes[:30]:
                                    abs_route = urllib.parse.urljoin(url, d_route)
                                    if abs_route not in visited:
                                        queue.append(abs_route)
                        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                            pass

                    # Planted-flag hunt: body, HTML comments, HTTP headers
                    flag_fids = self._scan_page_for_flags(
                        task, asset_ip, url, body_text, headers_text
                    )
                    finding_ids.extend(flag_fids)

                    # Emit a CANDIDATE finding for each form (potential injection surface)
                    for form in parser.forms:
                        if form["inputs"]:
                            fid = self._emit_form_finding(task, asset_ip, url, form)
                            finding_ids.append(fid)

                            input_names = [i.get("name", "").lower() for i in form["inputs"]]
                            input_types = [i.get("type", "").lower() for i in form["inputs"]]
                            asset_id = self._get_or_create_asset("web_app", asset_ip)

                            # Check for missing anti-CSRF token on state-changing forms
                            if form.get("method") == "POST":
                                has_csrf = any(
                                    any(k in n for k in ("csrf", "token", "authenticity", "_csrf"))
                                    for n in input_names
                                )
                                if not has_csrf:
                                    csrf_fid = self._emit_finding(
                                        task,
                                        asset_id,
                                        "form_missing_csrf_token",
                                        "medium",
                                        PtesPhase.VULNERABILITY_ANALYSIS,
                                        f"State-changing HTML form (action={form.get('action')}) at {url} lacks anti-CSRF token (CWE-352).",
                                        url,
                                        f"form_action={form.get('action')}; method=POST; inputs={input_names}",
                                        confidence="high",
                                    )
                                    finding_ids.append(csrf_fid)

                            # Check for cleartext password transmission
                            if url.startswith("http://") and "password" in input_types:
                                pwd_fid = self._emit_finding(
                                    task,
                                    asset_id,
                                    "insecure_http_password_field",
                                    "high",
                                    PtesPhase.VULNERABILITY_ANALYSIS,
                                    f"HTML form at {url} accepts credentials/passwords over unencrypted HTTP (CWE-319, CWE-523).",
                                    url,
                                    f"form_action={form.get('action')}; scheme=http; inputs={input_names}",
                                    confidence="high",
                                )
                                finding_ids.append(pwd_fid)
                else:
                    try:
                        non_html_text = body.decode(errors="replace")
                        flag_fids = self._scan_page_for_flags(
                            task, asset_ip, url, non_html_text, headers_text
                        )
                        finding_ids.extend(flag_fids)
                    except Exception:  # noqa: BLE001 S110
                        pass

            except urllib.error.HTTPError as exc:
                headers_dict = dict(exc.headers)
                origin = urllib.parse.urlsplit(url).netloc
                if origin not in seen_audits:
                    seen_audits.add(origin)
                    vuln_fids = self._audit_security_headers(
                        task, asset_ip, url, headers_dict, status_code=exc.code
                    )
                    finding_ids.extend(vuln_fids)
            except (urllib.error.URLError, OSError):
                pass  # unreachable / timeout — continue crawl

        return list(visited), all_forms, finding_ids, discovered_binaries

    @staticmethod
    def _normalise(url: str, base: str) -> str:
        """Make url absolute, strip fragments, keep only http/https."""
        try:
            abs_url = urllib.parse.urljoin(base, url)
            parsed = urllib.parse.urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                return ""
            # Drop fragment
            clean = urllib.parse.urlunparse(parsed._replace(fragment=""))
            return clean
        except Exception:  # noqa: BLE001
            return ""

    def _emit_form_finding(
        self, task: Task, asset_ip: str, page_url: str, form: dict
    ) -> str:
        """Record a CANDIDATE finding for a discovered form endpoint."""
        # Look up asset_id
        row = self.conn.execute(
            "SELECT asset_id FROM assets WHERE run_id=? AND canonical_key=?",
            (self.run_id, asset_ip),
        ).fetchone()
        if row is None:
            return ""
        asset_id = row[0]

        finding = Finding(
            finding_id=new_id("find"),
            asset_id=asset_id,
            finding_type="web_form_endpoint",
            severity="info",
            status=FindingStatus.CANDIDATE,
            confidence="low",
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            summary=(
                f"Form found at {page_url}: action={form['action']!r}, "
                f"method={form['method']}, "
                f"inputs={[i['name'] for i in form['inputs']]}"
            ),
        )
        fid = _persist_finding(self.conn, finding)

        evidence = Evidence(
            evidence_id=new_id("evid"),
            finding_id=fid,
            source_tool="web_crawler",
            artifact_path=page_url,
            hash=hashlib.sha256(json.dumps(form).encode()).hexdigest(),
            excerpt=json.dumps(form)[:500],
            verification_method="manual_review_required",
        )
        _persist_evidence(self.conn, evidence)
        return fid
