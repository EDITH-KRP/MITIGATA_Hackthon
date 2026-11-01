"""Scope registry and execution policy gate (spec section 5.3, 10).

SECURITY BOUNDARY: this module is deterministic code, not an LLM prompt.
Every tool action must pass the gate immediately before execution. The gate
fails closed: missing, ambiguous or unresolvable scope means DENY.
"""

from __future__ import annotations

import ipaddress
import socket
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import ScopeDecision, ScopeManifest, new_id, utc_now


class ScopeNotLockedError(RuntimeError):
    pass


@dataclass
class ScopeDecisionResult:
    decision: ScopeDecision
    reason: str
    resolved_target: str


class PolicyGate:
    """Shared gate used by the controller and every specialist worker."""

    def __init__(self, manifest: ScopeManifest):
        if manifest.locked_at is None:
            raise ScopeNotLockedError(
                "Scope manifest is not locked. No tool action may run until the "
                "organiser-selected scope is locked and versioned."
            )
        self.manifest = manifest
        self._nets = [
            ipaddress.ip_network(p, strict=False) for p in manifest.included_prefixes
        ]
        self._hosts = [ipaddress.ip_address(h) for h in manifest.included_hosts]
        self._excluded_nets = [
            ipaddress.ip_network(e, strict=False) for e in manifest.exclusions
        ]
        self._conn: sqlite3.Connection | None = None
        # In-run downloaded copies of in-scope content (web→binary hand-off).
        # NEVER writes to the locked manifest; targets themselves never grow.
        self._dynamic_binaries: dict[str, str] = {}  # path -> sha256
        self._dns_pinning_cache: dict[str, list[str]] = {}  # hostname -> pinned IP list (DNS rebinding guard)

    def bind_store(self, conn: sqlite3.Connection) -> None:
        """Attach a live DB connection so record_decision can persist decisions."""
        self._conn = conn

    # ------------------------------------------------------------------
    # Core IP/network checks
    # ------------------------------------------------------------------

    def check_destination(self, target: str) -> ScopeDecisionResult:
        """Check one network destination (IP or CIDR) against the locked scope without memory exhaustion."""
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return ScopeDecisionResult(
                ScopeDecision.DENY, f"unparseable destination: {target!r}", target
            )

        # Exclusions always win - O(1) overlap check
        for ex in self._excluded_nets:
            if net.overlaps(ex):
                return ScopeDecisionResult(
                    ScopeDecision.DENY, f"{target} overlaps excluded network {ex}", target
                )

        if net.num_addresses == 1:
            return self.check_ip(net.network_address)

        # Subnet containment check - O(1)
        for inc in self._nets:
            if net.subnet_of(inc):
                return ScopeDecisionResult(
                    ScopeDecision.ALLOW, f"{target} fully within included scope {inc}", target
                )

        # Bounded host check for small subnets (<= 256) without building complete lists
        if net.num_addresses <= 256:
            for addr in net.hosts():
                res = self.check_ip(addr)
                if res.decision is ScopeDecision.DENY:
                    return res
            return ScopeDecisionResult(ScopeDecision.ALLOW, "in locked scope", target)

        return ScopeDecisionResult(
            ScopeDecision.DENY, f"network {target} is not wholly contained within locked scope", target
        )

    def check_ip(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> ScopeDecisionResult:
        addr = ipaddress.ip_address(ip)
        presented = str(addr)
        # Exclusions always win.
        for net in self._excluded_nets:
            if addr in net:
                return ScopeDecisionResult(
                    ScopeDecision.DENY, f"{presented} is excluded by scope", presented
                )
        for net in self._nets:
            if addr in net:
                return ScopeDecisionResult(
                    ScopeDecision.ALLOW, f"{presented} in {net}", presented
                )
        if addr in self._hosts:
            return ScopeDecisionResult(
                ScopeDecision.ALLOW, f"{presented} in included host list", presented
            )
        return ScopeDecisionResult(
            ScopeDecision.DENY, f"{presented} not resolvable to locked scope", presented
        )

    # ------------------------------------------------------------------
    # URL / web check (resolves hostname → IP, then delegates to check_ip)
    # ------------------------------------------------------------------

    def check_url(self, url: str) -> ScopeDecisionResult:
        """Check a web URL incl. hostname resolution against the locked scope.

        Steps:
        1. Parse the URL — if unparseable, DENY immediately.
        2. Resolve the hostname to IP(s) — resolution failure → DENY.
        3. Every resolved IP must pass check_ip (exclusions win).
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
        except Exception:  # noqa: BLE001
            return ScopeDecisionResult(ScopeDecision.DENY, f"unparseable URL: {url!r}", url)

        if not hostname:
            return ScopeDecisionResult(
                ScopeDecision.DENY, f"no hostname in URL: {url!r}", url
            )

        # Resolve hostname → IPs
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
            resolved_ips = list({info[4][0] for info in addr_infos})
        except socket.gaierror as exc:
            return ScopeDecisionResult(
                ScopeDecision.DENY,
                f"hostname {hostname!r} could not be resolved: {exc}",
                url,
            )

        # DNS Rebinding Guard: verify resolution consistency across repeated checks
        if hostname in self._dns_pinning_cache:
            pinned = self._dns_pinning_cache[hostname]
            if not set(resolved_ips).issubset(set(pinned)):
                return ScopeDecisionResult(
                    ScopeDecision.DENY,
                    f"DNS rebinding detected for {hostname!r}: previous {pinned} != current {resolved_ips}",
                    url,
                )
        else:
            self._dns_pinning_cache[hostname] = resolved_ips

        for ip_str in resolved_ips:
            result = self.check_ip(ip_str)
            if result.decision is ScopeDecision.DENY:
                return ScopeDecisionResult(
                    ScopeDecision.DENY,
                    f"URL {url!r} resolves to {ip_str} which is {result.reason}",
                    url,
                )

        return ScopeDecisionResult(
            ScopeDecision.ALLOW,
            f"URL hostname {hostname!r} resolves to in-scope IPs",
            url,
        )

    # ------------------------------------------------------------------
    # Binary file check
    # ------------------------------------------------------------------

    def register_dynamic_binary(
        self,
        path: str,
        sha256: str,
        *,
        reason: str = "",
        run_id: str | None = None,
    ) -> None:
        """Authorise *static analysis only* of a downloaded copy of content
        that was fetched from an already-authorised, gate-allowed in-scope URL
        (web→binary hand-off).

        This does NOT touch the locked manifest and does NOT widen the target
        scope — the destination was already validated. Every registration is
        recorded in the audit log with the reason.
        """
        self._dynamic_binaries[path] = sha256
        result = ScopeDecisionResult(
            ScopeDecision.ALLOW,
            reason or "downloaded copy of in-scope URL content (static analysis only)",
            path,
        )
        self.record_decision(path, result, run_id)

    def check_binary_file(self, path: str) -> ScopeDecisionResult:
        sha256 = self.manifest.binary_hashes.get(path)
        if sha256 is None:
            # Fall back to in-run downloaded copies (fail closed for anything else)
            sha256 = self._dynamic_binaries.get(path)
        if sha256 is None:
            return ScopeDecisionResult(
                ScopeDecision.DENY,
                f"{path!r} is not an organiser-registered binary",
                path,
            )
        return ScopeDecisionResult(ScopeDecision.ALLOW, "registered binary hash", path)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def record_decision(
        self,
        requested: str,
        result: ScopeDecisionResult,
        run_id: str | None = None,
    ) -> None:
        """Persist allow/deny decisions in scope_decisions_log (audit requirement)."""
        if self._conn is None:
            return  # store not bound yet (e.g. during preflight / unit tests)
        event_id = new_id("sdl")
        self._conn.execute(
            """
            INSERT INTO scope_decisions_log
                (event_id, run_id, requested_target, decision, reason, at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                run_id,
                requested,
                result.decision.value,
                result.reason,
                utc_now(),
            ),
        )
        try:
            if getattr(self._conn, "in_transaction", True):
                self._conn.commit()
        except sqlite3.OperationalError:
            pass

    # ------------------------------------------------------------------
    # Convenience: check + record in one call
    # ------------------------------------------------------------------

    def gate(
        self,
        target: str,
        run_id: str | None = None,
        *,
        is_url: bool = False,
        is_binary: bool = False,
    ) -> ScopeDecisionResult:
        """All-in-one gate: check + record decision. Raises nothing — callers
        must inspect result.decision and refuse action on DENY."""
        if is_url:
            result = self.check_url(target)
        elif is_binary:
            result = self.check_binary_file(target)
        else:
            result = self.check_destination(target)
        self.record_decision(target, result, run_id)
        return result


def setup_scope_for_target(
    conn: sqlite3.Connection,
    target: str,
    exclusions: list[str] | None = None,
    binaries: dict[str, str] | None = None,
    created_by: str = "universal-launcher",
) -> tuple[ScopeManifest, str | None]:
    """Parse any universal target (URL, domain, IP, or CIDR) and lock a ScopeManifest in SQLite.

    Supports:
    - HTTP/HTTPS URLs: 'http://192.168.60.139/', 'https://lab.ctf.io/app'
    - Plain IP addresses: '192.168.60.139', '10.10.10.5'
    - Host and port: '192.168.60.139:1111', 'target.local:8080'
    - CIDR ranges: '192.168.60.0/24'

    Returns:
        tuple[ScopeManifest, str | None]: (locked_manifest, seed_url)
    """
    import hashlib
    import json
    from pathlib import Path

    target = target.strip()
    if not target:
        raise ValueError("Target specification cannot be empty")

    seed_url: str | None = None
    resolved_ips: list[str] = []
    included_prefixes: list[str] = []
    included_hosts: list[str] = []

    # 1. Full HTTP/HTTPS URLs
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.hostname or target
        seed_url = target
        try:
            ip_obj = ipaddress.ip_address(host)
            resolved_ips = [str(ip_obj)]
        except ValueError:
            try:
                addr_infos = socket.getaddrinfo(host, None)
                resolved_ips = list({info[4][0] for info in addr_infos})
            except (socket.gaierror, OSError):
                resolved_ips = []
        included_prefixes = [
            f"{ip}/{128 if ipaddress.ip_address(ip).version == 6 else 32}"
            for ip in resolved_ips
        ]
        included_hosts = list(resolved_ips)

    # 2. CIDR network blocks (e.g. 192.168.60.0/24)
    elif "/" in target and not target.startswith("/"):
        try:
            net = ipaddress.ip_network(target, strict=False)
            included_prefixes = [str(net)]
            included_hosts = []
        except ValueError:
            host = target.split("/")[0]
            try:
                ip_obj = ipaddress.ip_address(host)
                resolved_ips = [str(ip_obj)]
            except ValueError:
                try:
                    addr_infos = socket.getaddrinfo(host, None)
                    resolved_ips = list({info[4][0] for info in addr_infos})
                except (socket.gaierror, OSError):
                    resolved_ips = []
            included_prefixes = [
                f"{ip}/{128 if ipaddress.ip_address(ip).version == 6 else 32}"
                for ip in resolved_ips
            ]
            included_hosts = list(resolved_ips)

    # 3. Host or host:port
    else:
        host = target
        port: int | None = None
        if ":" in target:
            parts = target.split(":", 1)
            host = parts[0]
            if parts[1].isdigit():
                port = int(parts[1])
        try:
            ip_obj = ipaddress.ip_address(host)
            resolved_ips = [str(ip_obj)]
        except ValueError:
            try:
                addr_infos = socket.getaddrinfo(host, None)
                resolved_ips = list({info[4][0] for info in addr_infos})
            except (socket.gaierror, OSError):
                resolved_ips = []
        included_prefixes = [
            f"{ip}/{128 if ipaddress.ip_address(ip).version == 6 else 32}"
            for ip in resolved_ips
        ]
        included_hosts = list(resolved_ips)
        if port in (80, 443, 8080, 8000, 1111, 8833, 8888):
            scheme = "https" if port == 443 else "http"
            seed_url = f"{scheme}://{host}:{port}/"

    if not included_prefixes and not included_hosts:
        raise ValueError(f"Could not resolve valid network target from: {target}")

    # Discover and register target binaries if available on disk
    binary_hashes = dict(binaries or {})
    if not binary_hashes:
        bin_dir = Path("target_binaries")
        if bin_dir.exists() and bin_dir.is_dir():
            for bf in bin_dir.glob("*"):
                if bf.is_file() and not bf.name.endswith((".txt", ".md", ".json", ".py")):
                    try:
                        digest = hashlib.sha256(bf.read_bytes()).hexdigest()
                        binary_hashes[str(bf)] = digest
                    except (OSError, PermissionError):
                        pass

    scope_version = new_id("scope")
    locked_at = utc_now()

    manifest = ScopeManifest(
        scope_version=scope_version,
        included_prefixes=included_prefixes,
        included_hosts=included_hosts,
        exclusions=exclusions or [],
        binary_hashes=binary_hashes,
        created_by=created_by,
        locked_at=locked_at,
    )

    conn.execute(
        """
        INSERT INTO scope_manifests
        (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            manifest.scope_version,
            json.dumps(manifest.included_prefixes),
            json.dumps(manifest.included_hosts),
            json.dumps(manifest.exclusions),
            json.dumps(manifest.binary_hashes),
            manifest.created_by,
            manifest.locked_at,
        ),
    )
    conn.commit()

    return manifest, seed_url
