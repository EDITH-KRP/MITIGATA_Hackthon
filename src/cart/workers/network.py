from __future__ import annotations


def _safe_commit(conn: sqlite3.Connection) -> None:
    try:
        if getattr(conn, "in_transaction", True):
            conn.commit()
    except sqlite3.OperationalError:
        pass


import concurrent.futures
import hashlib
import ipaddress
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import (
    Asset,
    Evidence,
    Finding,
    FindingStatus,
    ScopeDecision,
    Service,
    Task,
    ToolEvent,
    new_id,
    utc_now,
)
from ..ptes import PtesPhase
from ..scope import PolicyGate, ScopeDecisionResult

# Minimum supported Nmap version
_MIN_NMAP_MAJOR = 7

# Common TCP ports catalog for native socket fallback
_COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 443, 445, 993, 995, 1111,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 27017,
]

_PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 1111: "lmsocialserver", 88: "kerberos", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http", 8080: "http-proxy",
    8443: "https-alt", 8888: "http", 9000: "http", 27017: "mongodb",
}

_COMMON_UDP_PORTS: list[int] = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1194, 1434, 1900, 4500, 5353,
]

_UDP_SERVICE_MAP: dict[int, str] = {
    53: "domain", 67: "dhcps", 68: "dhcpc", 69: "tftp", 123: "ntp",
    137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 162: "snmptrap",
    500: "isakmp", 514: "syslog", 1194: "openvpn", 1434: "ms-sql-m",
    1900: "ssdp", 4500: "ipsec-nat-t", 5353: "zeroconf",
}


def _probe_udp_port(ip: str, port: int, timeout_s: float = 0.5) -> tuple[bool, str]:
    """Single non-destructive UDP probe to detect open/responsive UDP services."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout_s)
            payload = b""
            if port == 53:
                payload = b"\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            elif port == 123:
                payload = b"\x1b" + 47 * b"\0"
            else:
                payload = b"\x00" * 4
            s.sendto(payload, (ip, port))
            try:
                data, _ = s.recvfrom(256)
                banner = "".join(chr(b) if 0x20 <= b < 0x7F else " " for b in data).strip()
                return True, banner[:80]
            except (TimeoutError, OSError):
                return False, ""
    except OSError:
        return False, ""


def _check_nmap() -> str | None:
    """Return path to nmap binary, or None if not installed."""
    nmap = shutil.which("nmap")
    if nmap is None:
        return None
    try:
        out = subprocess.run(
            [nmap, "--version"], check=False, capture_output=True, text=True, timeout=10
        ).stdout
        import re
        m = re.search(r"Nmap (\d+)\.", out)
        if m and int(m.group(1)) < _MIN_NMAP_MAJOR:
            return None
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    return nmap


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_nmap(nmap: str, args: list[str], timeout: int = 300) -> bytes:
    """Run nmap, return raw XML bytes. Raises on non-zero exit."""
    result = subprocess.run(
        [nmap, *args],
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode not in (0, 1):  # nmap exits 1 for "host down" runs
        raise RuntimeError(
            f"nmap exited {result.returncode}: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# XML normaliser
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_bytes: bytes, run_id: str) -> tuple[list[Asset], list[Service]]:
    """Parse Nmap XML output → (assets, services)."""
    root = ET.fromstring(xml_bytes)
    assets: list[Asset] = []
    services: list[Service] = []

    for host_el in root.findall("host"):
        # Status check — only process hosts reported up
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        # Canonical IP
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        asset = Asset(
            asset_id=new_id("asset"),
            run_id=run_id,
            asset_type="host",
            canonical_key=ip,
        )
        assets.append(asset)

        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_num = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            version = ""
            if svc_el is not None:
                parts = [svc_el.get("product", ""), svc_el.get("version", "")]
                version = " ".join(p for p in parts if p).strip()

            services.append(
                Service(
                    service_id=new_id("svc"),
                    asset_id=asset.asset_id,
                    protocol=proto,
                    port=port_num,
                    service_name=svc_name,
                    version=version,
                    state="open",
                )
            )

    return assets, services


# ---------------------------------------------------------------------------
# DB persistence helpers
# ---------------------------------------------------------------------------

def _persist_asset(conn: sqlite3.Connection, asset: Asset) -> str:
    """Upsert asset, return actual asset_id (existing or new)."""
    try:
        conn.execute(
            "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (asset.asset_id, asset.run_id, asset.asset_type, asset.canonical_key,
             asset.first_seen, asset.last_seen),
        )
        _safe_commit(conn)
        return asset.asset_id
    except sqlite3.IntegrityError:
        # Already exists — return existing id, update last_seen
        row = conn.execute(
            "SELECT asset_id FROM assets WHERE run_id=? AND asset_type=? AND canonical_key=?",
            (asset.run_id, asset.asset_type, asset.canonical_key),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE assets SET last_seen=? WHERE asset_id=?",
                (utc_now(), row[0]),
            )
            _safe_commit(conn)
            return row[0]
        return asset.asset_id


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

def _persist_service(conn: sqlite3.Connection, svc: Service) -> None:
    try:
        conn.execute(
            "INSERT INTO services (service_id, asset_id, protocol, port, service_name, version, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (svc.service_id, svc.asset_id, svc.protocol, svc.port,
             svc.service_name, svc.version, svc.state),
        )
        _safe_commit(conn)
    except sqlite3.IntegrityError:
        pass  # duplicate service — idempotent


def _persist_tool_event(conn: sqlite3.Connection, event: ToolEvent) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO tool_events "
        "(event_id, task_id, tool, target, scope_decision, started_at, finished_at, exit_status, output_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event.event_id, event.task_id, event.tool, event.target,
         event.scope_decision.value, event.started_at, event.finished_at,
         event.exit_status, event.output_hash),
    )
    _safe_commit(conn)


def _probe_tcp_port(ip: str, port: int, timeout_s: float = 0.4) -> bool:
    """Single TCP connect_ex probe (non-blocking, OS-level connect timeout)."""
    return _connect_probe(ip, port, timeout_s, grab_banner=False)[0]


def _connect_probe(
    ip: str, port: int, timeout_s: float = 0.4, grab_banner: bool = False
) -> tuple[bool, str]:
    """One TCP connect via socket.connect_ex + optional passive banner read.

    The connect is bounded by the socket timeout (never blocks indefinitely).
    Banner harvesting is *passive*: we read what the service itself sends and
    never transmit any payload — discovery-grade, non-destructive behaviour.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            if s.connect_ex((ip, port)) != 0:
                return False, ""
            if not grab_banner:
                return True, ""
            try:
                data = s.recv(120)
            except (TimeoutError, OSError):
                data = b""
        banner = "".join(chr(b) if 0x20 <= b < 0x7F else " " for b in data).strip()
        return True, banner[:80]
    except Exception:  # noqa: BLE001 - unreachable/refused host: not open
        return False, ""


def _scan_native_sockets(
    target: str,
    gate: PolicyGate,
    run_id: str,
    *,
    ports: list[int] | None = None,
    all_ports: bool = False,
    udp_ports: list[int] | None = None,
    scan_udp: bool = True,
    max_workers: int = 64,
    deadline: float | None = None,
) -> tuple[list[Asset], list[Service]]:
    """Pure stdlib multi-threaded TCP & UDP scanner (zero external dependencies).

    Builds bounded, non-blocking connect jobs per (allowed host × port),
    executes them through a ThreadPoolExecutor, and applies PolicyGate rules
    before submission. Results normalize to canonical Asset + Service records.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
    except ValueError:
        return [], []

    if ports is not None:
        port_list = list(ports)
    elif all_ports:
        port_list = list(range(1, 65536))
    else:
        port_list = list(_COMMON_PORTS)
    udp_port_list = list(udp_ports) if udp_ports is not None else list(_COMMON_UDP_PORTS)

    # Gate-per-IP up front (audit-logged); all in-scope allowed hosts generate jobs
    allowed_ips: list[str] = []
    for host in hosts:
        decision = gate.gate(str(host), run_id)
        if decision.decision is ScopeDecision.ALLOW:
            allowed_ips.append(str(host))

    if not allowed_ips:
        return [], []

    # Host presence phase: for subnets with > 8 hosts, pre-filter for live hosts
    active_ips: list[str] = []
    if len(allowed_ips) > 8:
        presence_ports = [80, 443, 22, 135, 445, 8080]
        for ip in allowed_ips:
            for p in presence_ports:
                is_up, _ = _connect_probe(ip, p, 0.25)
                if is_up:
                    active_ips.append(ip)
                    break
        if not active_ips:
            active_ips = allowed_ips  # fallback if firewall drops common discovery ports
    else:
        active_ips = allowed_ips

    tcp_jobs: list[tuple[str, int]] = [
        (ip, port) for ip in active_ips for port in port_list
    ]
    udp_jobs: list[tuple[str, int]] = (
        [(ip, port) for ip in active_ips for port in udp_port_list] if scan_udp else []
    )

    open_tcp: dict[str, dict[int, str]] = {}
    open_udp: dict[str, dict[int, str]] = {}

    # TCP probes
    pool_size = max(1, min(max_workers, len(tcp_jobs) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as pool:
        futures = {
            pool.submit(_connect_probe, ip, port, 0.4, grab_banner=True): (ip, port)
            for ip, port in tcp_jobs
        }
        for fut in concurrent.futures.as_completed(futures):
            if deadline is not None and time.monotonic() > deadline:
                for pending in futures:
                    pending.cancel()
                break
            ip, port = futures[fut]
            try:
                is_open, banner = fut.result()
            except Exception:  # noqa: BLE001 - failed probe = not open
                is_open, banner = False, ""
            if is_open:
                open_tcp.setdefault(ip, {})[port] = banner

    # UDP probes
    if udp_jobs and (deadline is None or time.monotonic() < deadline):
        udp_pool_size = max(1, min(16, len(udp_jobs)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=udp_pool_size) as pool:
            udp_futures = {
                pool.submit(_probe_udp_port, ip, port, 0.4): (ip, port)
                for ip, port in udp_jobs
            }
            for fut in concurrent.futures.as_completed(udp_futures):
                if deadline is not None and time.monotonic() > deadline:
                    for pending in udp_futures:
                        pending.cancel()
                    break
                ip, port = udp_futures[fut]
                try:
                    is_open, banner = fut.result()
                except Exception:  # noqa: BLE001
                    is_open, banner = False, ""
                if is_open:
                    open_udp.setdefault(ip, {})[port] = banner

    all_responsive_ips = sorted(set(open_tcp.keys()) | set(open_udp.keys()))
    assets: list[Asset] = []
    services: list[Service] = []
    for ip in all_responsive_ips:
        asset = Asset(
            asset_id=new_id("asset"),
            run_id=run_id,
            asset_type="host",
            canonical_key=ip,
        )
        assets.append(asset)
        for port in sorted(open_tcp.get(ip, {})):
            banner = open_tcp[ip][port]
            services.append(
                Service(
                    service_id=new_id("svc"),
                    asset_id=asset.asset_id,
                    protocol="tcp",
                    port=port,
                    service_name=_PORT_SERVICE_MAP.get(port, "unknown"),
                    version=banner,
                    state="open",
                )
            )
        for port in sorted(open_udp.get(ip, {})):
            banner = open_udp[ip][port]
            services.append(
                Service(
                    service_id=new_id("svc"),
                    asset_id=asset.asset_id,
                    protocol="udp",
                    port=port,
                    service_name=_UDP_SERVICE_MAP.get(port, "unknown"),
                    version=banner,
                    state="open",
                )
            )
    return assets, services


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

_WEB_PORTS = {80, 443, 1111, 8000, 8080, 8443, 8888}


class NetworkWorker:
    """In-scope live host / port / service discovery."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        gate: PolicyGate,
        run_id: str,
        all_ports: bool = False,
        scan_udp: bool = False,
    ):
        self.conn = conn
        self.gate = gate
        self.run_id = run_id
        self.all_ports = all_ports
        self.scan_udp = scan_udp
        self._nmap = _check_nmap()

    def _run_native_scan(
        self, task: Task, scope_decision: ScopeDecision | None = None
    ) -> tuple[list[Asset], list[Service]]:
        """Run the native scanner with a fresh, audited tool event.

        Re-passes the already-computed scope decision when available so the
        audit trail records exactly one allow/deny decision per target.
        """
        timeout_s = task.budget.get("timeout_s", 300)
        if scope_decision is None:
            scope_decision = self.gate.gate(task.target_id, self.run_id).decision
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="native_tcp_scanner",
            target=task.target_id,
            scope_decision=scope_decision,
            started_at=utc_now(),
        )
        deadline = time.monotonic() + timeout_s
        custom_ports = task.budget.get("ports")
        all_ports = task.budget.get("all_ports", self.all_ports)
        scan_udp = task.budget.get("scan_udp", self.scan_udp)
        assets, services = _scan_native_sockets(
            task.target_id, self.gate, self.run_id, ports=custom_ports, all_ports=all_ports, scan_udp=scan_udp, deadline=deadline
        )
        event.finished_at = utc_now()
        event.exit_status = "0"
        event.output_hash = hashlib.sha256(
            f"{len(assets)}:{len(services)}".encode()
        ).hexdigest()
        _persist_tool_event(self.conn, event)
        return assets, services

    def run(self, task: Task) -> dict:
        """Execute host + port discovery for task.target_id (an IP/CIDR).

        Returns dict with keys: assets, services, web_asset_ids, findings.
        """
        target = task.target_id
        if target.startswith("asset_"):
            row = self.conn.execute(
                "SELECT canonical_key FROM assets WHERE asset_id=?", (target,)
            ).fetchone()
            if row:
                target = row[0]

        # SCOPE GATE — must pass before any packet
        result: ScopeDecisionResult = self.gate.gate(target, self.run_id)
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="nmap",
            target=target,
            scope_decision=result.decision,
            started_at=utc_now(),
        )

        if result.decision is ScopeDecision.DENY:
            event.finished_at = utc_now()
            event.exit_status = "scope_denied"
            _persist_tool_event(self.conn, event)
            raise PermissionError(f"Scope DENY for target {target!r}: {result.reason}")

        # Choose scanner: Nmap if available, otherwise native TCP sockets.
        # If Nmap is present but fails at runtime, degrade to native sockets
        # seamlessly — with a failed tool event recorded for the audit trail.
        if self._nmap is not None:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    xml_path = Path(tmpdir) / "scan.xml"
                    port_range = task.budget.get("port_range")
                    if port_range:
                        ports_arg = str(port_range)
                    elif task.budget.get("all_ports", self.all_ports):
                        ports_arg = "1-65535"
                    elif task.budget.get("ports"):
                        ports_arg = ",".join(str(p) for p in task.budget["ports"])
                    else:
                        ports_arg = ",".join(str(p) for p in _COMMON_PORTS)

                    nmap_args = [
                        "-Pn",            # treat all hosts as online (lab environment / firewalled targets)
                        "-sV",            # version detection
                        "--version-light",
                        "-p", ports_arg,  # bounded or full port range
                        "--open",         # only open ports
                        "-T4",            # aggressive timing (lab environment)
                        "--max-retries", "1",
                        "--host-timeout", str(task.budget.get("timeout_s", 120)) + "s",
                        "-oX", str(xml_path),
                        target,
                    ]
                    xml_bytes = _run_nmap(
                        self._nmap,
                        nmap_args,
                        timeout=task.budget.get("timeout_s", 300),
                    )
                    if xml_path.exists():
                        xml_bytes = xml_path.read_bytes()

                    udp_bytes = b""
                    # Separate, non-interfering UDP scan pass when requested
                    if task.budget.get("scan_udp", self.scan_udp):
                        try:
                            udp_xml = Path(tmpdir) / "udp_scan.xml"
                            udp_ports = ",".join(str(p) for p in _COMMON_UDP_PORTS)
                            udp_args = [
                                "-Pn", "-sU", "-p", udp_ports, "--open", "-T4",
                                "--max-retries", "1", "--host-timeout", "60s",
                                "-oX", str(udp_xml), target,
                            ]
                            _run_nmap(self._nmap, udp_args, timeout=90)
                            if udp_xml.exists():
                                udp_bytes = udp_xml.read_bytes()
                        except (subprocess.SubprocessError, OSError):
                            udp_bytes = b""

                output_hash = _sha256_bytes(xml_bytes)
                event.finished_at = utc_now()
                event.exit_status = "0"
                event.output_hash = output_hash
                _persist_tool_event(self.conn, event)

                # Normalise XML
                assets, services = _parse_nmap_xml(xml_bytes, self.run_id)
                if udp_bytes:
                    u_assets, u_services = _parse_nmap_xml(udp_bytes, self.run_id)
                    assets.extend(u_assets)
                    services.extend(u_services)
                if not assets:
                    assets, services = self._run_native_scan(
                        task, scope_decision=result.decision
                    )
            except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
                event.finished_at = utc_now()
                event.exit_status = f"error:{exc}"
                _persist_tool_event(self.conn, event)
                # Seamless degradation: retry discovery with native sockets
                assets, services = self._run_native_scan(
                    task, scope_decision=result.decision
                )
        else:
            # Native socket scan fallback
            assets, services = self._run_native_scan(
                task, scope_decision=result.decision
            )

        # Persist + track web assets
        web_asset_ids: list[str] = []
        asset_by_id = {a.asset_id: a for a in assets}
        for asset in assets:
            _persist_asset(self.conn, asset)

        emitted_findings: list[str] = []
        for svc in services:
            asset = asset_by_id.get(svc.asset_id)
            if asset is None:
                continue  # service references an asset this scan did not emit
            _persist_service(self.conn, svc)
            if svc.port in _WEB_PORTS:
                # Scope-check the specific web service before marking web
                web_result = self.gate.gate(asset.canonical_key, self.run_id, is_url=False)
                if web_result.decision is ScopeDecision.ALLOW:
                    web_asset_ids.append(asset.asset_id)

            # 1. Cleartext unencrypted network service
            if svc.port in (80, 1111, 21, 23, 25, 110, 8000, 8080) and svc.protocol == "tcp":
                f_cleartext = Finding(
                    finding_id=new_id("find"),
                    asset_id=asset.asset_id,
                    finding_type="unencrypted_cleartext_service",
                    severity="medium",
                    status=FindingStatus.CANDIDATE,
                    confidence="high",
                    ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
                    summary=f"Unencrypted cleartext service exposed on port {svc.port}/{svc.protocol} ({svc.service_name}) without TLS encryption (CWE-319)",
                )
                fid = _persist_finding(self.conn, f_cleartext)
                ev = Evidence(
                    evidence_id=new_id("evid"),
                    finding_id=fid,
                    source_tool="nmap",
                    artifact_path=f"{asset.canonical_key}:{svc.port}",
                    hash=hashlib.sha256(f"{asset.canonical_key}:{svc.port}:{svc.service_name}".encode()).hexdigest(),
                    excerpt=f"port={svc.port}; protocol={svc.protocol}; service={svc.service_name}; banner={svc.version}",
                    verification_method="nmap_service_probe",
                )
                _persist_evidence(self.conn, ev)
                emitted_findings.append(fid)

            # 2. Non-standard port exposure
            if svc.port not in (80, 443, 22, 53, 21, 25) and svc.state == "open":
                f_nonstd = Finding(
                    finding_id=new_id("find"),
                    asset_id=asset.asset_id,
                    finding_type="non_standard_service_port",
                    severity="low",
                    status=FindingStatus.CANDIDATE,
                    confidence="high",
                    ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                    summary=f"Non-standard network service port {svc.port}/{svc.protocol} ({svc.service_name}) exposed directly on target (CWE-657)",
                )
                fid = _persist_finding(self.conn, f_nonstd)
                ev = Evidence(
                    evidence_id=new_id("evid"),
                    finding_id=fid,
                    source_tool="nmap",
                    artifact_path=f"{asset.canonical_key}:{svc.port}",
                    hash=hashlib.sha256(f"{asset.canonical_key}:{svc.port}".encode()).hexdigest(),
                    excerpt=f"port={svc.port}; protocol={svc.protocol}; service_name={svc.service_name}",
                    verification_method="nmap_port_scan",
                )
                _persist_evidence(self.conn, ev)
                emitted_findings.append(fid)

            # 3. Service version fingerprint
            if svc.version and re.search(r"\d+\.\d+", svc.version):
                f_ver = Finding(
                    finding_id=new_id("find"),
                    asset_id=asset.asset_id,
                    finding_type="network_service_fingerprint",
                    severity="low",
                    status=FindingStatus.CANDIDATE,
                    confidence="high",
                    ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                    summary=f"Software version fingerprint detected by network scanner: {svc.port}/{svc.protocol} running {svc.version} (CWE-200)",
                )
                fid = _persist_finding(self.conn, f_ver)
                ev = Evidence(
                    evidence_id=new_id("evid"),
                    finding_id=fid,
                    source_tool="nmap",
                    artifact_path=f"{asset.canonical_key}:{svc.port}",
                    hash=hashlib.sha256(svc.version.encode()).hexdigest(),
                    excerpt=f"port={svc.port}; service={svc.service_name}; version={svc.version}",
                    verification_method="nmap_version_detection",
                )
                _persist_evidence(self.conn, ev)
                emitted_findings.append(fid)

        return {
            "assets": [a.asset_id for a in assets],
            "services": len(services),
            "web_asset_ids": list(set(web_asset_ids)),
            "findings": emitted_findings,
        }
