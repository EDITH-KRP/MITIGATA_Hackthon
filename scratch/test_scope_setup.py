import sqlite3
import ipaddress
import socket
import json
from urllib.parse import urlparse
from pathlib import Path
from cart.store import connect
from cart.models import ScopeManifest, new_id, utc_now

def setup_scope_for_target(
    conn: sqlite3.Connection,
    target: str,
    exclusions: list[str] | None = None,
    binaries: dict[str, str] | None = None,
    created_by: str = "universal-launcher",
) -> tuple[ScopeManifest, str | None]:
    target = target.strip()
    if not target:
        raise ValueError("Target specification cannot be empty")
    seed_url: str | None = None
    resolved_ips: list[str] = []
    included_prefixes: list[str] = []
    included_hosts: list[str] = []

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
            except Exception:
                resolved_ips = []
        included_prefixes = [f"{ip}/32" for ip in resolved_ips]
        included_hosts = list(resolved_ips)
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
                except Exception:
                    resolved_ips = []
            included_prefixes = [f"{ip}/32" for ip in resolved_ips]
            included_hosts = list(resolved_ips)
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
            except Exception:
                resolved_ips = []
        included_prefixes = [f"{ip}/32" for ip in resolved_ips]
        included_hosts = list(resolved_ips)
        if port in (80, 443, 8080, 8000, 1111, 8833, 8888):
            scheme = "https" if port == 443 else "http"
            seed_url = f"{scheme}://{host}:{port}/"

    if not included_prefixes and not included_hosts:
        raise ValueError(f"Could not resolve valid network target from: {target}")

    binary_hashes = dict(binaries or {})
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

conn = connect(":memory:")
m1, u1 = setup_scope_for_target(conn, "http://192.168.60.139:1111/ops")
print("M1:", m1.included_prefixes, "Hosts:", m1.included_hosts, "Seed:", u1)
m2, u2 = setup_scope_for_target(conn, "192.168.60.0/24")
print("M2:", m2.included_prefixes, "Hosts:", m2.included_hosts, "Seed:", u2)
m3, u3 = setup_scope_for_target(conn, "127.0.0.1:8080")
print("M3:", m3.included_prefixes, "Hosts:", m3.included_hosts, "Seed:", u3)
print("SUCCESS!")

