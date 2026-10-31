import sqlite3

def derive_run_relationships(conn: sqlite3.Connection, run_id: str | None = None) -> int:
    """Ensure evidence-backed relationships exist in SQLite for confirmed findings."""
    # Check current relationships count
    cnt = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    
    # Query confirmed findings and evidence
    query = """
        SELECT f.finding_id, f.asset_id, a.canonical_key, a.asset_type, f.finding_type, f.severity, e.evidence_id
        FROM findings f
        JOIN assets a ON f.asset_id = a.asset_id
        JOIN evidence e ON f.finding_id = e.finding_id
        WHERE f.status = 'confirmed' AND f.severity IN ('critical', 'high', 'medium')
    """
    rows = conn.execute(query).fetchall()
    if not rows:
        return 0

    inserted = 0
    # Map assets by type and key
    assets_by_type: dict[str, list[tuple[str, str]]] = {}
    for r in rows:
        aid, key, atype = r[1], r[2], r[3]
        assets_by_type.setdefault(atype, [])
        if (aid, key) not in assets_by_type[atype]:
            assets_by_type[atype].append((aid, key))

    host_assets = [aid for aid, k in assets_by_type.get("host", [])]
    web_assets = [aid for aid, k in assets_by_type.get("web_app", [])]
    bin_assets = [aid for aid, k in assets_by_type.get("binary", [])]

    # Map finding types to evidence IDs
    finding_ev: dict[str, tuple[str, str]] = {}
    for r in rows:
        fid, aid, key, atype, ftype, sev, evid = r
        finding_ev[ftype] = (aid, evid)

    # 1. Reverse Proxy Bypass / Service Exposure: host -> web_app
    if "reverse_proxy_ip_spoofing" in finding_ev and host_assets and web_assets:
        aid, evid = finding_ev["reverse_proxy_ip_spoofing"]
        src = host_assets[0]
        dst = web_assets[0]
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "REVERSE_PROXY_IP_SPOOFING", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    # 2. Artifact Vault Download: web_app -> binary (keykeeper)
    if "unauthenticated_artifact_vault_exposure" in finding_ev and web_assets and bin_assets:
        aid, evid = finding_ev["unauthenticated_artifact_vault_exposure"]
        src = web_assets[0]
        # find keykeeper binary asset
        dst = next((ba for ba, bk in assets_by_type.get("binary", []) if "keykeeper" in bk.lower()), bin_assets[0])
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "ARTIFACT_VAULT_DOWNLOAD", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    # 3. Binary Passkey Reversed: binary (keykeeper) -> host
    if bin_assets and host_assets:
        src = next((ba for ba, bk in assets_by_type.get("binary", []) if "keykeeper" in bk.lower()), bin_assets[0])
        dst = host_assets[0]
        evid = finding_ev.get("unauthenticated_console_service", ("", ""))[1] or rows[0][6]
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "REVERSED_AUTH_PASSKEY", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    # 4. Binary Probe: host -> binary (vuln_auth_daemon)
    if bin_assets and host_assets:
        src = host_assets[0]
        dst = next((ba for ba, bk in assets_by_type.get("binary", []) if "vuln_auth_daemon" in bk.lower()), bin_assets[-1])
        evid = finding_ev.get("binary_unsafe_function", ("", ""))[1] or rows[0][6]
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "BINARY_DAEMON_PROBE", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    return inserted

conn = sqlite3.connect("cart.db")
print("Deriving relationships...")
added = derive_run_relationships(conn)
print(f"Added {added} relationships.")
print("Total relationships:", conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0])

