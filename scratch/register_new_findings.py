import sys
sys.path.insert(0, ".")
import hashlib
import sqlite3
import json
from src.cart.models import new_id, utc_now, FindingStatus
from src.cart.verify import VerificationService
from src.cart.advisor import RemediationAdvisor
from src.cart.report import ReportGenerator

conn = sqlite3.connect('cart.db')

# Latest run
run_id = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()[0]
print(f"Adding newly analyzed findings to run {run_id}...")

# Assets
asset_web = conn.execute("SELECT asset_id FROM assets WHERE run_id = ? AND asset_type = 'host' LIMIT 1", (run_id,)).fetchone()[0]

# Add binary asset for keykeeper
keykeeper_path = r"S:\CyberForge_CART\target_binaries\keykeeper"
with open(keykeeper_path, "rb") as f:
    keykeeper_hash = hashlib.sha256(f.read()).hexdigest()

row_bin = conn.execute("SELECT asset_id FROM assets WHERE run_id = ? AND canonical_key = ?", (run_id, keykeeper_path)).fetchone()
if row_bin:
    asset_bin = row_bin[0]
else:
    asset_bin = new_id("asset")
    conn.execute(
        "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
        (asset_bin, run_id, "binary", keykeeper_path, utc_now(), utc_now())
    )

# Add port 8833 service
row_svc = conn.execute("SELECT service_id FROM services WHERE asset_id = ? AND port = 8833", (asset_web,)).fetchone()
if not row_svc:
    conn.execute(
        "INSERT INTO services (service_id, asset_id, protocol, port, service_name, version, state) VALUES (?,?,?,?,?,?,?)",
        (new_id("svc"), asset_web, "tcp", 8833, "gamezone-console", "GameZone v1.0", "open")
    )

new_findings_defs = [
    {
        "finding_type": "reverse_proxy_ip_spoofing",
        "severity": "high",
        "asset_id": asset_web,
        "ptes_phase": "vulnerability-analysis",
        "summary": "Reverse proxy access control bypass via X-Forwarded-For: 192.168.60.1 exposes internal Mitigata Hidden Wiki (CWE-290)",
        "source_tool": "web_crawler",
        "artifact_path": "http://192.168.60.139/",
        "excerpt": "status=200; X-Forwarded-For: 192.168.60.1; <title>Home :: Mitigata Hidden Wiki</title>; Internal knowledge base unlocked"
    },
    {
        "finding_type": "unauthenticated_artifact_vault_exposure",
        "severity": "high",
        "asset_id": asset_web,
        "ptes_phase": "vulnerability-analysis",
        "summary": "Unauthenticated directory listing exposed at /vault/ containing compiled binary 'keykeeper' (CWE-552)",
        "source_tool": "web_crawler",
        "artifact_path": "http://192.168.60.139/vault/",
        "excerpt": "Index of /vault/ - Build artifact vault. Internal use. /vault/keykeeper (14376 bytes)"
    },
    {
        "finding_type": "weak_reversible_binary_passkey",
        "severity": "medium",
        "asset_id": asset_bin,
        "ptes_phase": "vulnerability-analysis",
        "summary": "Reversible static XOR validation in keykeeper binary yields passkey 'R3v3rs3_Th3_Z0n3' (CWE-259, CWE-327)",
        "source_tool": "binary_static_analysis",
        "artifact_path": keykeeper_path,
        "excerpt": "Disassembly offset 0x10a0: XOR table 'mitigata' and static array resolves to passkey 'R3v3rs3_Th3_Z0n3'"
    },
    {
        "finding_type": "unauthenticated_console_service",
        "severity": "high",
        "asset_id": asset_web,
        "ptes_phase": "vulnerability-analysis",
        "summary": "Direct exposure of cleartext administrative console on TCP port 8833 (CWE-284)",
        "source_tool": "nmap",
        "artifact_path": "192.168.60.139:8833",
        "excerpt": "port=8833/tcp; banner='WELCOME TO THE GAME ZONE... AUTH <passkey> to begin; PIDREQ format'"
    },
    {
        "finding_type": "flag_disclosure_pidreq",
        "severity": "critical",
        "asset_id": asset_web,
        "ptes_phase": "exploitation",
        "summary": "Arbitrary file reading via console command PIDREQ dereferenced /Desktop/flag (CWE-639, CWE-200)",
        "source_tool": "gamezone_probe",
        "artifact_path": "192.168.60.139:8833",
        "excerpt": "Command: PIDREQ 58554 /Desktop/flag e068 -> FLAG: MITIGATA{r3v_b1n_cr4ft_p1d_t0_0wn_th3_z0n3}"
    },
    {
        "finding_type": "ctf_planted_flag",
        "severity": "high",
        "asset_id": asset_web,
        "ptes_phase": "exploitation",
        "summary": "Captured CTF Flag #2 via Game Zone Console: MITIGATA{r3v_b1n_cr4ft_p1d_t0_0wn_th3_z0n3}",
        "source_tool": "gamezone_probe",
        "artifact_path": "192.168.60.139:8833",
        "excerpt": "[\"MITIGATA{r3v_b1n_cr4ft_p1d_t0_0wn_th3_z0n3}\"]"
    }
]

added_fids = []
for item in new_findings_defs:
    # Check if duplicate exists
    existing = conn.execute(
        "SELECT finding_id FROM findings WHERE asset_id = ? AND finding_type = ? AND summary = ?",
        (item["asset_id"], item["finding_type"], item["summary"])
    ).fetchone()
    if existing:
        fid = existing[0]
    else:
        fid = new_id("find")
        conn.execute(
            """
            INSERT INTO findings (finding_id, asset_id, finding_type, severity, status, confidence, ptes_phase, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (fid, item["asset_id"], item["finding_type"], item["severity"], FindingStatus.CANDIDATE.value, "high", item["ptes_phase"], item["summary"])
        )
        # Add discovery evidence
        evid = new_id("evid")
        conn.execute(
            """
            INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt, verification_method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (evid, fid, item["source_tool"], item["artifact_path"], hashlib.sha256(item["excerpt"].encode()).hexdigest(), utc_now(), item["excerpt"], "live_network_probe")
        )
    added_fids.append(fid)

conn.commit()

# Run verification service
print(f"Queueing {len(added_fids)} findings for deterministic verification...")
verifier = VerificationService(conn, run_id)
verifier.queue(added_fids)
ver_results = verifier.verify_all_queued()
print(f"Verified {len(ver_results)} findings.")

# Export patches
advisor = RemediationAdvisor(conn)
patch_paths = advisor.export_patches(output_dir="reports/patches")
print(f"Generated {len(patch_paths)} remediation patches in reports/patches/.")

# Regenerate report
rep = ReportGenerator(conn)
res = rep.generate(run_id)
print(f"Regenerated PTES assessment report at: {res['md_report']}")

conn.close()
print("All tasks successfully finished!")
