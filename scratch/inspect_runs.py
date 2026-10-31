import sqlite3

conn = sqlite3.connect("cart.db")
runs = conn.execute("SELECT run_id, started_at, tier, status FROM runs ORDER BY rowid ASC").fetchall()
for r in runs:
    sev_rows = conn.execute(
        "SELECT severity, COUNT(*) FROM findings f JOIN assets a ON f.asset_id=a.asset_id WHERE a.run_id=? GROUP BY severity",
        (r[0],)
    ).fetchall()
    f_types = conn.execute(
        "SELECT DISTINCT f.finding_type FROM findings f JOIN assets a ON f.asset_id=a.asset_id WHERE a.run_id=?",
        (r[0],)
    ).fetchall()
    if sev_rows:
        print(f"Run: {r[0]} ({r[1]}) - Status: {r[3]}")
        print(f"  Severities: {sev_rows}")
        print(f"  Types: {[t[0] for t in f_types]}")
        print()
conn.close()

