import sqlite3

conn = sqlite3.connect("cart.db")
rows = conn.execute("""
    SELECT f.finding_id, f.finding_type, f.severity, f.summary, e.source_tool, e.artifact_path, e.excerpt
    FROM findings f
    JOIN assets a ON f.asset_id = a.asset_id
    LEFT JOIN evidence e ON f.finding_id = e.finding_id
    WHERE a.run_id = 'run_a41f9facb5fe' AND f.severity IN ('critical', 'high')
""").fetchall()
for r in rows:
    print(r[1], f"({r[2]})", "tool:", r[4], "path:", r[5])
    print("  excerpt:", r[6][:100] if r[6] else "None")

