import sqlite3

conn = sqlite3.connect("cart.db")
rows = conn.execute("""
    SELECT f.finding_id, f.finding_type, f.severity, f.status, f.summary
    FROM findings f
    JOIN assets a ON f.asset_id = a.asset_id
    WHERE a.run_id = 'run_a41f9facb5fe' AND f.severity != 'info'
    ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
""").fetchall()

print(f"Total non-info findings for run_a41f9facb5fe: {len(rows)}")
for r in rows:
    print(f"[{r[2].upper()}] {r[1]} -> {r[4][:70]}")

