import sqlite3
conn = sqlite3.connect('cart.db')
run_id = 'run_9e0d486f1cbf'

print('Tasks for run_9e0d486f1cbf:')
for t in conn.execute("SELECT task_id, task_type, target_id, status FROM tasks WHERE dedupe_key LIKE 'run_9e0d486f1cbf%'").fetchall():
    print(t)

print('Assets for run_9e0d486f1cbf:')
for a in conn.execute("SELECT asset_id, asset_type, canonical_key FROM assets WHERE run_id = 'run_9e0d486f1cbf'").fetchall():
    print(a)

print('Findings linked to assets of run_9e0d486f1cbf:')
query = """
    SELECT f.finding_id, f.asset_id, a.canonical_key, f.finding_type, f.severity, f.status
    FROM findings f
    JOIN assets a ON f.asset_id = a.asset_id
    WHERE a.run_id = 'run_9e0d486f1cbf'
"""
for f in conn.execute(query).fetchall():
    print(f)

