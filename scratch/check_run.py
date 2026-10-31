import sqlite3
conn = sqlite3.connect('cart.db')
run = conn.execute("SELECT run_id, status, started_at, completed_at FROM runs WHERE run_id = 'run_b7a13ea5e5ea'").fetchone()
print('Run status:', run)
tasks = conn.execute("SELECT task_type, status, target_id FROM tasks WHERE dedupe_key LIKE 'run_b7a13ea5e5ea%'").fetchall()
print('Tasks for run:', len(tasks))
for t in tasks:
    print(' ', t)
findings = conn.execute("SELECT finding_type, severity, status FROM findings WHERE finding_id IN (SELECT finding_id FROM evidence WHERE timestamp >= '2026-10-31T19:30:00Z')").fetchall()
print('New findings:', len(findings))

