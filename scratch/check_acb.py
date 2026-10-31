import sqlite3
conn = sqlite3.connect('cart.db')
run_id = 'run_acb051d2fd86'
scope = conn.execute("SELECT s.included_prefixes, s.included_hosts, s.created_by, s.locked_at FROM runs r JOIN scope_manifests s ON r.scope_version = s.scope_version WHERE r.run_id = 'run_acb051d2fd86'").fetchone()
print('Scope for run_acb051d2fd86:', scope)
tasks = conn.execute("SELECT task_id, task_type, target_id, status FROM tasks WHERE dedupe_key LIKE 'run_acb051d2fd86%'").fetchall()
print('Tasks for run_acb051d2fd86:', len(tasks))
for t in tasks:
    print(' ', t)
assets = conn.execute("SELECT asset_id, asset_type, canonical_key FROM assets WHERE run_id = 'run_acb051d2fd86'").fetchall()
print('Assets:', len(assets))
for a in assets:
    print(' ', a)
findings = conn.execute("SELECT f.finding_id, a.canonical_key, f.finding_type, f.severity, f.status FROM findings f JOIN assets a ON f.asset_id = a.asset_id WHERE a.run_id = 'run_acb051d2fd86'").fetchall()
print('Findings:', len(findings))
for f in findings:
    print(' ', f)

