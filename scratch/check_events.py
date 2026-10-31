import sqlite3
conn = sqlite3.connect('cart.db')
run_id = 'run_9e0d486f1cbf'

print('Tool events:')
query = """
    SELECT tool, target, scope_decision, exit_status
    FROM tool_events
    WHERE task_id IN (SELECT task_id FROM tasks WHERE dedupe_key LIKE 'run_9e0d486f1cbf%')
"""
for r in conn.execute(query).fetchall():
    print(r)

print('\nFindings created during run_9e0d486f1cbf:')
f_query = """
    SELECT f.finding_id, f.asset_id, a.canonical_key, f.finding_type, f.severity, f.status, f.summary
    FROM findings f
    JOIN assets a ON f.asset_id = a.asset_id
    WHERE a.run_id = 'run_9e0d486f1cbf'
"""
for r in conn.execute(f_query).fetchall():
    print(r)

