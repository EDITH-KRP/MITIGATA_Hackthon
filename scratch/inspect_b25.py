import sqlite3

conn = sqlite3.connect("cart.db")
tasks = conn.execute("SELECT task_id, task_type, owner, status, target_id FROM tasks WHERE dedupe_key LIKE 'run_b2588018a9fc%'").fetchall()
print(f"Tasks for run_b2588018a9fc ({len(tasks)}):")
for t in tasks:
    print(" ", t)

