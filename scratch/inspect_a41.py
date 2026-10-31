import sqlite3

conn = sqlite3.connect("cart.db")
row = conn.execute("SELECT scope_version FROM runs WHERE run_id = 'run_a41f9facb5fe'").fetchone()
manifest = conn.execute("SELECT included_prefixes, included_hosts, binary_hashes FROM scope_manifests WHERE scope_version = ?", (row[0],)).fetchone()
print("Scope prefixes:", manifest[0])
print("Scope hosts:", manifest[1])
print("Binary hashes:", manifest[2])

tasks = conn.execute("SELECT task_id, task_type, owner, status, target_id FROM tasks WHERE dedupe_key LIKE 'run_a41f9facb5fe%'").fetchall()
print(f"Tasks for run_a41f9facb5fe ({len(tasks)}):")
for t in tasks:
    print(" ", t)

