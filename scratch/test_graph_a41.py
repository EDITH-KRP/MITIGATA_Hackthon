import sys
sys.path.insert(0, "src")
import sqlite3
from cart.attackpath import derive_run_relationships, AttackPathBuilder

conn = sqlite3.connect("cart.db")
derive_run_relationships(conn, "run_a41f9facb5fe")
builder = AttackPathBuilder(conn, "run_a41f9facb5fe")
paths = builder.build()
print(f"Paths for run_a41f9facb5fe: {len(paths)}")
for p in paths:
    for e in p.edges:
        print(" ", e.source_id, "->", e.target_id, e.relationship_type)
