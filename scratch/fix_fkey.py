with open('tests/test_cart.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''    def test_derive_run_relationships(self):
        from cart.attackpath import derive_run_relationships, AttackPathBuilder
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_h', 'r1', 'host', '192.168.1.5', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")'''

repl = '''    def test_derive_run_relationships(self):
        from cart.attackpath import derive_run_relationships, AttackPathBuilder
        self.conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s1', '[]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES ('r1', 'completed', 'recon', '2026-01-01T00:00:00Z', 's1')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_h', 'r1', 'host', '192.168.1.5', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")'''

assert target in text, 'target not found'
text = text.replace(target, repl, 1)

with open('tests/test_cart.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated foreign keys!')

