with open('tests/test_cart.py', 'r', encoding='utf-8') as f:
    text = f.read()

new_tests = '''

class TestUniversalTargetAndAttackGraph(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_setup_scope_for_target_url(self):
        from cart.scope import setup_scope_for_target
        manifest, seed_url = setup_scope_for_target(self.conn, "http://192.168.60.139:1111/ops")
        self.assertIsNotNone(manifest.locked_at)
        self.assertIn("192.168.60.139/32", manifest.included_prefixes)
        self.assertIn("192.168.60.139", manifest.included_hosts)
        self.assertEqual(seed_url, "http://192.168.60.139:1111/ops")

    def test_setup_scope_for_target_cidr(self):
        from cart.scope import setup_scope_for_target
        manifest, seed_url = setup_scope_for_target(self.conn, "10.0.0.0/24")
        self.assertIsNotNone(manifest.locked_at)
        self.assertIn("10.0.0.0/24", manifest.included_prefixes)
        self.assertIsNone(seed_url)

    def test_derive_run_relationships(self):
        from cart.attackpath import derive_run_relationships, AttackPathBuilder
        self.conn.execute("INSERT INTO assets (asset_id, asset_type, canonical_key) VALUES ('a_h', 'host', '192.168.1.5')")
        self.conn.execute("INSERT INTO assets (asset_id, asset_type, canonical_key) VALUES ('a_w', 'web_app', '192.168.1.5')")
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f1', 'a_h', 'reverse_proxy_ip_spoofing', 'high', 'confirmed')")
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, excerpt) VALUES ('e1', 'f1', 'Spoofed XFF')")
        self.conn.commit()

        count = derive_run_relationships(self.conn)
        self.assertGreaterEqual(count, 1)
        builder = AttackPathBuilder(self.conn, "current")
        paths = builder.build()
        self.assertGreaterEqual(len(paths), 1)


if __name__ == "__main__":
    unittest.main()
'''

target = '''if __name__ == "__main__":
    unittest.main()'''

assert target in text, 'target not found'
text = text.replace(target, new_tests.strip(), 1)

with open('tests/test_cart.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Appended universal target and attack graph tests!')

