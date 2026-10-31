with open('tests/test_cart.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = "self.conn.execute(\"INSERT INTO evidence (evidence_id, finding_id, excerpt) VALUES ('e1', 'f1', 'Spoofed XFF')\")"
repl = "self.conn.execute(\"INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt) VALUES ('e1', 'f1', 'test_tool', 'test_path', 'hash123', '2026-01-01T00:00:00Z', 'Spoofed XFF')\")"

assert target in text, 'target not found'
text = text.replace(target, repl, 1)

with open('tests/test_cart.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated evidence schema in test!')

