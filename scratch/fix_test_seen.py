with open('tests/test_cart.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key) VALUES ('a_h', 'r1', 'host', '192.168.1.5')",
    "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_h', 'r1', 'host', '192.168.1.5', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
)
text = text.replace(
    "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key) VALUES ('a_w', 'r1', 'web_app', '192.168.1.5')",
    "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_w', 'r1', 'web_app', '192.168.1.5', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
)

with open('tests/test_cart.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated first_seen and last_seen!')

