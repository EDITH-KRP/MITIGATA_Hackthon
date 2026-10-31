with open('tests/test_cart.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    "INSERT INTO assets (asset_id, asset_type, canonical_key) VALUES ('a_h', 'host', '192.168.1.5')",
    "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key) VALUES ('a_h', 'r1', 'host', '192.168.1.5')"
)
text = text.replace(
    "INSERT INTO assets (asset_id, asset_type, canonical_key) VALUES ('a_w', 'web_app', '192.168.1.5')",
    "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key) VALUES ('a_w', 'r1', 'web_app', '192.168.1.5')"
)

with open('tests/test_cart.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated assets insertion in test!')

