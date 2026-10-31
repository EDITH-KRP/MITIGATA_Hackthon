with open('src/cart/attackpath.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''    assets_by_type: dict[str, list[tuple[str, str]]] = {}
    for r in rows:
        aid, key, atype = r[1], r[2], r[3]
        assets_by_type.setdefault(atype, [])
        if (aid, key) not in assets_by_type[atype]:
            assets_by_type[atype].append((aid, key))'''

repl = '''    all_assets = conn.execute("SELECT asset_id, canonical_key, asset_type FROM assets").fetchall()
    assets_by_type: dict[str, list[tuple[str, str]]] = {}
    for aid, key, atype in all_assets:
        assets_by_type.setdefault(atype, []).append((aid, key))'''

assert target in text, 'target not found'
text = text.replace(target, repl, 1)

with open('src/cart/attackpath.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated assets_by_type in attackpath.py!')

