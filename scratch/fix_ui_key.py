with open('src/cart/ui.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '"key": key,'
assert target in text
new_text = text.replace('"key": key,', '"canonical_key": key,\n            "key": key,')
with open('src/cart/ui.py', 'w', encoding='utf-8') as f:
    f.write(new_text)
print('Updated ui.py canonical_key!')

