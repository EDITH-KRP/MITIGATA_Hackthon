with open('src/cart/verify.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = 'r"flag\{[^\}]+\}|CTF\{[^\}]+\}|CyberForge\{[^\}]+\}",'
replacement = 'r"flag\{[^\}]+\}|CTF\{[^\}]+\}|CyberForge\{[^\}]+\}|MITIGATA\{[^\}]+\}|[a-zA-Z0-9_-]+\{[^\}]+\}",'
assert target in text
new_text = text.replace(target, replacement)
with open('src/cart/verify.py', 'w', encoding='utf-8') as f:
    f.write(new_text)
print('Updated verify.py flag pattern!')

