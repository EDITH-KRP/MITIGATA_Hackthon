with open('src/cart/scope.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    '    if not binary_hashes:\n        bin_dir = Path("target_binaries")',
    '    if not binary_hashes and not seed_url:\n        bin_dir = Path("target_binaries")'
)

with open('src/cart/scope.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated scope.py: binaries only loaded if not a seed_url!')

