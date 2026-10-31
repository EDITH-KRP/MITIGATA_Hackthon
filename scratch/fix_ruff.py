import re

# 1. Fix src/cart/ui.py
with open('src/cart/ui.py', 'r', encoding='utf-8') as f:
    ui_text = f.read()

# Replace def _handle_graph
old_def = '        def _handle_graph(self) -> None:\n        conn = connect('
new_def = '    def _handle_graph(self) -> None:\n        conn = connect('
ui_text = ui_text.replace(old_def, new_def, 1)

# Check all lines in _handle_graph body that start with 8 spaces
# Let's inspect _handle_graph block
pattern = r'    def _handle_graph\(self\) -> None:\n([\s\S]*?)\n    def _handle_report'
m = re.search(pattern, ui_text)
if m:
    body = m.group(1)
    # Ensure each line in body starts with 8 spaces
    fixed_lines = []
    for line in body.splitlines():
        if line.strip():
            # if line starts with 4 spaces (and not 8), add 4 spaces
            if line.startswith('    ') and not line.startswith('        '):
                fixed_lines.append('    ' + line)
            elif not line.startswith('    '):
                fixed_lines.append('        ' + line)
            else:
                fixed_lines.append(line)
        else:
            fixed_lines.append('')
    fixed_body = '\n'.join(fixed_lines)
    ui_text = ui_text[:m.start(1)] + fixed_body + ui_text[m.end(1):]

with open('src/cart/ui.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(ui_text)
print('Fixed ui.py indentation!')

# 2. Fix src/cart/attackpath.py
with open('src/cart/attackpath.py', 'r', encoding='utf-8') as f:
    ap_text = f.read()

ap_text = ap_text.replace('fid, aid, key, atype, ftype, sev, evid = r', '_fid, aid, _key, _atype, ftype, _sev, evid = r')
with open('src/cart/attackpath.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(ap_text)
print('Fixed attackpath.py unused vars!')

# 3. Fix src/cart/scope.py
with open('src/cart/scope.py', 'r', encoding='utf-8') as f:
    sc_text = f.read()

sc_text = sc_text.replace('except Exception:\n                resolved_ips = []', 'except (socket.gaierror, OSError):\n                resolved_ips = []')
sc_text = sc_text.replace('except Exception:\n                        pass', 'except (OSError, PermissionError):\n                        pass')
with open('src/cart/scope.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(sc_text)
print('Fixed scope.py blind exceptions!')

# 4. Fix src/cart/cli.py
with open('src/cart/cli.py', 'r', encoding='utf-8') as f:
    cli_text = f.read()

cli_text = cli_text.replace('manifest, seed_url = setup_scope_for_target(', 'manifest, _seed_url = setup_scope_for_target(')
with open('src/cart/cli.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(cli_text)
print('Fixed cli.py unused vars!')

