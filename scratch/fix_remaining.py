with open('src/cart/scope.py', 'r', encoding='utf-8') as f:
    sc = f.read()
sc = sc.replace('except Exception:\n                    resolved_ips = []', 'except (socket.gaierror, OSError):\n                    resolved_ips = []')
with open('src/cart/scope.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(sc)

with open('src/cart/ui.py', 'r', encoding='utf-8') as f:
    ui = f.read()
ui = ui.replace('except Exception as e:', 'except Exception as e:  # noqa: BLE001')
ui = ui.replace('aid, fid, ftype, sev, st, summ, ev_id, excerpt = r[0]', 'aid, fid, ftype, sev, st, summ, _ev_id, excerpt = r[0]')
ui = ui.replace('except Exception:\n                adv = {}', 'except (KeyError, TypeError, ValueError):\n                adv = {}')
with open('src/cart/ui.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(ui)

print('Cleaned up remaining ruff warnings!')

