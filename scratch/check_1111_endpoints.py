import urllib.request

paths = [
    '/', '/health', '/status', '/metrics', '/robots.txt', '/docs', '/api',
    '/log', '/logs', '/monitor', '/view', '/console', '/debug', '/admin',
    '/version', '/info', '/ping'
]

for p in paths:
    url = f'http://192.168.60.139:1111{p}'
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            print(f"[+] 200 OK: {p} -> {resp.read().decode()[:100]}")
    except urllib.error.HTTPError as e:
        print(f"[*] {p} -> {e.code}")
    except Exception as e:
        print(f"[-] {p} -> {e}")

