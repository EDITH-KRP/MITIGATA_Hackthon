import socket
import re

def get(path):
    s = socket.create_connection(('192.168.60.139', 80), timeout=3)
    req = f"GET {path} HTTP/1.1\r\nHost: 192.168.60.139\r\nCookie: filemanager=31d9d419d12f4fb42c375d7c8e04fdb7\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    res = b""
    while True:
        c = s.recv(4096)
        if not c: break
        res += c
    s.close()
    return res.decode('utf-8', errors='ignore')

for path in ['/index.php?p=&view=README.txt', '/index.php?p=ops&view=netops-handover.txt', '/index.php?p=backups&view=placeholder.txt']:
    print(f"=== PATH: {path} ===")
    content = get(path)
    # Extract code or pre block or plain text
    matches = re.findall(r'<pre[^>]*>(.*?)</pre>', content, re.DOTALL)
    if matches:
        for m in matches:
            print("PRE BLOCK:\n", m.strip()[:1000])
    else:
        flags = re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', content)
        print("FLAGS:", flags)
        print("SNIPPET:", content[:500])

