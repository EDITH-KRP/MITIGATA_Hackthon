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

print("=== README.txt ===")
readme = get('/index.php?p=&dl=README.txt')
print(readme)

print("=== backups ===")
backups = get('/index.php?p=backups')
for m in re.findall(r'href="([^"]*p=[^"]*)"', backups):
    print("backups link:", m)
for f in re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', backups):
    print("FLAG in backups:", f)

print("=== ops ===")
ops = get('/index.php?p=ops')
for m in re.findall(r'href="([^"]*p=[^"]*)"', ops):
    print("ops link:", m)
for f in re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', ops):
    print("FLAG in ops:", f)

