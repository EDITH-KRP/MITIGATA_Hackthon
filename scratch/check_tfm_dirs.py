import socket
import re

def request_tfm(path):
    s = socket.create_connection(('192.168.60.139', 80), timeout=3)
    req = (
        f"GET /index.php{path} HTTP/1.1\r\n"
        "Host: 192.168.60.139\r\n"
        "Cookie: filemanager=31d9d419d12f4fb42c375d7c8e04fdb7\r\n"
        "Connection: close\r\n\r\n"
    )
    s.sendall(req.encode())
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    return buf.decode('utf-8', errors='ignore')

# 1. Read README.txt
print("=== README.txt ===")
readme_resp = request_tfm("?p=&view=README.txt")
# Find text or print body
print(readme_resp[:2000])

# 2. List ?p=backups
print("\n=== ?p=backups ===")
backups_resp = request_tfm("?p=backups")
for m in re.findall(r'href="([^"]*index\.php\?[^"]*)"', backups_resp):
    print("Backups Link:", m)
flags_b = re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', backups_resp)
if flags_b:
    print("FLAGS IN BACKUPS:", flags_b)

# 3. List ?p=ops
print("\n=== ?p=ops ===")
ops_resp = request_tfm("?p=ops")
for m in re.findall(r'href="([^"]*index\.php\?[^"]*)"', ops_resp):
    print("Ops Link:", m)
flags_o = re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', ops_resp)
if flags_o:
    print("FLAGS IN OPS:", flags_o)

