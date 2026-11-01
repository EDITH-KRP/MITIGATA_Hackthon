import urllib.request
import re

headers = {'X-Forwarded-For': '192.168.60.1'}

def fetch(path):
    url = f'http://192.168.60.139{path}'
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return 0, str(e)

s, body = fetch('/')
print("=== / ===")
print("Status:", s)
print("Title:", re.findall(r'<title>(.*?)</title>', body, re.I))
flags = re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', body)
if flags:
    print("FLAGS IN /:", flags)

links = set(re.findall(r'href=["\'](/[^"\']*)["\']', body))
print("Discovered links:", links)

# Let's inspect page contents for each
for p in sorted(links):
    s, b = fetch(p)
    print(f"\n--- {p} (status {s}, length {len(b)}) ---")
    fl = re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', b)
    if fl:
        print(f"*** FLAGS IN {p}: {fl} ***")
    # Clean text to see what is written
    text = re.sub(r'<[^>]+>', ' ', b)
    text = ' '.join(text.split())
    print("Content preview:", text[:300])

    # Check for sublinks
    sub = set(re.findall(r'href=["\'](/[^"\']*)["\']', b))
    for sl in sub:
        if sl not in links:
            print("  New sublink:", sl)

