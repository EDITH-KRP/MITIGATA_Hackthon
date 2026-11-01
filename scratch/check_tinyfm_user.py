import urllib.request, re

req = urllib.request.Request('http://192.168.60.139/index.php?p=', headers={'Cookie': 'filemanager=31d9d419d12f4fb42c375d7c8e04fdb7'})
with urllib.request.urlopen(req) as resp:
    body = resp.read().decode('utf-8', errors='ignore')

# Check username or avatar
for match in re.finditer(r'<li[^>]*class="[^"]*nav-item avatar[^"]*"[^>]*>(.*?)</li>', body, re.DOTALL):
    print("Avatar element:", re.sub(r'<[^>]+>', ' ', match.group(1)).strip())

# Check all links
links = re.findall(r'href="([^"]+)"', body)
action_links = [l for l in links if 'logout' in l or 'login' in l or 'user' in l or 'admin' in l or 'help' in l]
print("Action links:", action_links)

