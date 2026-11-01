import urllib.request
import re

cookie = 'filemanager=31d9d419d12f4fb42c375d7c8e04fdb7'

req = urllib.request.Request('http://192.168.60.139/index.php?p=', headers={'Cookie': cookie})
with urllib.request.urlopen(req) as r:
    html = r.read().decode('utf-8', errors='ignore')

idx = html.find('function fm_search')
if idx != -1:
    print(html[idx:idx+1500])
else:
    print("Not found")

