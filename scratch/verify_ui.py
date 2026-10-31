import urllib.request
with urllib.request.urlopen('http://127.0.0.1:8080/') as res:
    html = res.read().decode('utf-8')
    print('Status:', res.status)
    print('Has Universal Target Launcher:', 'Universal Target Assessment Launcher' in html)
    print('Has Target Input:', 'id="target-input"' in html)
    print('Has Launch Button:', 'id="btn-launch-run"' in html)

