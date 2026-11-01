from check_tfm_dirs import request_tfm
import re

for d in ['backups', 'ops']:
    resp = request_tfm(f"?p={d}")
    print(f"=== DIRECTORY: {d} (len {len(resp)}) ===")
    
    # In Tiny File Manager, directory items are listed in a table with id="main-table"
    # Find rows in main-table
    table = re.search(r'<table[^>]*id="main-table"[^>]*>(.*?)</table>', resp, re.DOTALL)
    if table:
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', table.group(1), re.DOTALL)
        for r in rows:
            text = ' '.join(re.sub(r'<[^>]+>', ' ', r).split())
            if text:
                print("  Row:", text)
    else:
        print("  main-table not found, finding all a hrefs:")
        for m in re.findall(r'href="([^"]+)"', resp):
            if "index.php" in m:
                print("   ", m)

