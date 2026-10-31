with open('src/cart/report.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '### PRD Assessment Quality KPIs'
assert target in text
new_text = text.replace(target, '## 2. PRD Assessment Metrics')
with open('src/cart/report.py', 'w', encoding='utf-8') as f:
    f.write(new_text)
print('Updated report.py metrics heading!')

