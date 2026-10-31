with open('src/cart/advisor.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('"reproduction_command": "python3 -c \'print("A"*512)\' | ./binary",', '"reproduction_command": "python3 -c \\"print(\'A\'*512)\\" | ./binary",')

with open('src/cart/advisor.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Fixed quotes in advisor.py!')

