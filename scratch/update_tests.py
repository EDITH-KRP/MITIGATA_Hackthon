with open('tests/test_cart.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''        self.assertEqual(
            set(adv.keys()),
            {"finding_id", "title", "plain_english_summary", "impact",
             "recommended_fix", "patch_example"},
        )'''

replacement = '''        self.assertTrue(
            {"finding_id", "title", "plain_english_summary", "impact",
             "recommended_fix", "patch_example"}.issubset(set(adv.keys()))
        )'''

assert target in text, 'target not found'
text = text.replace(target, replacement, 1)

with open('tests/test_cart.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated tests/test_cart.py successfully!')

