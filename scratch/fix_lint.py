import re

# 1. Fix src/cart/ui.py
with open("src/cart/ui.py", "r", encoding="utf-8") as f:
    ui_code = f.read()

# Add import re
if "import re" not in ui_code[:300]:
    ui_code = ui_code.replace("import html", "import html\nimport re")

# Make _INDEX_HTML a raw string
ui_code = ui_code.replace('_INDEX_HTML = """<!DOCTYPE html>', '_INDEX_HTML = r"""<!DOCTYPE html>')

# Fix startswith tuple
ui_code = ui_code.replace('elif stripped.startswith("- ") or stripped.startswith("* "):', 'elif stripped.startswith(("- ", "* ")):')

with open("src/cart/ui.py", "w", encoding="utf-8") as f:
    f.write(ui_code)

# 2. Fix src/cart/report.py
with open("src/cart/report.py", "r", encoding="utf-8") as f:
    rep_code = f.read()

rep_code = rep_code.replace("f\"# Penetration Testing Execution Standard (PTES) Assessment Report\",", "\"# Penetration Testing Execution Standard (PTES) Assessment Report\",")
rep_code = rep_code.replace("f\"| **Assessment Framework** | Penetration Testing Execution Standard (PTES) |\",", "\"| **Assessment Framework** | Penetration Testing Execution Standard (PTES) |\",")
rep_code = rep_code.replace("except Exception:\n                    pfxs, hosts, excls, bin_h = [], [], [], {}", "except (json.JSONDecodeError, KeyError, TypeError, ValueError):\n                    pfxs, hosts, excls, bin_h = [], [], [], {}")
rep_code = rep_code.replace("except Exception:\n                advisory_data = {", "except (KeyError, TypeError, ValueError):\n                advisory_data = {")

# Parenthesize implicit string concatenations in collections
rep_code = rep_code.replace(
    '"All assessment activities strictly conformed to the pre-authorized scope manifest. "\n            "Traffic routing and worker tasking were continuously validated by the deterministic `PolicyGate`.",',
    '("All assessment activities strictly conformed to the pre-authorized scope manifest. "\n            "Traffic routing and worker tasking were continuously validated by the deterministic `PolicyGate`."),'
)
rep_code = rep_code.replace(
    '"Active and passive reconnaissance mapped reachable hosts, listening TCP/UDP daemons, "\n            "service version banners, and exposed web applications.",',
    '("Active and passive reconnaissance mapped reachable hosts, listening TCP/UDP daemons, "\n            "service version banners, and exposed web applications."),'
)
rep_code = rep_code.replace(
    '"This section provides full VAPT expert writeups for all confirmed security weaknesses, "\n            "documenting exactly **how and where each vulnerability was found**, the evidence proof-of-concept, "\n            "and **how it can be patched**.",',
    '("This section provides full VAPT expert writeups for all confirmed security weaknesses, "\n            "documenting exactly **how and where each vulnerability was found**, the evidence proof-of-concept, "\n            "and **how it can be patched**."),'
)
rep_code = rep_code.replace(
    '"Autonomous exploitation successfully retrieved sensitive proof-of-concept markers and CTF flags "\n            "without manual intervention, verifying end-to-end exploitability.",',
    '("Autonomous exploitation successfully retrieved sensitive proof-of-concept markers and CTF flags "\n            "without manual intervention, verifying end-to-end exploitability."),'
)
rep_code = rep_code.replace(
    '"The Attack Path Builder chained confirmed findings to demonstrate how an adversary "\n            "could pivot across security boundaries:",',
    '("The Attack Path Builder chained confirmed findings to demonstrate how an adversary "\n            "could pivot across security boundaries:"),'
)
rep_code = rep_code.replace(
    '"Remediation actions are structured into three prioritized tiers according to risk severity:",',
    '("Remediation actions are structured into three prioritized tiers according to risk severity:"),'
)

with open("src/cart/report.py", "w", encoding="utf-8") as f:
    f.write(rep_code)

print("Fixes applied successfully!")

