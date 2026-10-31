import sqlite3
from cart.advisor import RemediationAdvisor

conn = sqlite3.connect('cart.db')
advisor = RemediationAdvisor(conn)
f_row = conn.execute("SELECT finding_id, finding_type FROM findings WHERE severity IN ('critical', 'high') LIMIT 1").fetchone()
print('Testing finding:', f_row)
adv = advisor.advise(f_row[0])
print('Keys returned:', list(adv.keys()))
print('CWE:', adv.get('cwe_id'))
print('CVSS:', adv.get('cvss_score'), adv.get('cvss_vector'))
print('Reproduction:', adv.get('reproduction_command'))
print('Verification:', adv.get('verification_test'))

