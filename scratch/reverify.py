import sys
sys.path.insert(0, ".")
import sqlite3
from src.cart.verify import VerificationService
from src.cart.report import ReportGenerator

conn = sqlite3.connect('cart.db')
run_id = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()[0]

conn.execute("UPDATE findings SET status = 'candidate' WHERE finding_type = 'ctf_planted_flag' AND status != 'confirmed'")
conn.commit()

verifier = VerificationService(conn, run_id)
cands = [r[0] for r in conn.execute("SELECT finding_id FROM findings WHERE status = 'candidate'").fetchall()]
verifier.queue(cands)
ver_res = verifier.verify_all_queued()
print("Verified count:", len(ver_res))

# Regenerate report
rep = ReportGenerator(conn)
out = rep.generate(run_id)
print("Report regenerated:", out["md_report"])

conn.close()
