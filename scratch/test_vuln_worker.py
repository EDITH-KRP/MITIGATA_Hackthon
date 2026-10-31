import sqlite3
import hashlib
from pathlib import Path
from cart.models import ScopeManifest, Task, utc_now
from cart.scope import PolicyGate
from cart.workers.binary import BinaryWorker
from cart.verify import VerificationService
from cart.store import connect

conn = connect(':memory:')

conn.execute("INSERT INTO runs (run_id, status, tier) VALUES ('test_run', 'running', 'recon')")
conn.commit()

p = Path('target_binaries/vuln_worker.bin')
digest = hashlib.sha256(p.read_bytes()).hexdigest()
manifest = ScopeManifest(
    scope_version='test_scope',
    included_prefixes=['192.168.1.0/24'],
    binary_hashes={str(p): digest},
    locked_at=utc_now(),
)
gate = PolicyGate(manifest)
gate.bind_store(conn)

task = Task(task_id='t1', task_type='binary_static_analysis', owner='binary', target_id=str(p))
conn.execute("INSERT INTO tasks (task_id, task_type, owner, target_id, status) VALUES ('t1', 'binary_static_analysis', 'binary', ?, 'running')", (str(p),))
conn.commit()

worker = BinaryWorker(conn, gate, 'test_run')
res = worker.run(task)

verifier = VerificationService(conn, 'test_run')
verifier.queue(res['findings'])
verifier.verify_all_queued()

findings = conn.execute('SELECT finding_type, severity, status, summary FROM findings').fetchall()
print(f'Total findings: {len(findings)}')
for f in findings:
    print(f'  [{f[1].upper()}] ({f[2]}) {f[0]}: {f[3]}')
