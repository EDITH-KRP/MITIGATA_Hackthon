import re

with open('src/cart/ui.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Imports
imp_target = 'from .attackpath import AttackPathBuilder'
imp_repl = '''from .attackpath import AttackPathBuilder, derive_run_relationships
from .models import FindingStatus, RunStatus, Task, TaskStatus, new_id, utc_now
from .orchestrator import Orchestrator
from .ptes import PtesPhase
from .scope import PolicyGate, setup_scope_for_target
from .verify import VerificationService
from .workers.binary import BinaryWorker
from .workers.network import NetworkWorker
from .workers.web import WebWorker'''

if imp_target in text and 'derive_run_relationships' not in text:
    text = text.replace(imp_target, imp_repl, 1)

# 2. Add Universal Target Assessment Launcher Card in HTML
# Right after </header>
launcher_html = '''
<!-- Universal Target Assessment Launcher -->
<div class="card" style="margin-bottom: 1.5rem; border-color: rgba(6, 182, 212, 0.4); background: linear-gradient(180deg, #090e1a 0%, #060912 100%);">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.8rem;">
    <div style="display:flex; align-items:center; gap:0.6rem;">
      <span style="font-size:1.2rem;">🎯</span>
      <span style="font-weight:700; color:#f1f5f9; font-size:1rem;">Universal Target Assessment Launcher</span>
      <span class="sev-pill" style="background:rgba(6,182,212,0.2); color:#38bdf8; border:1px solid rgba(6,182,212,0.4);">Public Lab / CTF / Network Range Ready</span>
    </div>
    <span id="launcher-status" style="font-size:0.8rem; color:#64748b;">Ready to assess any target URL, IP or CIDR</span>
  </div>
  <p style="color:#94a3b8; font-size:0.82rem; margin-bottom:1rem;">
    Assess any web application, CTF lab, or network infrastructure. The fail-closed <code>PolicyGate</code> locks scope, deploys network, web, and binary agents, captures flags, verifies vulnerabilities, and outputs a publication-grade PTES report.
  </p>
  <div style="display:flex; gap:0.8rem; align-items:center; flex-wrap:wrap;">
    <div style="flex:1; min-width:280px;">
      <input type="text" id="target-input" value="http://192.168.60.139/" placeholder="e.g. http://192.168.60.139/ or https://lab.ctf.io/ or 10.10.10.5 or 192.168.60.0/24" 
             style="width:100%; background:#030712; border:1px solid #1e293b; color:#fff; padding:0.6rem 0.9rem; border-radius:6px; font-family:Consolas, monospace; font-size:0.88rem;">
    </div>
    <div style="width:160px;">
      <select id="tier-select" style="width:100%; background:#030712; border:1px solid #1e293b; color:#fff; padding:0.6rem 0.8rem; border-radius:6px; font-size:0.88rem;">
        <option value="deep" selected>Tier: Deep Exploit</option>
        <option value="breach">Tier: Breach & PoC</option>
        <option value="recon">Tier: Recon Only</option>
      </select>
    </div>
    <button id="btn-launch-run" onclick="launchAssessment()" class="btn-primary" style="padding:0.6rem 1.4rem; font-size:0.88rem; display:flex; align-items:center; gap:0.5rem;">
      <span>🚀</span>
      <span>Launch Autonomous Run</span>
    </button>
  </div>
</div>
'''

header_end = '</header>'
if header_end in text and 'Universal Target Assessment Launcher' not in text:
    text = text.replace(header_end, header_end + '\n' + launcher_html, 1)

# 3. Add launchAssessment() function in JavaScript
launch_js = '''
async function launchAssessment() {
  const target = document.getElementById('target-input').value.trim();
  const tier = document.getElementById('tier-select').value;
  const statusEl = document.getElementById('launcher-status');
  const btn = document.getElementById('btn-launch-run');

  if (!target) {
    alert('Please enter a target URL, domain, IP, or CIDR (e.g. http://192.168.60.139/ or https://lab.ctf.io/).');
    return;
  }

  btn.disabled = true;
  btn.style.opacity = '0.6';
  btn.innerHTML = '<span>⏳</span><span>Locking Scope & Starting...</span>';
  statusEl.textContent = `Locking scope and initiating autonomous agents on ${target}...`;
  statusEl.style.color = '#38bdf8';

  try {
    const res = await fetch('/api/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target, tier: tier })
    });
    const data = await res.json();
    if (data.success) {
      statusEl.textContent = `✅ Run ${data.run_id} running! Assessing ${data.target}...`;
      statusEl.style.color = '#22c55e';
      setTimeout(() => refreshData(), 1200);
    } else {
      statusEl.textContent = `❌ Launch failed: ${data.error || 'Unknown error'}`;
      statusEl.style.color = '#ef4444';
      alert('Launch failed: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    statusEl.textContent = `❌ Network error: ${err.message}`;
    statusEl.style.color = '#ef4444';
  } finally {
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.innerHTML = '<span>🚀</span><span>Launch Autonomous Run</span>';
  }
}
'''

# 4. Replace renderGraph and showNodeDetails in JavaScript
graph_render_code = '''
function renderGraph(graph) {
  const svg = document.getElementById('attack-graph');
  svg.innerHTML = '';
  if (!graph.nodes || !graph.nodes.length) {
    svg.innerHTML = `
      <text x="50%" y="45%" fill="#38bdf8" text-anchor="middle" font-size="14" font-weight="bold">
        ⚔️ Autonomous Assessment Pipeline Active
      </text>
      <text x="50%" y="60%" fill="#64748b" text-anchor="middle" font-size="12">
        Evidence-backed attack paths will render as specialist agents verify targets.
      </text>
    `;
    return;
  }

  const width = svg.clientWidth || 920;
  const height = svg.clientHeight || 320;
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <marker id="arrow-red" viewBox="0 -5 10 10" refX="24" refY="0" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M0,-5L10,0L0,5" fill="#ef4444"></path>
    </marker>
    <marker id="arrow-cyan" viewBox="0 -5 10 10" refX="24" refY="0" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M0,-5L10,0L0,5" fill="#06b6d4"></path>
    </marker>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#ef4444" flood-opacity="0.7"/>
    </filter>
  `;
  svg.appendChild(defs);

  const stageRanks = {
    'target': 0, 'host': 0, 'recon': 0,
    'access_bypass': 1, 'web_app': 1, 'web': 1,
    'vault': 2, 'reversing': 2,
    'binary': 3, 'exploitation': 3,
    'objective': 4, 'flag': 4
  };

  const stageGroups = {};
  graph.nodes.forEach(n => {
    const s = n.stage || (n.asset_type === 'binary' ? 'binary' : n.asset_type === 'web_app' ? 'web_app' : 'target');
    const rank = stageRanks[s] !== undefined ? stageRanks[s] : 1;
    stageGroups[rank] = stageGroups[rank] || [];
    stageGroups[rank].push(n);
  });

  const ranks = Object.keys(stageGroups).map(Number).sort((a,b) => a-b);
  const minX = 80;
  const maxX = width - 90;
  const xSpan = ranks.length > 1 ? (maxX - minX) / (ranks.length - 1) : 0;

  const positions = {};
  ranks.forEach((r, rIdx) => {
    const group = stageGroups[r];
    const x = ranks.length > 1 ? minX + rIdx * xSpan : width / 2;
    const gLen = group.length;
    group.forEach((node, idx) => {
      let y = height / 2;
      if (gLen === 2) {
        y = idx === 0 ? height * 0.35 : height * 0.65;
      } else if (gLen > 2) {
        const ySpan = (height - 120) / (gLen - 1);
        y = 60 + idx * ySpan;
      }
      positions[node.id] = { x, y, node };
    });
  });

  // Draw Edges
  (graph.edges || []).forEach(e => {
    const p1 = positions[e.source];
    const p2 = positions[e.target];
    if (p1 && p2) {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      const dx = p2.x - p1.x;
      const cx = (p1.x + p2.x) / 2;
      const cy = (p1.y + p2.y) / 2 - (Math.abs(dx) > 40 ? 25 : 0);

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', `M ${p1.x} ${p1.y} Q ${cx} ${cy} ${p2.x} ${p2.y}`);
      path.setAttribute('stroke', '#ef4444');
      path.setAttribute('stroke-width', '2');
      path.setAttribute('fill', 'none');
      path.setAttribute('marker-end', 'url(#arrow-red)');
      path.setAttribute('stroke-dasharray', '4,3');
      g.appendChild(path);

      if (e.label) {
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', cx);
        text.setAttribute('y', cy - 5);
        text.setAttribute('fill', '#94a3b8');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('font-size', '9');
        text.setAttribute('font-family', 'Consolas, monospace');
        text.textContent = e.label.length > 30 ? e.label.substring(0, 28) + '…' : e.label;
        g.appendChild(text);
      }
      svg.appendChild(g);
    }
  });

  // Draw Nodes
  Object.values(positions).forEach(p => {
    const node = p.node;
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.style.cursor = 'pointer';
    g.onclick = () => showNodeDetails(node);

    const sevColors = {
      'CRITICAL': '#ef4444',
      'HIGH': '#f97316',
      'MEDIUM': '#f59e0b',
      'LOW': '#06b6d4',
      'INFO': '#38bdf8'
    };
    const color = sevColors[node.severity] || '#06b6d4';

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', p.x);
    circle.setAttribute('cy', p.y);
    circle.setAttribute('r', '18');
    circle.setAttribute('fill', '#090e1a');
    circle.setAttribute('stroke', color);
    circle.setAttribute('stroke-width', '2.5');
    circle.setAttribute('filter', 'url(#glow)');
    g.appendChild(circle);

    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    icon.setAttribute('x', p.x);
    icon.setAttribute('y', p.y + 5);
    icon.setAttribute('text-anchor', 'middle');
    icon.setAttribute('font-size', '14');
    icon.textContent = node.asset_type === 'binary' ? '⚙️' : node.asset_type === 'web_app' ? '🌐' : '🖥️';
    g.appendChild(icon);

    const pill = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    pill.setAttribute('x', p.x);
    pill.setAttribute('y', p.y - 25);
    pill.setAttribute('fill', color);
    pill.setAttribute('text-anchor', 'middle');
    pill.setAttribute('font-size', '9');
    pill.setAttribute('font-weight', 'bold');
    pill.setAttribute('font-family', 'Consolas, monospace');
    pill.textContent = node.severity || 'IN-SCOPE';
    g.appendChild(pill);

    const labelText = node.label || node.id.substring(0, 16);
    const labelBg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    const textLen = Math.min(labelText.length * 6.5, 170);
    labelBg.setAttribute('x', p.x - textLen / 2);
    labelBg.setAttribute('y', p.y + 24);
    labelBg.setAttribute('width', textLen);
    labelBg.setAttribute('height', '18');
    labelBg.setAttribute('rx', '4');
    labelBg.setAttribute('fill', 'rgba(15, 23, 42, 0.9)');
    labelBg.setAttribute('stroke', '#1e293b');
    g.appendChild(labelBg);

    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', p.x);
    label.setAttribute('y', p.y + 37);
    label.setAttribute('fill', '#f1f5f9');
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('font-size', '10');
    label.setAttribute('font-weight', '600');
    label.textContent = labelText.length > 24 ? labelText.substring(0, 22) + '…' : labelText;
    g.appendChild(label);

    svg.appendChild(g);
  });
}

function showNodeDetails(node) {
  document.getElementById('modal-title').textContent = `${node.label}`;
  
  let findingsHtml = '';
  if (node.findings && node.findings.length > 0) {
    findingsHtml = `
      <div style="margin-top:1rem;">
        <h4 style="color:#f1f5f9; font-size:0.9rem; margin-bottom:0.6rem; border-bottom:1px solid #1e293b; padding-bottom:0.3rem;">
          Verified Vulnerabilities & Findings (${node.findings.length})
        </h4>
        <div style="display:flex; flex-direction:column; gap:0.6rem; max-height:280px; overflow-y:auto; padding-right:4px;">
          ${node.findings.map(f => `
            <div style="background:#090d16; border:1px solid #1e293b; border-radius:6px; padding:0.7rem;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
                <span class="sev-pill sev-${(f.severity || 'low').toLowerCase()}">${(f.severity || 'LOW').toUpperCase()}</span>
                <span style="color:#22c55e; font-size:0.75rem; font-weight:700;">${f.cwe || 'CWE'} • CVSS ${f.cvss || 'N/A'}</span>
              </div>
              <div style="font-weight:600; color:#fff; font-size:0.85rem; margin-bottom:0.3rem;">${f.title || f.type}</div>
              <p style="color:#94a3b8; font-size:0.78rem; margin-bottom:0.5rem;">${f.summary || ''}</p>
              ${f.excerpt ? `
                <div style="background:#020617; border-left:3px solid #06b6d4; padding:0.4rem 0.6rem; margin-bottom:0.4rem; border-radius:2px;">
                  <div style="font-size:0.68rem; color:#64748b; text-transform:uppercase;">Live Evidence Proof:</div>
                  <pre style="color:#38bdf8; font-size:0.75rem; white-space:pre-wrap; margin:0; font-family:Consolas, monospace;">${f.excerpt}</pre>
                </div>
              ` : ''}
              ${f.remediation ? `
                <div style="background:#020617; border-left:3px solid #22c55e; padding:0.4rem 0.6rem; border-radius:2px;">
                  <div style="font-size:0.68rem; color:#64748b; text-transform:uppercase;">Remediation Patchwork:</div>
                  <pre style="color:#4ade80; font-size:0.75rem; white-space:pre-wrap; margin:0; font-family:Consolas, monospace;">${f.remediation}</pre>
                </div>
              ` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  } else {
    findingsHtml = `
      <p style="color:#94a3b8; margin-top:0.8rem; font-size:0.85rem;">
        No direct exploitable vulnerabilities isolated on this node. It serves as an authorized routing intermediary.
      </p>
    `;
  }

  document.getElementById('modal-body').innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.8rem;">
      <div>
        <span class="sev-pill sev-${(node.severity || 'low').toLowerCase()}">${(node.severity || 'INFO').toUpperCase()}</span>
        <span style="color:#38bdf8; font-size:0.8rem; font-weight:700; margin-left:0.6rem;">Stage: ${(node.stage || 'ASSESSMENT TARGET').toUpperCase()}</span>
      </div>
      <span style="color:#64748b; font-size:0.75rem; font-family:monospace;">ID: ${node.id}</span>
    </div>
    <div style="background:#090d16; border:1px solid #1e293b; border-radius:6px; padding:0.6rem 0.8rem; font-size:0.8rem;">
      <div><strong>Target Key:</strong> <code style="color:#38bdf8;">${node.canonical_key || node.label}</code></div>
      <div><strong>Asset Classification:</strong> <code>${(node.asset_type || 'host').toUpperCase()}</code></div>
    </div>
    ${findingsHtml}
    <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top:1rem; border-top:1px solid #1e293b; padding-top:0.8rem;">
      <button onclick="downloadPatches()" class="btn-sec" style="font-size:0.78rem;">💾 Download All Patches</button>
      <button onclick="openPrintableReport()" class="btn-primary" style="font-size:0.78rem;">📄 View Full VAPT Report</button>
    </div>
  `;
  document.getElementById('node-modal').style.display = 'flex';
}
'''

# Find old renderGraph and replace through showNodeDetails
old_rg_pattern = r'function renderGraph\(graph\)\s*\{[\s\S]*?function showNodeDetails\(node\)\s*\{[\s\S]*?document\.getElementById\(\'node-modal\'\)\.style\.display = \'flex\';\s*\}'
m = re.search(old_rg_pattern, text)
if m:
    text = text[:m.start()] + launch_js + '\n' + graph_render_code + text[m.end():]

# 5. Add do_POST and _handle_launch to DashboardHandler
dopost_code = '''
    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/launch":
            self._handle_launch()
        else:
            self._send_json({"error": "not found"}, status=404)

    def _handle_launch(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")
        try:
            data = json.loads(body)
            target = data.get("target", "").strip()
            tier = data.get("tier", "deep")
            if not target:
                self._send_json({"success": False, "error": "Target cannot be empty"}, status=400)
                return

            conn = connect(self.db_path, check_same_thread=False)
            manifest, seed_url = setup_scope_for_target(conn, target, created_by="ui-launcher")
            run_id = new_id("run")
            start_time = utc_now()

            conn.execute(
                "INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES (?, ?, ?, ?, ?)",
                (run_id, RunStatus.RUNNING.value, tier, start_time, manifest.scope_version),
            )
            conn.commit()

            import threading
            def _run_worker():
                t_conn = connect(self.db_path, check_same_thread=False)
                gate = PolicyGate(manifest)
                gate.bind_store(t_conn)
                orchestrator = Orchestrator(conn=t_conn, run_id=run_id, max_concurrency=4, total_time_budget_s=1200)
                net_worker = NetworkWorker(conn=t_conn, gate=gate, run_id=run_id)
                web_worker = WebWorker(conn=t_conn, gate=gate, run_id=run_id)
                bin_worker = BinaryWorker(conn=t_conn, gate=gate, run_id=run_id)

                for prefix in manifest.included_prefixes:
                    t = Task(
                        task_id=new_id("task"),
                        task_type="host_discovery",
                        owner="network",
                        target_id=prefix,
                        status=TaskStatus.READY,
                        ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                        dedupe_key=f"{run_id}:host:{prefix}",
                        budget={"timeout_s": 180, "retries": 1},
                    )
                    orchestrator.create_task(t)

                if seed_url:
                    t_web = Task(
                        task_id=new_id("task"),
                        task_type="web_crawl_endpoint_discovery",
                        owner="web",
                        target_id=seed_url,
                        status=TaskStatus.READY,
                        ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                        dedupe_key=f"{run_id}:web:{seed_url}",
                        budget={"timeout_s": 300, "retries": 1},
                    )
                    orchestrator.create_task(t_web)

                for b_path in manifest.binary_hashes:
                    t = Task(
                        task_id=new_id("task"),
                        task_type="binary_static_analysis",
                        owner="binary",
                        target_id=b_path,
                        status=TaskStatus.READY,
                        ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                        dedupe_key=f"{run_id}:bin:{b_path}",
                        budget={"timeout_s": 60, "retries": 1},
                    )
                    orchestrator.create_task(t)

                def dispatch_worker(task: Task) -> dict:
                    if task.owner == "network":
                        return net_worker.run(task)
                    elif task.owner == "web":
                        return web_worker.run(task)
                    elif task.owner == "binary":
                        return bin_worker.run(task)
                    raise ValueError(f"Unknown task owner: {task.owner}")

                def handle_result(task: Task, result: dict) -> None:
                    if task.task_type == "host_discovery":
                        web_assets = result.get("web_asset_ids", [])
                        for asset_id in result.get("assets", []):
                            is_web = asset_id in web_assets
                            orchestrator.on_host_discovered(asset_id, is_web=is_web)
                    elif task.task_type == "web_crawl_endpoint_discovery":
                        for disc in result.get("discovered_binaries", []):
                            bp = disc.get("path", "")
                            if bp:
                                orchestrator.on_binary_discovered(bp, source_task=task)

                orchestrator.run_loop(worker_fn=dispatch_worker, on_result=handle_result)

                # Verification
                verifier = VerificationService(conn=t_conn, run_id=run_id)
                cand_rows = t_conn.execute("SELECT finding_id FROM findings WHERE status = ?", (FindingStatus.CANDIDATE.value,)).fetchall()
                fids = [r[0] for r in cand_rows]
                verifier.queue(fids)
                verifier.verify_all_queued()

                # Derive relationships for attack graph
                derive_run_relationships(t_conn, run_id)

                # Generate PTES report
                gen = ReportGenerator(conn=t_conn)
                gen.generate(run_id)
                t_conn.close()

            bg_thread = threading.Thread(target=_run_worker, daemon=True)
            bg_thread.start()

            conn.close()
            self._send_json({"success": True, "run_id": run_id, "target": target, "seed_url": seed_url})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)
'''

doget_pattern = r'def do_GET\(self\) -> None:'
if 'def do_POST' not in text and 'def do_GET' in text:
    text = text.replace('def do_GET(self) -> None:', dopost_code + '\n    def do_GET(self) -> None:', 1)

# 6. Update _handle_graph in DashboardHandler
handle_graph_code = '''    def _handle_graph(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        derive_run_relationships(conn)
        builder = AttackPathBuilder(conn, "current")
        paths = builder.build()

        asset_rows = conn.execute("SELECT asset_id, asset_type, canonical_key FROM assets").fetchall()
        asset_map = {r[0]: {"type": r[1], "key": r[2]} for r in asset_rows}

        f_query = """
            SELECT f.asset_id, f.finding_id, f.finding_type, f.severity, f.status, f.summary, e.evidence_id, e.excerpt
            FROM findings f
            LEFT JOIN evidence e ON f.finding_id = e.finding_id
            WHERE f.status = 'confirmed' AND f.severity != 'info'
        """
        f_rows = conn.execute(f_query).fetchall()
        advisor = RemediationAdvisor(conn)

        findings_by_asset: dict[str, list[dict[str, Any]]] = {}
        for r in f_rows:
            aid, fid, ftype, sev, st, summ, ev_id, excerpt = r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7] or ""
            try:
                adv = advisor.advise(fid)
            except Exception:
                adv = {}

            item = {
                "finding_id": fid,
                "type": ftype,
                "title": adv.get("title", ftype.replace("_", " ").title()),
                "severity": sev.upper(),
                "status": st.upper(),
                "summary": summ,
                "cwe": adv.get("cwe_id", "CWE-699"),
                "cvss": adv.get("cvss_score", "7.5"),
                "excerpt": excerpt,
                "remediation": adv.get("recommended_fix", ""),
                "patch": adv.get("patch_example", ""),
            }
            findings_by_asset.setdefault(aid, []).append(item)

        nodes_dict: dict[str, Any] = {}
        edges_set: set[tuple[str, str, str]] = set()
        edges_list: list[dict[str, Any]] = []

        def get_node_meta(aid: str) -> dict[str, Any]:
            info = asset_map.get(aid, {"type": "host", "key": aid})
            atype = info["type"]
            key = info["key"]
            flist = findings_by_asset.get(aid, [])
            sevs = [f["severity"].upper() for f in flist]
            if "CRITICAL" in sevs:
                max_sev = "CRITICAL"
            elif "HIGH" in sevs:
                max_sev = "HIGH"
            elif "MEDIUM" in sevs:
                max_sev = "MEDIUM"
            elif "LOW" in sevs:
                max_sev = "LOW"
            else:
                max_sev = "INFO"

            if atype == "binary":
                bname = Path(key).name
                if "keykeeper" in bname.lower():
                    label = "keykeeper (Reversed Binary)"
                    stage = "reversing"
                elif "vuln_auth" in bname.lower():
                    label = "vuln_auth_daemon (ELF Daemon)"
                    stage = "exploitation"
                else:
                    label = f"{bname} (Binary)"
                    stage = "binary"
            elif atype == "web_app":
                label = f"Mitigata Hidden Wiki ({key})"
                stage = "access_bypass"
            else:
                label = f"Target Host ({key})"
                stage = "target"

            return {
                "id": aid,
                "label": label,
                "canonical_key": key,
                "asset_type": atype,
                "stage": stage,
                "severity": max_sev,
                "findings": flist,
                "findings_count": len(flist),
            }

        for p in paths:
            for e in p.edges:
                if e.source_id not in nodes_dict:
                    nodes_dict[e.source_id] = get_node_meta(e.source_id)
                if e.target_id not in nodes_dict:
                    nodes_dict[e.target_id] = get_node_meta(e.target_id)

                edge_key = (e.source_id, e.target_id, e.relationship_type)
                if edge_key not in edges_set:
                    edges_set.add(edge_key)
                    tech_label = {
                        "REVERSE_PROXY_IP_SPOOFING": "Reverse Proxy IP Spoofing (XFF Bypass)",
                        "ARTIFACT_VAULT_DOWNLOAD": "Artifact Exfiltration (/vault/)",
                        "REVERSED_AUTH_PASSKEY": "Binary Reverse Engineering (XOR Decrypt)",
                        "BINARY_DAEMON_PROBE": "Static Binary Daemon Audit",
                        "WEB_SERVICE_EXPOSURE": "Web Service Exposure",
                        "FLAG_DISCLOSURE_PIDREQ": "Arbitrary File Read Exploit",
                    }.get(e.relationship_type, e.relationship_type.replace("_", " ").title())

                    edges_list.append({
                        "source": e.source_id,
                        "target": e.target_id,
                        "label": tech_label,
                        "relationship_type": e.relationship_type,
                        "confidence": e.confidence_label,
                        "evidence_id": e.evidence_id,
                    })

        if not nodes_dict:
            for aid in findings_by_asset:
                nodes_dict[aid] = get_node_meta(aid)

        conn.close()
        self._send_json({
            "nodes": list(nodes_dict.values()),
            "edges": edges_list,
        })
'''

old_handle_graph = r'def _handle_graph\(self\) -> None:[\s\S]*?self\._send_json\(\{\s*"nodes": list\(nodes_dict\.values\(\)\),\s*"edges": edges_list,\s*\}\)'
m_hg = re.search(old_handle_graph, text)
if m_hg:
    text = text[:m_hg.start()] + handle_graph_code + text[m_hg.end():]

with open('src/cart/ui.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Successfully updated ui.py!')
