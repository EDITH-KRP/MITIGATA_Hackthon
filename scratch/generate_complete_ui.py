import re

ui_template = '''"""Local findings & reporting UI (spec section 5.10, FR-8).

Provides:
1. Executive dashboard with live multi-agent coordination strip.
2. Filtered security vulnerability table (CRITICAL, HIGH, MEDIUM, LOW).
3. Planted CTF flags trophy case with 1-click copy.
4. Beautiful in-browser Markdown renderer for the PTES assessment report.
5. Publication-grade PDF download & printable report export (/report/printable).
"""

from __future__ import annotations

import html
import http.server
import json
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any

from .advisor import RemediationAdvisor
from .attackpath import AttackPathBuilder
from .preflight import list_candidate_networks
from .report import ReportGenerator
from .store import connect


def markdown_to_printable_html(md: str) -> str:
    """Convert PTES Markdown into clean, semantic HTML with executive print styling."""
    lines = md.splitlines()
    html_out = []
    in_code_block = False
    code_block_lang = ""
    code_block_lines = []
    in_table = False
    table_lines = []

    def flush_table():
        nonlocal in_table, table_lines
        if not table_lines:
            in_table = False
            return
        out = ["<div class=\'table-wrapper\'><table class=\'report-table\'>"]
        header_cols = [c.strip() for c in table_lines[0].strip(\'|\').split(\'|\')]
        out.append("<thead><tr>")
        for col in header_cols:
            out.append(f"<th>{inline_format(col)}</th>")
        out.append("</tr></thead><tbody>")

        for row in table_lines[2:]:
            cols = [c.strip() for c in row.strip(\'|\').split(\'|\')]
            out.append("<tr>")
            for col in cols:
                out.append(f"<td>{inline_format(col)}</td>")
            out.append("</tr>")
        out.append("</tbody></table></div>")
        table_lines = []
        in_table = False
        html_out.append("\\n".join(out))

    def inline_format(text: str) -> str:
        text = re.sub(r\'\\*\\*(.+?)\\*\\*\', r\'<strong>\\1</strong>\', text)
        text = re.sub(r\'\\*(.+?)\\*\', r\'<em>\\1</em>\', text)
        text = re.sub(r\'`([^`]+)`\', r\'<code>\\1</code>\', text)
        text = re.sub(r\'\\[([^\\]]+)\\]\\(([^)]+)\\)\', r\'<a href="\\2" target="_blank">\\1</a>\', text)
        text = text.replace("🔴 CRITICAL", "<span class=\'badge badge-crit\'>CRITICAL</span>")
        text = text.replace("🟠 HIGH", "<span class=\'badge badge-high\'>HIGH</span>")
        text = text.replace("🟡 MEDIUM", "<span class=\'badge badge-med\'>MEDIUM</span>")
        text = text.replace("🔵 LOW", "<span class=\'badge badge-low\'>LOW</span>")
        text = text.replace("⚪ INFO", "<span class=\'badge badge-info\'>INFO</span>")
        text = text.replace("✅ PASS", "<span class=\'badge badge-pass\'>PASS</span>")
        return text

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_code_block:
                code_text = html.escape("\\n".join(code_block_lines))
                html_out.append(f"<pre class=\'code-box\'><code class=\'lang-{code_block_lang}\'>{code_text}</code></pre>")
                in_code_block = False
                code_block_lines = []
            else:
                if in_table:
                    flush_table()
                in_code_block = True
                code_block_lang = stripped[3:].strip()
                code_block_lines = []
            continue

        if in_code_block:
            code_block_lines.append(line)
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_lines = [stripped]
            else:
                table_lines.append(stripped)
            continue
        elif in_table:
            flush_table()

        if not stripped:
            continue

        if stripped.startswith("#### "):
            html_out.append(f"<h4>{inline_format(stripped[5:])}</h4>")
        elif stripped.startswith("### "):
            html_out.append(f"<h3>{inline_format(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            html_out.append(f"<h2>{inline_format(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            html_out.append(f"<h1>{inline_format(stripped[2:])}</h1>")
        elif stripped.startswith("> "):
            html_out.append(f"<blockquote class=\'callout\'>{inline_format(stripped[2:])}</blockquote>")
        elif stripped == "---":
            html_out.append("<hr class=\'section-divider\'/>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            html_out.append(f"<li class=\'bullet-item\'>{inline_format(stripped[2:])}</li>")
        else:
            html_out.append(f"<p>{inline_format(stripped)}</p>")

    if in_table:
        flush_table()

    return "\\n".join(html_out)


_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberForge CART — Autonomous VAPT Assessment Engine</title>
<style>
:root {
  --bg: #080c14;
  --panel: #0f172a;
  --panel-border: #1e293b;
  --text: #f1f5f9;
  --text-muted: #94a3b8;
  --accent: #06b6d4;
  --accent-glow: rgba(6, 182, 212, 0.25);
  --gold: #f59e0b;
  --gold-glow: rgba(245, 158, 11, 0.25);
  --green: #10b981;
  --red: #ef4444;
  --orange: #f97316;
  --purple: #8b5cf6;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
body { background: var(--bg); color: var(--text); padding: 1.5rem; line-height: 1.5; }
header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--panel-border); padding-bottom: 1rem; margin-bottom: 1.2rem; }
.logo { font-size: 1.35rem; font-weight: 800; letter-spacing: 0.5px; color: #fff; display: flex; align-items: center; gap: 0.6rem; }
.logo span { color: var(--accent); }
.badge { font-size: 0.72rem; padding: 0.2rem 0.6rem; border-radius: 9999px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
.badge-running { background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }
.badge-partial { background: rgba(245, 158, 11, 0.2); color: var(--gold); border: 1px solid var(--gold); }
.badge-completed { background: rgba(6, 182, 212, 0.2); color: var(--accent); border: 1px solid var(--accent); }
.badge-idle { background: rgba(148, 163, 184, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }

.grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 1rem; margin-bottom: 1.2rem; }
.col-3 { grid-column: span 3; }
.col-4 { grid-column: span 4; }
.col-6 { grid-column: span 6; }
.col-8 { grid-column: span 8; }
.col-12 { grid-column: span 12; }

.card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 10px; padding: 1.1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.25); }
.card-header { font-size: 0.82rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.8rem; display: flex; justify-content: space-between; align-items: center; }
.metric-val { font-size: 1.85rem; font-weight: 800; color: #fff; margin-bottom: 0.2rem; }
.metric-sub { font-size: 0.75rem; color: var(--text-muted); }

/* Trophy Case */
.trophy-case { background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(15, 23, 42, 0.95) 100%); border: 1px solid var(--gold); box-shadow: 0 0 20px var(--gold-glow); border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: 1.2rem; }
.flag-chip { display: inline-flex; align-items: center; gap: 0.6rem; background: rgba(245, 158, 11, 0.18); border: 1px solid var(--gold); color: #fff; padding: 0.35rem 0.85rem; border-radius: 6px; font-family: Consolas, monospace; font-size: 0.88rem; font-weight: 700; margin: 0.3rem 0.4rem 0.3rem 0; }
.flag-meta { font-size: 0.68rem; font-weight: 400; color: #fde68a; font-family: system-ui, sans-serif; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.btn-copy { background: var(--gold); color: #000; border: none; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.72rem; font-weight: bold; cursor: pointer; transition: opacity 0.2s; }
.btn-copy:hover { opacity: 0.85; }

/* Multi-Agent Strip */
.agent-strip { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin-bottom: 1.2rem; }
.agent-card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 8px; padding: 0.85rem; display: flex; flex-direction: column; gap: 0.35rem; }
.agent-name { font-size: 0.82rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.4rem; }
.agent-role { font-size: 0.7rem; color: var(--text-muted); }
.agent-stat { font-size: 0.76rem; font-weight: 600; color: var(--accent); }

table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
th, td { text-align: left; padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--panel-border); }
th { color: var(--text-muted); font-size: 0.73rem; text-transform: uppercase; letter-spacing: 0.5px; background: rgba(15, 23, 42, 0.6); }
tr:hover td { background: rgba(255, 255, 255, 0.02); }
tr:last-child td { border-bottom: none; }

/* Severity Badges */
.sev-pill { font-size: 0.7rem; font-weight: 800; padding: 0.18rem 0.55rem; border-radius: 4px; display: inline-block; text-transform: uppercase; letter-spacing: 0.5px; }
.sev-critical { background: rgba(239, 68, 68, 0.25); color: #fca5a5; border: 1px solid var(--red); }
.sev-high { background: rgba(249, 115, 22, 0.25); color: #fdba74; border: 1px solid var(--orange); }
.sev-medium { background: rgba(245, 158, 11, 0.25); color: #fde047; border: 1px solid var(--gold); }
.sev-low { background: rgba(6, 182, 212, 0.25); color: #a5f3fc; border: 1px solid var(--accent); }
.sev-info { background: rgba(148, 163, 184, 0.2); color: var(--text-muted); border: 1px solid var(--panel-border); }

.log-box { font-family: Consolas, monospace; font-size: 0.78rem; height: 260px; overflow-y: auto; background: #060912; padding: 0.75rem; border-radius: 6px; border: 1px solid #141c2e; }
.log-line { margin-bottom: 0.3rem; }
.log-deny { color: var(--red); }
.log-allow { color: var(--green); }
.log-meta { color: var(--text-muted); }

.graph-container { width: 100%; height: 320px; background: #060912; border: 1px solid #141c2e; border-radius: 8px; overflow: hidden; display: flex; align-items: center; justify-content: center; position: relative; }
svg { width: 100%; height: 100%; }

button { background: var(--accent); color: #000; border: none; padding: 0.45rem 0.9rem; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 0.82rem; transition: all 0.2s; }
button:hover { background: #22d3ee; box-shadow: 0 0 12px var(--accent-glow); }
button.btn-sec { background: transparent; border: 1px solid var(--panel-border); color: var(--text); }
button.btn-sec:hover { background: var(--panel-border); }
button.tab-btn { background: transparent; border: none; color: var(--text-muted); cursor: pointer; border-radius: 4px; }
button.tab-btn.active-tab { background: var(--panel-border); color: #fff; font-weight: 700; }

/* Rendered Markdown Styling */
.rendered-report-container { font-size: 0.86rem; line-height: 1.65; color: #e2e8f0; }
.rendered-report-container h1 { font-size: 1.4rem; color: #fff; border-bottom: 2px solid var(--accent); padding-bottom: 0.4rem; margin: 1.2rem 0 0.8rem 0; }
.rendered-report-container h2 { font-size: 1.15rem; color: var(--accent); border-bottom: 1px solid var(--panel-border); padding-bottom: 0.3rem; margin: 1.2rem 0 0.6rem 0; }
.rendered-report-container h3 { font-size: 1rem; color: #f8fafc; margin: 1rem 0 0.4rem 0; }
.rendered-report-container h4 { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin: 0.8rem 0 0.3rem 0; }
.rendered-report-container p { margin-bottom: 0.6rem; }
.rendered-report-container code { background: #060912; border: 1px solid #1e293b; border-radius: 4px; padding: 0.15rem 0.4rem; font-family: Consolas, monospace; font-size: 0.82rem; color: #38bdf8; }
.rendered-report-container pre.code-box { background: #060912; border: 1px solid #1e293b; border-radius: 6px; padding: 0.8rem; margin: 0.6rem 0; overflow-x: auto; font-family: Consolas, monospace; font-size: 0.8rem; color: #cbd5e1; }
.rendered-report-container blockquote.callout { background: rgba(6, 182, 212, 0.08); border-left: 3px solid var(--accent); padding: 0.6rem 0.9rem; margin: 0.6rem 0; color: #94a3b8; }
.rendered-report-container hr.section-divider { border: none; border-top: 1px solid var(--panel-border); margin: 1.2rem 0; }
.rendered-report-container ul, .rendered-report-container ol { margin-left: 1.4rem; margin-bottom: 0.6rem; }
.rendered-report-container li { margin-bottom: 0.25rem; }
.rendered-report-container table.report-table { width: 100%; border-collapse: collapse; margin: 0.8rem 0; font-size: 0.82rem; }
.rendered-report-container table.report-table th, .rendered-report-container table.report-table td { border: 1px solid var(--panel-border); padding: 0.45rem 0.65rem; }
.rendered-report-container table.report-table th { background: rgba(15, 23, 42, 0.8); color: var(--text-muted); }

pre.report-pre { white-space: pre-wrap; font-family: Consolas, monospace; font-size: 0.78rem; background: #060912; padding: 1rem; border-radius: 6px; max-height: 480px; overflow-y: auto; color: #cbd5e1; border: 1px solid #141c2e; }

/* Modal Drawer */
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); z-index: 100; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
.modal-content { background: var(--panel); border: 1px solid var(--accent); border-radius: 10px; width: 620px; max-width: 92%; max-height: 82vh; overflow-y: auto; padding: 1.5rem; box-shadow: 0 0 25px var(--accent-glow); }
</style>
</head>
<body>

<header>
  <div class="logo">
    ⚡ <span>CyberForge</span> CART
    <span id="run-badge" class="badge badge-idle">IDLE</span>
    <span style="font-size:0.75rem; color:var(--text-muted); font-weight:400; margin-left:0.5rem;">Autonomous VAPT Assessment Engine</span>
  </div>
  <div style="display:flex; gap:0.5rem; align-items:center;">
    <span id="run-timer" style="font-family:monospace; font-size:0.85rem; color:var(--text-muted);">00:00:00</span>
    <button onclick="openPrintableReport()" class="btn-sec" style="color:var(--accent); border-color:var(--accent); font-weight:700;">📄 Download PDF</button>
    <button onclick="downloadPatches()" class="btn-sec" style="color:var(--green); border-color:var(--green);">💾 Export Patches</button>
    <button onclick="refreshData()" class="btn-sec">↻ Refresh</button>
  </div>
</header>

<!-- Multi-Agent Live Coordination Strip -->
<div class="agent-strip" id="agents-strip">
  <div class="agent-card">
    <div class="agent-name">🌐 Network Specialist</div>
    <div class="agent-role">Host & Port Discovery</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">🕷️ Web Specialist</div>
    <div class="agent-role">Endpoints & Form Crawler</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">⚙️ Binary Specialist</div>
    <div class="agent-role">Static Analysis & Unsafe Libc</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">🛡️ Verification Service</div>
    <div class="agent-role">Deterministic Playbooks</div>
    <div class="agent-stat">0 Confirmed</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">💡 Remediation Advisor</div>
    <div class="agent-role">Plain-English Patches</div>
    <div class="agent-stat">0 Patches Ready</div>
  </div>
</div>

<!-- Planted CTF Flags Trophy Case -->
<div class="trophy-case" id="trophy-case" style="display:none;">
  <div style="font-size:0.85rem; font-weight:800; color:var(--gold); display:flex; align-items:center; gap:0.4rem; margin-bottom:0.5rem;">
    🚩 CAPTURED CTF PLANTED FLAGS (<span id="flag-count">0</span>)
  </div>
  <div id="flag-chips-list"></div>
</div>

<!-- Key Performance Indicators -->
<div class="grid">
  <div class="col-3 card">
    <div class="card-header">Scope Safety</div>
    <div class="metric-val" id="metric-safety" style="color:var(--green);">0 Leaks</div>
    <div class="metric-sub" id="metric-safety-sub">0 out-of-scope probes blocked</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Autonomy Post-Start</div>
    <div class="metric-val" id="metric-autonomy" style="color:var(--accent);">100%</div>
    <div class="metric-sub">0 human interventions required</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Verified Findings</div>
    <div class="metric-val" id="metric-findings">0 / 0</div>
    <div class="metric-sub" id="metric-findings-sub">0% verification rate</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Discovered Assets</div>
    <div class="metric-val" id="metric-assets">0</div>
    <div class="metric-sub" id="metric-assets-sub">0 open services identified</div>
  </div>
</div>

<!-- Main Views: Attack Graph + Scope Logs -->
<div class="grid">
  <div class="col-8 card">
    <div class="card-header">
      <span>Evidence-Backed Attack Graph</span>
      <span style="font-size:0.75rem; color:var(--text-muted);">Click any node to inspect details</span>
    </div>
    <div class="graph-container" id="graph-viewport">
      <svg id="attack-graph"></svg>
    </div>
  </div>

  <div class="col-4 card">
    <div class="card-header">Scope Gate Decisions</div>
    <div class="log-box" id="scope-logs">
      <div class="log-meta">Waiting for scope audit events...</div>
    </div>
  </div>
</div>

<!-- Security Vulnerabilities Table -->
<div class="grid">
  <div class="col-12 card">
    <div class="card-header">
      <span>Confirmed Weaknesses & Findings</span>
      <div style="display:flex; align-items:center; gap:0.5rem;">
        <label for="severity-filter" style="font-size:0.75rem; text-transform:none; color:var(--text-muted);">Filter:</label>
        <select id="severity-filter" onchange="refreshData()" style="background:#060912; color:var(--text); border:1px solid var(--panel-border); border-radius:4px; padding:0.2rem 0.5rem; font-size:0.75rem;">
          <option value="vulns" selected>Vulnerabilities Only (Low, Mid, High, Critical)</option>
          <option value="high">High & Critical Only</option>
          <option value="all">Include Informational (Forms)</option>
        </select>
      </div>
    </div>
    <div style="max-height: 380px; overflow-y: auto;">
      <table id="findings-table">
        <thead>
          <tr>
            <th>Target / Location</th>
            <th>Specialist Worker</th>
            <th>Vulnerability Type</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Live Evidence</th>
          </tr>
        </thead>
        <tbody>
          <tr><td colspan="6" style="color:var(--text-muted); text-align:center;">No findings reported yet</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Assets & Services -->
<div class="grid">
  <div class="col-6 card">
    <div class="card-header">Candidate Network Targets</div>
    <div style="max-height: 250px; overflow-y: auto;">
      <table id="candidates-table">
        <thead>
          <tr>
            <th>Interface / CIDR</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          <tr><td colspan="3" style="color:var(--text-muted); text-align:center;">No candidates detected</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="col-6 card">
    <div class="card-header">Asset & Service Inventory</div>
    <div style="max-height: 250px; overflow-y: auto;">
      <table id="inventory-table">
        <thead>
          <tr>
            <th>Target Key</th>
            <th>Classification</th>
            <th>Open Services</th>
          </tr>
        </thead>
        <tbody>
          <tr><td colspan="3" style="color:var(--text-muted); text-align:center;">No assets cataloged</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- PTES Executive Assessment Report Tab -->
<div class="grid">
  <div class="col-12 card">
    <div class="card-header">
      <div style="display:flex; align-items:center; gap:0.6rem;">
        <span>📑 Penetration Testing Execution Standard (PTES) Report</span>
        <div style="display:inline-flex; border:1px solid var(--panel-border); border-radius:4px; overflow:hidden;">
          <button id="btn-view-rendered" onclick="switchReportTab(\'rendered\')" class="tab-btn active-tab" style="padding:0.2rem 0.6rem; font-size:0.75rem;">👁️ Formatted View</button>
          <button id="btn-view-raw" onclick="switchReportTab(\'raw\')" class="tab-btn" style="padding:0.2rem 0.6rem; font-size:0.75rem;">📝 Raw Markdown</button>
        </div>
      </div>
      <div style="display:flex; gap:0.5rem; align-items:center;">
        <button onclick="openPrintableReport()" class="btn-sec" style="color:var(--accent); border-color:var(--accent); font-size:0.75rem; padding:0.25rem 0.6rem; font-weight:700;">📄 Download / Print as PDF</button>
        <button onclick="downloadReport()" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.6rem;">📥 Download Markdown</button>
      </div>
    </div>
    <div id="rendered-report" class="rendered-report-container" style="max-height: 520px; overflow-y: auto; padding: 1.2rem; background: #060912; border-radius: 6px; border: 1px solid #141c2e;"></div>
    <pre class="report-pre" id="report-text" style="display:none; max-height: 520px; overflow-y: auto;">No report generated yet.</pre>
  </div>
</div>

<!-- Node Inspection Modal -->
<div class="modal-overlay" id="node-modal" onclick="closeModal(event)">
  <div class="modal-content" onclick="event.stopPropagation()">
    <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--panel-border); padding-bottom:0.5rem; margin-bottom:1rem;">
      <h3 id="modal-title" style="color:var(--accent);">Evidence Details</h3>
      <button onclick="document.getElementById(\'node-modal\').style.display=\'none\'" class="btn-sec" style="padding:0.2rem 0.5rem;">✕</button>
    </div>
    <div id="modal-body" style="font-size:0.85rem; line-height:1.6;"></div>
  </div>
</div>

<script>
let lastReportContent = "";

function openPrintableReport() {
  window.open(\'/report/printable\', \'_blank\');
}

function switchReportTab(tab) {
  const renderedEl = document.getElementById(\'rendered-report\');
  const rawEl = document.getElementById(\'report-text\');
  const btnRendered = document.getElementById(\'btn-view-rendered\');
  const btnRaw = document.getElementById(\'btn-view-raw\');
  if (tab === \'rendered\') {
    renderedEl.style.display = \'block\';
    rawEl.style.display = \'none\';
    btnRendered.classList.add(\'active-tab\');
    btnRaw.classList.remove(\'active-tab\');
  } else {
    renderedEl.style.display = \'none\';
    rawEl.style.display = \'block\';
    btnRendered.classList.remove(\'active-tab\');
    btnRaw.classList.add(\'active-tab\');
  }
}

// Client-side markdown renderer for the report view
function formatMarkdown(md) {
  if (!md) return \'<p style="color:var(--text-muted);">No report generated yet.</p>\';
  const lines = md.split(\'\\n\');
  let out = [];
  let inCode = false;
  let codeLines = [];
  let inTable = false;
  let tableLines = [];

  function flushTbl() {
    if (!tableLines.length) { inTable = false; return; }
    out.push(\'<table class="report-table"><thead><tr>\');
    const headers = tableLines[0].split(\'|\').filter((c, i, a) => i > 0 && i < a.length - 1);
    headers.forEach(h => out.push(`<th>${inlineFmt(h.trim())}</th>`));
    out.push(\'</tr></thead><tbody>\');
    for (let r = 2; r < tableLines.length; r++) {
      out.push(\'<tr>\');
      const cols = tableLines[r].split(\'|\').filter((c, i, a) => i > 0 && i < a.length - 1);
      cols.forEach(c => out.push(`<td>${inlineFmt(c.trim())}</td>`));
      out.push(\'</tr>\');
    }
    out.push(\'</tbody></table>\');
    tableLines = [];
    inTable = false;
  }

  function inlineFmt(s) {
    s = s.replace(/\\*\\*(.+?)\\*\\*/g, \'<strong>$1</strong>\');
    s = s.replace(/`([^`]+)`/g, \'<code>$1</code>\');
    s = s.replace(/🔴 CRITICAL/g, \'<span class="sev-pill sev-critical">CRITICAL</span>\');
    s = s.replace(/🟠 HIGH/g, \'<span class="sev-pill sev-high">HIGH</span>\');
    s = s.replace(/🟡 MEDIUM/g, \'<span class="sev-pill sev-medium">MEDIUM</span>\');
    s = s.replace(/🔵 LOW/g, \'<span class="sev-pill sev-low">LOW</span>\');
    s = s.replace(/✅ PASS/g, \'<span style="color:var(--green); font-weight:700;">✅ PASS</span>\');
    return s;
  }

  for (let line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith(\'```\')) {
      if (inCode) {
        out.push(`<pre class="code-box"><code>${codeLines.join(\'\\n\')}</code></pre>`);
        inCode = false;
        codeLines = [];
      } else {
        if (inTable) flushTbl();
        inCode = true;
        codeLines = [];
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line.replace(/&/g, \'&amp;\').replace(/</g, \'&lt;\').replace(/>/g, \'&gt;\'));
      continue;
    }
    if (trimmed.startsWith(\'|\') && trimmed.endsWith(\'|\')) {
      if (!inTable) { inTable = true; tableLines = [trimmed]; }
      else tableLines.push(trimmed);
      continue;
    } else if (inTable) {
      flushTbl();
    }
    if (!trimmed) continue;
    if (trimmed.startsWith(\'#### \')) out.push(`<h4>${inlineFmt(trimmed.slice(5))}</h4>`);
    else if (trimmed.startsWith(\'### \')) out.push(`<h3>${inlineFmt(trimmed.slice(4))}</h3>`);
    else if (trimmed.startsWith(\'## \')) out.push(`<h2>${inlineFmt(trimmed.slice(3))}</h2>`);
    else if (trimmed.startsWith(\'# \')) out.push(`<h1>${inlineFmt(trimmed.slice(2))}</h1>`);
    else if (trimmed.startsWith(\'> \')) out.push(`<blockquote class="callout">${inlineFmt(trimmed.slice(2))}</blockquote>`);
    else if (trimmed === \'---\') out.push(\'<hr class="section-divider"/>\');
    else if (trimmed.startsWith(\'- \') || trimmed.startsWith(\'* \')) out.push(`<li>${inlineFmt(trimmed.slice(2))}</li>`);
    else out.push(`<p>${inlineFmt(trimmed)}</p>`);
  }
  if (inTable) flushTbl();
  return out.join(\'\\n\');
}

async function refreshData() {
  try {
    const res = await fetch(\'/api/status\');
    const data = await res.json();
    renderStatus(data);
    
    const logsRes = await fetch(\'/api/logs\');
    const logsData = await logsRes.json();
    renderLogs(logsData);

    const invRes = await fetch(\'/api/inventory\');
    const invData = await invRes.json();
    renderInventory(invData);

    const filterVal = document.getElementById(\'severity-filter\') ? document.getElementById(\'severity-filter\').value : \'vulns\';
    const includeInfo = filterVal === \'all\';
    const fRes = await fetch(\'/api/findings\' + (includeInfo ? \'?include_info=true\' : \'\'));
    const fData = await fRes.json();
    
    // Filter out client-side if high only
    let filteredFindings = fData;
    if (filterVal === \'high\') {
      filteredFindings = fData.filter(f => [\'high\', \'critical\'].includes(f.severity.toLowerCase()));
    }
    renderFindings(filteredFindings);

    const gRes = await fetch(\'/api/graph\');
    const gData = await gRes.json();
    renderGraph(gData);

    const flagsRes = await fetch(\'/api/flags\');
    const flagsData = await flagsRes.json();
    renderFlags(flagsData);

    const agentsRes = await fetch(\'/api/agents\');
    const agentsData = await agentsRes.json();
    renderAgents(agentsData);

    const repRes = await fetch(\'/api/report\');
    const repData = await repRes.json();
    if (repData.report) {
      document.getElementById(\'report-text\').textContent = repData.report;
      document.getElementById(\'rendered-report\').innerHTML = formatMarkdown(repData.report);
      lastReportContent = repData.report;
    }
  } catch (err) {
    console.error(\'Fetch error:\', err);
  }
}

function renderStatus(data) {
  const badge = document.getElementById(\'run-badge\');
  badge.textContent = data.status.toUpperCase();
  badge.className = \'badge \' + (
    data.status === \'running\' ? \'badge-running\' :
    data.status === \'partial\' ? \'badge-partial\' :
    data.status === \'completed\' ? \'badge-completed\' : \'badge-idle\'
  );

  document.getElementById(\'metric-safety\').textContent = `${data.metrics.scope_safety_out_of_bounds_probes} Leaks`;
  document.getElementById(\'metric-safety-sub\').textContent = `${data.metrics.scope_decisions_denied} out-of-scope probes blocked`;
  document.getElementById(\'metric-findings\').textContent = `${data.metrics.confirmed_findings} / ${data.metrics.total_findings}`;
  document.getElementById(\'metric-findings-sub\').textContent = `${data.metrics.verification_rate_pct}% verification rate`;
  document.getElementById(\'metric-assets\').textContent = data.metrics.total_assets_discovered;
  document.getElementById(\'metric-assets-sub\').textContent = `${data.metrics.total_services_discovered} open services identified`;
}

function renderAgents(agents) {
  const container = document.getElementById(\'agents-strip\');
  container.innerHTML = \'\';
  agents.forEach(a => {
    const card = document.createElement(\'div\');
    card.className = \'agent-card\';
    const statText = a.role.includes(\'Playbooks\') 
      ? `${a.completed} Confirmed`
      : a.role.includes(\'Patches\')
      ? `${a.completed} Patches Ready`
      : `${a.active} Active / ${a.completed} Done`;

    card.innerHTML = `
      <div class="agent-name">${a.icon} ${a.name}</div>
      <div class="agent-role">${a.role}</div>
      <div class="agent-stat">${statText}</div>
    `;
    container.appendChild(card);
  });
}

function renderFlags(flags) {
  const trophy = document.getElementById(\'trophy-case\');
  const countEl = document.getElementById(\'flag-count\');
  const listEl = document.getElementById(\'flag-chips-list\');

  if (!flags || !flags.length) {
    trophy.style.display = \'none\';
    return;
  }

  trophy.style.display = \'block\';
  countEl.textContent = flags.length;
  listEl.innerHTML = \'\';

  flags.forEach(f => {
    let flagVal = f.excerpt || f.summary;
    try {
      const parsed = JSON.parse(flagVal);
      if (Array.isArray(parsed) && parsed.length) flagVal = parsed[0];
    } catch (e) {}

    const chip = document.createElement(\'div\');
    chip.className = \'flag-chip\';
    chip.innerHTML = `
      <span>🚩</span>
      <span style="user-select:all;">${flagVal}</span>
      <span class="flag-meta" title="${f.location || f.asset_key}">📍 ${f.location || f.asset_key}</span>
      <button class="btn-copy" onclick="copyFlag(\'${flagVal.replace(/\'/g, "\\\\\'")}\', this)">COPY</button>
    `;
    listEl.appendChild(chip);
  });
}

function copyFlag(val, btn) {
  navigator.clipboard.writeText(val).then(() => {
    const orig = btn.textContent;
    btn.textContent = \'COPIED!\';
    btn.style.background = \'#10b981\';
    setTimeout(() => {
      btn.textContent = orig;
      btn.style.background = \'var(--gold)\';
    }, 1500);
  });
}

function renderLogs(logs) {
  const box = document.getElementById(\'scope-logs\');
  box.innerHTML = \'\';
  logs.forEach(l => {
    const line = document.createElement(\'div\');
    line.className = \'log-line\';
    const isDeny = l.decision.toLowerCase() === \'deny\';
    line.innerHTML = `
      <span class="${isDeny ? \'log-deny\' : \'log-allow\'}">[${l.decision.toUpperCase()}]</span>
      <span style="color:#fff;">${l.target}</span>
      <span class="log-meta">(${l.reason || \'in-scope\'})</span>
    `;
    box.appendChild(line);
  });
}

function renderInventory(inv) {
  const tbody = document.querySelector(\'#inventory-table tbody\');
  tbody.innerHTML = \'\';
  if (!inv || !inv.length) {
    tbody.innerHTML = \'<tr><td colspan="3" style="color:var(--text-muted); text-align:center;">No assets cataloged</td></tr>\';
    return;
  }
  inv.forEach(a => {
    const tr = document.createElement(\'tr\');
    const svcs = a.services.map(s => `${s.port}/${s.protocol} (${s.service_name || \'unknown\'})`).join(\', \') || \'None\';
    tr.innerHTML = `
      <td style="font-weight:700; color:#fff;">${a.canonical_key}</td>
      <td><span class="badge" style="background:#1e293b; color:var(--text);">${a.asset_type.toUpperCase()}</span></td>
      <td><span style="color:var(--accent); font-family:monospace;">${svcs}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderFindings(findings) {
  const tbody = document.querySelector(\'#findings-table tbody\');
  tbody.innerHTML = \'\';
  if (!findings || !findings.length) {
    tbody.innerHTML = \'<tr><td colspan="6" style="color:var(--text-muted); text-align:center;">No vulnerabilities matching filter</td></tr>\';
    return;
  }
  findings.forEach(f => {
    const tr = document.createElement(\'tr\');
    const sev = f.severity.toLowerCase();
    const pillClass = `sev-${sev}`;
    
    // Display specialist tool neatly
    let toolBadge = f.tool || \'automated\';
    if (toolBadge.includes(\'nmap\')) toolBadge = \'🌐 Nmap Specialist\';
    else if (toolBadge.includes(\'binary\')) toolBadge = \'⚙️ Binary Specialist\';
    else if (toolBadge.includes(\'web\')) toolBadge = \'🕷️ Web Specialist\';
    else if (toolBadge.includes(\'gamezone\')) toolBadge = \'🎮 GameZone Probe\';

    tr.innerHTML = `
      <td style="font-family:monospace; color:#38bdf8; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${f.target_url || \'N/A\'}">${f.target_url || \'N/A\'}</td>
      <td style="font-size:0.75rem; color:var(--text-muted);">${toolBadge}</td>
      <td style="font-weight:600; color:#fff;">${f.type.replace(/_/g, \' \')}</td>
      <td><span class="sev-pill ${pillClass}">${f.severity}</span></td>
      <td><span style="color:var(--green); font-weight:700;">${f.status}</span></td>
      <td>
        <button onclick="inspectFinding(\'${f.finding_id}\')" class="btn-sec" style="font-size:0.75rem; padding:0.2rem 0.6rem;">🔍 Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function inspectFinding(fid) {
  try {
    const res = await fetch(\'/api/findings?include_info=true\');
    const data = await res.json();
    const f = data.find(x => x.finding_id === fid);
    if (!f) return alert(\'Finding not found\');

    document.getElementById(\'modal-title\').textContent = `Finding: ${f.type.replace(/_/g, \' \').toUpperCase()}`;
    document.getElementById(\'modal-body\').innerHTML = `
      <div style="margin-bottom:0.8rem;">
        <span class="sev-pill sev-${f.severity.toLowerCase()}">${f.severity.toUpperCase()}</span>
        <span style="color:var(--green); font-weight:700; margin-left:0.5rem;">[${f.status.toUpperCase()}]</span>
        <span style="color:var(--text-muted); font-size:0.75rem; margin-left:0.5rem;">Tool: ${f.tool}</span>
      </div>
      <p style="margin-bottom:0.8rem; color:#fff;">${f.summary}</p>
      <div style="background:#060912; border:1px solid #141c2e; border-radius:6px; padding:0.8rem; margin-bottom:0.8rem;">
        <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:0.4rem; text-transform:uppercase;">Technical Proof of Concept / Evidence</div>
        <pre style="white-space:pre-wrap; font-family:Consolas, monospace; font-size:0.8rem; color:#38bdf8;">${f.excerpt || \'No raw excerpt recorded\'}</pre>
      </div>
      <div style="font-size:0.75rem; color:var(--text-muted);">
        <div><strong>Evidence SHA-256 Digest:</strong> <code>${f.hash || \'N/A\'}</code></div>
        <div><strong>Target Location:</strong> <code>${f.target_url || \'N/A\'}</code></div>
      </div>
    `;
    document.getElementById(\'node-modal\').style.display = \'flex\';
  } catch (err) {
    alert(\'Error inspecting finding: \' + err);
  }
}

function renderGraph(graph) {
  const svg = document.getElementById(\'attack-graph\');
  svg.innerHTML = \'\';
  if (!graph.nodes || !graph.nodes.length) {
    svg.innerHTML = \'<text x="50%" y="50%" fill="#94a3b8" text-anchor="middle" font-size="14">No attack paths generated yet</text>\';
    return;
  }
  const width = svg.clientWidth || 600;
  const height = svg.clientHeight || 320;
  const cx = width / 2;
  const cy = height / 2;
  const r = Math.min(width, height) * 0.35;

  const total = graph.nodes.length;
  const positions = {};
  graph.nodes.forEach((n, i) => {
    const angle = (i / total) * 2 * Math.PI - Math.PI / 2;
    positions[n.id] = {
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
      node: n
    };
  });

  graph.edges.forEach(e => {
    const p1 = positions[e.source];
    const p2 = positions[e.target];
    if (p1 && p2) {
      const line = document.createElementNS(\'http://www.w3.org/2000/svg\', \'line\');
      line.setAttribute(\'x1\', p1.x);
      line.setAttribute(\'y1\', p1.y);
      line.setAttribute(\'x2\', p2.x);
      line.setAttribute(\'y2\', p2.y);
      line.setAttribute(\'stroke\', \'#ef4444\');
      line.setAttribute(\'stroke-width\', \'2\');
      line.setAttribute(\'stroke-dasharray\', \'4,4\');
      svg.appendChild(line);
    }
  });

  Object.values(positions).forEach(p => {
    const g = document.createElementNS(\'http://www.w3.org/2000/svg\', \'g\');
    g.style.cursor = \'pointer\';
    g.onclick = () => showNodeDetails(p.node);

    const circle = document.createElementNS(\'http://www.w3.org/2000/svg\', \'circle\');
    circle.setAttribute(\'cx\', p.x);
    circle.setAttribute(\'cy\', p.y);
    circle.setAttribute(\'r\', \'16\');
    circle.setAttribute(\'fill\', p.node.type === \'compromised\' ? \'#ef4444\' : \'#06b6d4\');
    circle.setAttribute(\'stroke\', \'#fff\');
    circle.setAttribute(\'stroke-width\', \'2\');

    const label = document.createElementNS(\'http://www.w3.org/2000/svg\', \'text\');
    label.setAttribute(\'x\', p.x);
    label.setAttribute(\'y\', p.y + 28);
    label.setAttribute(\'fill\', \'#f1f5f9\');
    label.setAttribute(\'text-anchor\', \'middle\');
    label.setAttribute(\'font-size\', \'11\');
    label.setAttribute(\'font-weight\', \'bold\');
    label.textContent = p.node.label;

    g.appendChild(circle);
    g.appendChild(label);
    svg.appendChild(g);
  });
}

function showNodeDetails(node) {
  document.getElementById(\'modal-title\').textContent = `Host Target: ${node.label}`;
  document.getElementById(\'modal-body\').innerHTML = `
    <p><strong>Asset Identifier:</strong> <code>${node.id}</code></p>
    <p><strong>Node State:</strong> <span style="color:var(--accent); font-weight:700;">${node.type.toUpperCase()}</span></p>
    <p style="margin-top:0.8rem; color:var(--text-muted);">Validated in-scope host target participating in the active assessment path.</p>
  `;
  document.getElementById(\'node-modal\').style.display = \'flex\';
}

function closeModal(event) {
  document.getElementById(\'node-modal\').style.display = \'none\';
}

function downloadReport() {
  if (!lastReportContent) return alert(\'No report available to download.\');
  const blob = new Blob([lastReportContent], { type: \'text/markdown\' });
  const a = document.createElement(\'a\');
  a.href = URL.createObjectURL(blob);
  a.download = \'cart_ptes_assessment_report.md\';
  a.click();
}

async function downloadPatches() {
  try {
    const res = await fetch(\'/api/patches\');
    const data = await res.json();
    if (!data.patches || !data.patches.length) {
      alert(\'No confirmed vulnerabilities require code patches yet.\');
      return;
    }
    alert(`Successfully generated ${data.patches.length} patch file(s) in reports/patches/!`);
  } catch (err) {
    alert(\'Error generating patches: \' + err);
  }
}

// Auto-refresh timer
refreshData();
setInterval(refreshData, 3000);
</script>

</body>
</html>
"""


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """Local HTTP API + Dashboard server."""

    db_path: str = "cart.db"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._send_html(_INDEX_HTML)
        elif path == "/api/status":
            self._handle_status()
        elif path == "/api/candidates":
            self._handle_candidates()
        elif path == "/api/inventory":
            self._handle_inventory()
        elif path == "/api/findings":
            self._handle_findings(parsed.query)
        elif path == "/api/graph":
            self._handle_graph()
        elif path == "/api/flags":
            self._handle_flags()
        elif path == "/api/agents":
            self._handle_agents()
        elif path == "/api/asset":
            self._handle_asset_detail(parsed.query)
        elif path == "/api/patches":
            self._handle_patches()
        elif path == "/api/logs":
            self._handle_logs()
        elif path == "/api/report":
            self._handle_report()
        elif path in ("/report/printable", "/api/report/printable", "/report/pdf"):
            self._handle_printable_report()
        else:
            self._send_json({"error": "not found"}, status=404)

    def _send_html(self, content: str) -> None:
        raw = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle_printable_report(self) -> None:
        """Render publication-grade printable PTES report for PDF export."""
        conn = connect(self.db_path, check_same_thread=False)
        rep_row = conn.execute(
            "SELECT path FROM report_artifacts WHERE format = 'md' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

        md_text = ""
        if rep_row and Path(rep_row[0]).exists():
            md_text = Path(rep_row[0]).read_text(encoding="utf-8")
        conn.close()

        html_body = markdown_to_printable_html(md_text)

        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberForge CART — PTES Penetration Testing Executive Report</title>
<style>
  :root {{
    --primary: #0284c7;
    --dark: #0f172a;
    --muted: #64748b;
    --border: #cbd5e1;
    --bg-code: #f8fafc;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: var(--dark);
    line-height: 1.6;
    padding: 2.5rem 3rem;
    max-width: 960px;
    margin: 0 auto;
    background: #fff;
  }}
  
  /* Top floating navigation bar */
  .floating-bar {{
    position: sticky;
    top: 1rem;
    background: #0f172a;
    color: #fff;
    padding: 0.75rem 1.25rem;
    border-radius: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 15px rgba(0,0,0,0.25);
    margin-bottom: 2rem;
    z-index: 1000;
  }}
  .floating-bar button {{
    background: #06b6d4;
    color: #000;
    border: none;
    padding: 0.4rem 0.9rem;
    border-radius: 4px;
    font-weight: 700;
    cursor: pointer;
    font-size: 0.85rem;
  }}
  .floating-bar button:hover {{ background: #22d3ee; }}

  /* Cover Page */
  .cover-page {{
    page-break-after: always;
    padding: 4rem 1rem;
    display: flex;
    flex-direction: column;
    justify-content: center;
    border-bottom: 2px solid var(--border);
    margin-bottom: 3rem;
  }}
  .doc-classification {{
    font-size: 0.85rem;
    font-weight: 800;
    letter-spacing: 1.5px;
    color: #dc2626;
    text-transform: uppercase;
    margin-bottom: 1.5rem;
  }}
  .report-title {{
    font-size: 2.2rem;
    font-weight: 800;
    color: var(--dark);
    line-height: 1.25;
    margin-bottom: 0.8rem;
  }}
  .report-subtitle {{
    font-size: 1.15rem;
    color: var(--muted);
    margin-bottom: 3rem;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.2rem;
    font-size: 0.9rem;
    border-top: 1px solid var(--border);
    padding-top: 1.5rem;
  }}
  .meta-item strong {{ display: block; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }}

  /* Content typography */
  h1 {{ font-size: 1.6rem; color: var(--dark); border-bottom: 2px solid var(--primary); padding-bottom: 0.4rem; margin: 2rem 0 1rem 0; page-break-after: avoid; }}
  h2 {{ font-size: 1.25rem; color: var(--primary); border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; margin: 2rem 0 0.8rem 0; page-break-after: avoid; page-break-before: always; }}
  h3 {{ font-size: 1.05rem; color: var(--dark); margin: 1.4rem 0 0.4rem 0; page-break-after: avoid; }}
  h4 {{ font-size: 0.88rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin: 1rem 0 0.3rem 0; }}
  p {{ margin-bottom: 0.8rem; font-size: 0.92rem; }}
  ul, ol {{ margin-left: 1.6rem; margin-bottom: 0.8rem; font-size: 0.92rem; }}
  li {{ margin-bottom: 0.3rem; }}
  code {{ font-family: Consolas, monospace; background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85rem; border: 1px solid #e2e8f0; }}
  pre.code-box {{ background: var(--bg-code); border: 1px solid var(--border); border-radius: 6px; padding: 0.85rem; margin: 0.8rem 0; overflow-x: auto; font-family: Consolas, monospace; font-size: 0.82rem; line-height: 1.45; page-break-inside: avoid; }}
  blockquote.callout {{ background: #f0f9ff; border-left: 4px solid var(--primary); padding: 0.75rem 1rem; margin: 1rem 0; font-style: italic; color: #334155; }}
  hr.section-divider {{ border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }}

  /* Tables */
  .table-wrapper {{ margin: 1.2rem 0; overflow-x: auto; page-break-inside: avoid; }}
  table.report-table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  table.report-table th, table.report-table td {{ border: 1px solid var(--border); padding: 0.5rem 0.75rem; text-align: left; }}
  table.report-table th {{ background: #f8fafc; color: var(--dark); font-weight: 700; }}
  table.report-table tr:nth-child(even) td {{ background: #fafafa; }}

  /* Badges */
  .badge {{ font-size: 0.72rem; font-weight: 800; padding: 0.15rem 0.5rem; border-radius: 4px; display: inline-block; text-transform: uppercase; }}
  .badge-crit {{ background: #fee2e2; color: #b91c1c; border: 1px solid #ef4444; }}
  .badge-high {{ background: #ffedd5; color: #c2410c; border: 1px solid #f97316; }}
  .badge-med {{ background: #fef3c7; color: #b45309; border: 1px solid #f59e0b; }}
  .badge-low {{ background: #e0f2fe; color: #0369a1; border: 1px solid #0284c7; }}
  .badge-pass {{ background: #dcfce7; color: #15803d; border: 1px solid #22c55e; }}
  .badge-info {{ background: #f1f5f9; color: #64748b; border: 1px solid #cbd5e1; }}

  /* Print Stylesheet */
  @media print {{
    @page {{
      size: A4;
      margin: 1.8cm 1.5cm;
    }}
    body {{
      padding: 0 !important;
      max-width: 100% !important;
      font-size: 9.5pt;
    }}
    .no-print {{ display: none !important; }}
    .cover-page {{
      min-height: 85vh;
      border-bottom: none;
      margin-bottom: 0;
    }}
    h1 {{ font-size: 16pt; margin-top: 14pt; }}
    h2 {{ font-size: 13pt; margin-top: 14pt; }}
    h3 {{ font-size: 11pt; margin-top: 10pt; }}
    pre.code-box {{ font-size: 7.5pt; }}
    table.report-table {{ font-size: 8.5pt; }}
  }}
</style>
</head>
<body>

<div class="floating-bar no-print">
  <div>
    <strong>CyberForge CART</strong> — Printable VAPT Executive Report
  </div>
  <div style="display:flex; gap:0.5rem;">
    <button onclick="window.print()">🖨️ Save as PDF / Print</button>
    <button onclick="window.close()" style="background:#334155; color:#fff;">✕ Close</button>
  </div>
</div>

<div class="cover-page">
  <div class="doc-classification">RESTRICTED // FORMAL SECURITY AUDIT REPORT</div>
  <h1 class="report-title">Vulnerability Assessment & Penetration Testing (VAPT) Report</h1>
  <div class="report-subtitle">Comprehensive Technical Audit Executed under the Penetration Testing Execution Standard (PTES)</div>
  <div class="meta-grid">
    <div class="meta-item">
      <strong>Assessment Standard</strong>
      Penetration Testing Execution Standard (PTES v1.0)
    </div>
    <div class="meta-item">
      <strong>Auditing Engine</strong>
      CyberForge CART (Controlled Autonomous Red Teaming)
    </div>
    <div class="meta-item">
      <strong>Designated Target Scope</strong>
      192.168.60.139/32 & Registered Binaries
    </div>
    <div class="meta-item">
      <strong>Enforced Scope Manifest</strong>
      Cryptographically Locked (Fail-Closed PolicyGate)
    </div>
  </div>
</div>

<div class="report-body">
  {html_body}
</div>

</body>
</html>"""
        self._send_html(doc)

    def _handle_status(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        run_row = conn.execute(
            "SELECT run_id, status, tier, started_at, completed_at, scope_version FROM runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()

        if not run_row:
            conn.close()
            self._send_json({
                "run_id": "none",
                "status": "idle",
                "tier": "standard",
                "scope_version": "none",
                "started_at": "",
                "completed_at": "",
                "metrics": {
                    "scope_safety_out_of_bounds_probes": 0,
                    "scope_decisions_allowed": 0,
                    "scope_decisions_denied": 0,
                    "total_assets_discovered": 0,
                    "total_services_discovered": 0,
                    "total_findings": 0,
                    "confirmed_findings": 0,
                    "verification_rate_pct": 100.0,
                    "false_alarm_rate_pct": 0.0,
                    "runtime_seconds": 0.0,
                    "autonomy_interventions": 0,
                },
            })
            return

        run_id, status, tier, start, end, scope_ver = run_row
        reporter = ReportGenerator(conn)
        report_data = reporter._collect_data(run_id)

        self._send_json({
            "run_id": run_id,
            "status": status,
            "tier": tier,
            "scope_version": scope_ver,
            "started_at": start,
            "completed_at": end,
            "metrics": report_data["metrics"],
        })
        conn.close()

    def _handle_flags(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        rows = conn.execute(
            "SELECT finding_id, asset_id, severity, status, summary "
            "FROM findings WHERE finding_type = 'ctf_planted_flag' "
            "ORDER BY rowid"
        ).fetchall()
        asset_keys = dict(
            conn.execute("SELECT asset_id, canonical_key FROM assets").fetchall()
        )
        flags = []
        for fid, aid, severity, status, summary in rows:
            ev = conn.execute(
                "SELECT artifact_path, excerpt, hash, timestamp "
                "FROM evidence WHERE finding_id = ? LIMIT 1",
                (fid,),
            ).fetchone()
            flags.append({
                "finding_id": fid,
                "asset_id": aid,
                "asset_key": asset_keys.get(aid, aid),
                "severity": severity,
                "status": status,
                "summary": summary,
                "location": ev[0] if ev else "",
                "excerpt": ev[1] if ev else "",
                "hash": ev[2] if ev else "",
                "captured_at": ev[3] if ev else "",
                "source": ev[0] if ev else "",
            })
        conn.close()
        self._send_json(flags)

    def _handle_agents(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        agents = {
            "network": {"name": "Network Specialist", "icon": "🌐", "role": "Host & Port Discovery", "active": 0, "completed": 0},
            "web": {"name": "Web Specialist", "icon": "🕷️", "role": "Endpoints & Form Crawler", "active": 0, "completed": 0},
            "binary": {"name": "Binary Specialist", "icon": "⚙️", "role": "Static Analysis & Unsafe Libc", "active": 0, "completed": 0},
            "verifier": {"name": "Verification Service", "icon": "🛡️", "role": "Deterministic Playbooks", "active": 0, "completed": 0},
            "advisor": {"name": "Remediation Advisor", "icon": "💡", "role": "Plain-English Patches", "active": 0, "completed": 0},
        }

        task_rows = conn.execute("SELECT owner, status, count(*) FROM tasks GROUP BY owner, status").fetchall()
        for owner, status, count in task_rows:
            if owner in agents:
                if status == "running":
                    agents[owner]["active"] += count
                elif status == "succeeded":
                    agents[owner]["completed"] += count

        conf_count = conn.execute("SELECT count(*) FROM findings WHERE status = 'confirmed'").fetchone()[0]
        cand_count = conn.execute("SELECT count(*) FROM findings WHERE status = 'candidate'").fetchone()[0]
        agents["verifier"]["active"] = cand_count
        agents["verifier"]["completed"] = conf_count
        agents["advisor"]["completed"] = conf_count

        conn.close()
        self._send_json(list(agents.values()))

    def _get_latest_run_id(self, conn: sqlite3.Connection) -> str | None:
        row = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def _handle_asset_detail(self, query_str: str) -> None:
        qs = urllib.parse.parse_qs(query_str)
        asset_id = qs.get("id", [None])[0]
        if not asset_id:
            self._send_json({"error": "missing id"}, status=400)
            return

        conn = connect(self.db_path, check_same_thread=False)
        asset_row = conn.execute(
            "SELECT asset_id, asset_type, canonical_key, first_seen, last_seen FROM assets WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()

        if not asset_row:
            conn.close()
            self._send_json({"error": "asset not found"}, status=404)
            return

        aid, atype, key, first, last = asset_row
        svc_rows = conn.execute(
            "SELECT port, protocol, service_name, version, state FROM services WHERE asset_id = ?",
            (aid,),
        ).fetchall()
        services = [
            {"port": s[0], "protocol": s[1], "name": s[2], "banner": s[3], "state": s[4]}
            for s in svc_rows
        ]

        find_rows = conn.execute(
            "SELECT finding_id, finding_type, severity, status, summary FROM findings WHERE asset_id = ?",
            (aid,),
        ).fetchall()
        findings = [
            {"finding_id": f[0], "type": f[1], "severity": f[2], "status": f[3], "summary": f[4]}
            for f in find_rows
        ]

        conn.close()
        self._send_json({
            "asset_id": aid,
            "type": atype,
            "key": key,
            "first_seen": first,
            "last_seen": last,
            "services": services,
            "findings": findings,
        })

    def _handle_patches(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        advisor = RemediationAdvisor(conn)
        patches = advisor.export_patches(output_dir="reports/patches")
        conn.close()
        self._send_json({"patches": patches})

    def _handle_candidates(self) -> None:
        candidates = list_candidate_networks()
        self._send_json(candidates)

    def _handle_inventory(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        latest_run = self._get_latest_run_id(conn)
        if latest_run:
            rows = conn.execute(
                "SELECT asset_id, asset_type, canonical_key FROM assets WHERE run_id = ?",
                (latest_run,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT asset_id, asset_type, canonical_key FROM assets").fetchall()

        inv = []
        for aid, atype, key in rows:
            svcs = conn.execute(
                "SELECT port, protocol, service_name FROM services WHERE asset_id = ?",
                (aid,),
            ).fetchall()
            inv.append({
                "asset_id": aid,
                "asset_type": atype,
                "canonical_key": key,
                "services": [
                    {"port": s[0], "protocol": s[1], "service_name": s[2]}
                    for s in svcs
                ],
            })
        conn.close()
        self._send_json(inv)

    def _handle_findings(self, query_str: str = "") -> None:
        qs = urllib.parse.parse_qs(query_str)
        include_info = qs.get("include_info", ["0"])[0].lower() in ("1", "true")
        severity_filter = "" if include_info else "AND f.severity != 'info'"

        conn = connect(self.db_path, check_same_thread=False)
        latest_run = self._get_latest_run_id(conn)
        if latest_run:
            rows = conn.execute(
                f"SELECT f.finding_id, f.finding_type, f.severity, f.status, f.summary, "
                f"MAX(e.evidence_id), MAX(e.artifact_path), MAX(e.excerpt), MAX(e.source_tool), MAX(e.hash) "
                f"FROM findings f "
                f"JOIN assets a ON f.asset_id = a.asset_id "
                f"LEFT JOIN evidence e ON f.finding_id = e.finding_id AND e.artifact_path != '' "
                f"WHERE a.run_id = ? {severity_filter} "
                f"GROUP BY f.finding_id "
                f"ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.rowid DESC",
                (latest_run,),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT f.finding_id, f.finding_type, f.severity, f.status, f.summary, "
                f"MAX(e.evidence_id), MAX(e.artifact_path), MAX(e.excerpt), MAX(e.source_tool), MAX(e.hash) "
                f"FROM findings f "
                f"LEFT JOIN evidence e ON f.finding_id = e.finding_id AND e.artifact_path != '' "
                f"WHERE 1=1 {severity_filter} "
                f"GROUP BY f.finding_id "
                f"ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.rowid DESC"
            ).fetchall()
        findings = []
        for fid, ftype, sev, st, summary, evid, art_path, excerpt, tool, h in rows:
            findings.append({
                "finding_id": fid,
                "type": ftype,
                "severity": sev,
                "status": st,
                "summary": summary,
                "evidence_id": evid or "none",
                "target_url": art_path or "",
                "tool": tool or "web_crawler",
                "hash": (h or "")[:12],
                "excerpt": excerpt or "",
                "evidence_count": 1 if evid else 0,
            })
        conn.close()
        self._send_json(findings)

    def _handle_logs(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        rows = conn.execute(
            "SELECT requested_target, decision, reason, at FROM scope_decisions_log ORDER BY at DESC LIMIT 50"
        ).fetchall()
        logs = [
            {"target": r[0], "decision": r[1], "reason": r[2], "at": r[3]}
            for r in rows
        ]
        conn.close()
        self._send_json(logs)

    def _handle_graph(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        builder = AttackPathBuilder(conn, "current")
        paths = builder.build()

        nodes_dict: dict[str, Any] = {}
        edges_list: list[dict[str, str]] = []

        for p in paths:
            for e in p.edges:
                nodes_dict[e.source_id] = {
                    "id": e.source_id,
                    "label": e.source_id[:16],
                    "type": "asset",
                }
                nodes_dict[e.target_id] = {
                    "id": e.target_id,
                    "label": e.target_id[:16],
                    "type": "compromised",
                }
                edges_list.append({
                    "source": e.source_id,
                    "target": e.target_id,
                    "label": e.relationship_type,
                })

        conn.close()
        self._send_json({
            "nodes": list(nodes_dict.values()),
            "edges": edges_list,
        })

    def _handle_report(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        rep_row = conn.execute(
            "SELECT path FROM report_artifacts WHERE format = 'md' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

        report_text = ""
        if rep_row and Path(rep_row[0]).exists():
            report_text = Path(rep_row[0]).read_text(encoding="utf-8")

        conn.close()
        self._send_json({"report": report_text})


def run_dashboard_server(
    db_path: str = "cart.db",
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = False,
) -> http.server.HTTPServer:
    """Launch the local HTTP dashboard server."""
    class BoundHandler(DashboardHandler):
        pass

    BoundHandler.db_path = db_path

    server = http.server.HTTPServer((host, port), BoundHandler)
    url = f"http://{host}:{port}/"
    print(f"\\n[+] CyberForge CART UI Dashboard running at: {url}")
    print("[+] Press Ctrl+C in terminal to stop dashboard server.")

    if open_browser:
        import webbrowser
        webbrowser.open(url)

    return server
'''

with open("src/cart/ui.py", "w", encoding="utf-8") as f:
    f.write(ui_template)
print("Successfully wrote updated src/cart/ui.py!")

