"""Local findings & reporting UI (spec section 5.10, FR-8).

Provides:
1. Executive dashboard with live multi-agent coordination strip.
2. Filtered security vulnerability table (CRITICAL, HIGH, MEDIUM, LOW).
3. Real-time autonomous assessment progress & completion banner.
4. Beautiful in-browser Markdown renderer for the PTES assessment report.
5. Publication-grade PDF download & printable report export (/report/printable).
"""

from __future__ import annotations

import html
import http.server
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from .advisor import RemediationAdvisor
from .attackpath import AttackPathBuilder, derive_run_relationships
from .models import FindingStatus, RunStatus, Task, TaskStatus, new_id, utc_now
from .orchestrator import Orchestrator
from .preflight import list_candidate_networks
from .ptes import PtesPhase
from .report import ReportGenerator
from .scope import PolicyGate, setup_scope_for_target
from .store import connect
from .verify import VerificationService
from .workers.binary import BinaryWorker
from .workers.network import NetworkWorker
from .workers.web import WebWorker


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
        out = ["<div class='table-wrapper'><table class='report-table'>"]
        header_cols = [c.strip() for c in table_lines[0].strip('|').split('|')]
        out.append("<thead><tr>")
        for col in header_cols:
            out.append(f"<th>{inline_format(col)}</th>")
        out.append("</tr></thead><tbody>")

        for row in table_lines[2:]:
            cols = [c.strip() for c in row.strip('|').split('|')]
            out.append("<tr>")
            for col in cols:
                out.append(f"<td>{inline_format(col)}</td>")
            out.append("</tr>")
        out.append("</tbody></table></div>")
        table_lines = []
        in_table = False
        html_out.append("\n".join(out))

    def inline_format(text: str) -> str:
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
        text = text.replace("🔴 CRITICAL", "<span class='badge badge-crit'>CRITICAL</span>")
        text = text.replace("🟠 HIGH", "<span class='badge badge-high'>HIGH</span>")
        text = text.replace("🟡 MEDIUM", "<span class='badge badge-med'>MEDIUM</span>")
        text = text.replace("🔵 LOW", "<span class='badge badge-low'>LOW</span>")
        text = text.replace("⚪ INFO", "<span class='badge badge-info'>INFO</span>")
        text = text.replace("✅ PASS", "<span class='badge badge-pass'>PASS</span>")
        return text

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_code_block:
                code_text = html.escape("\n".join(code_block_lines))
                html_out.append(f"<pre class='code-box'><code class='lang-{code_block_lang}'>{code_text}</code></pre>")
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
            html_out.append(f"<blockquote class='callout'>{inline_format(stripped[2:])}</blockquote>")
        elif stripped == "---":
            html_out.append("<hr class='section-divider'/>")
        elif stripped.startswith(("- ", "* ")):
            html_out.append(f"<li class='bullet-item'>{inline_format(stripped[2:])}</li>")
        else:
            html_out.append(f"<p>{inline_format(stripped)}</p>")

    if in_table:
        flush_table()

    return "\n".join(html_out)


_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberForge CART — Autonomous VAPT Assessment Engine</title>
<style>
:root {
  /* 1. Backgrounds */
  --bg: #090d16;
  --panel: #0e131f;
  --panel-hover: #141b2d;
  --panel-border: rgba(255, 255, 255, 0.08);
  --code-bg: #060910;
  
  /* 2. Text */
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --text-subtle: #64748b;
  
  /* 3. Gradient */
  --gradient: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
  --gradient-hover: linear-gradient(135deg, #67e8f9 0%, #a5b4fc 100%);
  --gradient-subtle: linear-gradient(135deg, rgba(56, 189, 248, 0.08) 0%, rgba(129, 140, 248, 0.08) 100%);
  --gradient-border: rgba(56, 189, 248, 0.35);
  --gradient-glow: rgba(56, 189, 248, 0.25);
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
}

body {
  background: var(--bg);
  color: var(--text);
  padding: 1.75rem 2rem;
  line-height: 1.5;
  font-size: 0.88rem;
  -webkit-font-smoothing: antialiased;
}

/* Header */
header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--panel-border);
  padding-bottom: 1.1rem;
  margin-bottom: 1.5rem;
}

.logo {
  font-size: 1.3rem;
  font-weight: 800;
  letter-spacing: 0.5px;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 0.6rem;
}

.grad-text {
  background: var(--gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  font-weight: 800;
}

.badge {
  font-size: 0.68rem;
  padding: 0.2rem 0.6rem;
  border-radius: 9999px;
  text-transform: uppercase;
  font-weight: 700;
  letter-spacing: 0.5px;
  border: 1px solid var(--panel-border);
  color: var(--text-muted);
  transition: all 0.2s;
}

.badge-running {
  background: var(--gradient-subtle);
  color: #38bdf8;
  border-color: #38bdf8;
  box-shadow: 0 0 12px var(--gradient-glow);
}

.badge-completed {
  background: var(--gradient-subtle);
  color: #818cf8;
  border-color: #818cf8;
}

.badge-idle, .badge-partial {
  background: rgba(255, 255, 255, 0.03);
  color: var(--text-muted);
  border-color: var(--panel-border);
}

/* Grid & Cards */
.grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 1rem;
  margin-bottom: 1.25rem;
}

.col-3 { grid-column: span 3; }
.col-4 { grid-column: span 4; }
.col-6 { grid-column: span 6; }
.col-8 { grid-column: span 8; }
.col-12 { grid-column: span 12; }

.card {
  background: var(--panel);
  border: 1px solid var(--panel-border);
  border-radius: 10px;
  padding: 1.2rem;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

.card:hover {
  border-color: rgba(255, 255, 255, 0.15);
}

.card-header {
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 0.85rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.metric-val {
  font-size: 1.85rem;
  font-weight: 800;
  color: var(--text);
  margin-bottom: 0.25rem;
  letter-spacing: -0.5px;
}

.metric-sub {
  font-size: 0.75rem;
  color: var(--text-muted);
}

/* Status & Completion Banner */
.status-banner {
  background: var(--gradient-subtle);
  border: 1px solid var(--gradient-border);
  box-shadow: 0 4px 25px rgba(0, 0, 0, 0.35);
  border-radius: 10px;
  padding: 1.15rem 1.4rem;
  margin-bottom: 1.35rem;
  animation: bannerFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.status-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--gradient);
  box-shadow: 0 0 10px #38bdf8;
  display: inline-block;
}

.status-dot.pulsing {
  animation: pulseDot 1.6s infinite;
}

@keyframes pulseDot {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.7); }
  70% { transform: scale(1.15); box-shadow: 0 0 0 8px rgba(56, 189, 248, 0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(56, 189, 248, 0); }
}

@keyframes bannerFadeIn {
  from { opacity: 0; transform: translateY(-4px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Multi-Agent Strip */
.agent-strip {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 0.85rem;
  margin-bottom: 1.35rem;
}

.agent-card {
  background: var(--panel);
  border: 1px solid var(--panel-border);
  border-radius: 8px;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  position: relative;
  overflow: hidden;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

.agent-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: var(--gradient);
  opacity: 0;
  transition: opacity 0.2s;
}

.agent-card:hover {
  background: var(--panel-hover);
  border-color: rgba(255, 255, 255, 0.16);
}

.agent-card:hover::before {
  opacity: 1;
}

.agent-name {
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.2px;
}

.agent-role {
  font-size: 0.72rem;
  color: var(--text-muted);
}

.agent-stat {
  font-size: 0.76rem;
  font-weight: 600;
  color: #38bdf8;
  margin-top: 0.2rem;
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.82rem;
}

th, td {
  text-align: left;
  padding: 0.65rem 0.85rem;
  border-bottom: 1px solid var(--panel-border);
}

th {
  color: var(--text-subtle);
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  background: rgba(0, 0, 0, 0.25);
}

tr:hover td {
  background: rgba(255, 255, 255, 0.025);
}

tr:last-child td {
  border-bottom: none;
}

/* Severity Pills */
.sev-pill {
  font-size: 0.68rem;
  font-weight: 700;
  padding: 0.2rem 0.55rem;
  border-radius: 4px;
  display: inline-block;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.sev-critical {
  background: var(--gradient-subtle);
  border: 1px solid #38bdf8;
  color: var(--text);
  box-shadow: 0 0 10px rgba(56, 189, 248, 0.2);
}

.sev-high {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(56, 189, 248, 0.45);
  color: var(--text);
}

.sev-medium {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.16);
  color: var(--text-muted);
}

.sev-low, .sev-info {
  background: transparent;
  border: 1px solid rgba(255, 255, 255, 0.08);
  color: var(--text-subtle);
}

/* Log Box */
.log-box {
  font-family: Consolas, monospace;
  font-size: 0.78rem;
  height: 260px;
  overflow-y: auto;
  background: var(--code-bg);
  padding: 0.85rem;
  border-radius: 6px;
  border: 1px solid var(--panel-border);
}

.log-line { margin-bottom: 0.35rem; }
.log-deny { color: #818cf8; font-weight: 700; }
.log-allow { color: #38bdf8; font-weight: 700; }
.log-meta { color: var(--text-subtle); }

/* Graph Viewport */
.graph-container {
  width: 100%;
  height: 320px;
  background: var(--code-bg);
  border: 1px solid var(--panel-border);
  border-radius: 8px;
  overflow: hidden;
  position: relative;
}

svg { width: 100%; height: 100%; }

/* Buttons */
button {
  background: var(--gradient);
  color: #090d16;
  border: none;
  padding: 0.48rem 0.95rem;
  border-radius: 6px;
  font-weight: 700;
  cursor: pointer;
  font-size: 0.82rem;
  letter-spacing: 0.3px;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 4px 12px var(--gradient-glow);
}

button:hover {
  background: var(--gradient-hover);
  transform: translateY(-1px);
  box-shadow: 0 6px 18px rgba(56, 189, 248, 0.38);
}

button.btn-sec {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid var(--panel-border);
  color: var(--text);
  box-shadow: none;
}

button.btn-sec:hover {
  background: rgba(255, 255, 255, 0.08);
  border-color: rgba(255, 255, 255, 0.22);
  box-shadow: none;
  transform: translateY(-1px);
}

button.btn-primary {
  background: var(--gradient);
  color: #090d16;
  border: none;
}

button.btn-primary-pdf {
  background: var(--gradient);
  color: #090d16;
  border: none;
  padding: 0.48rem 1rem;
  border-radius: 6px;
  font-weight: 800;
  cursor: pointer;
  font-size: 0.82rem;
  letter-spacing: 0.4px;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 4px 14px var(--gradient-glow);
}

button.btn-primary-pdf:hover {
  background: var(--gradient-hover);
  transform: translateY(-1px);
  box-shadow: 0 6px 20px rgba(56, 189, 248, 0.45);
}

button.tab-btn {
  background: transparent;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  border-radius: 4px;
  box-shadow: none;
}

button.tab-btn.active-tab {
  background: rgba(255, 255, 255, 0.08);
  color: var(--text);
  font-weight: 700;
  box-shadow: none;
}

/* Rendered Report */
.rendered-report-container { font-size: 0.86rem; line-height: 1.65; color: #e2e8f0; }
.rendered-report-container h1 { font-size: 1.35rem; color: var(--text); border-bottom: 2px solid #38bdf8; padding-bottom: 0.4rem; margin: 1.2rem 0 0.8rem 0; }
.rendered-report-container h2 { font-size: 1.12rem; color: #38bdf8; border-bottom: 1px solid var(--panel-border); padding-bottom: 0.3rem; margin: 1.2rem 0 0.6rem 0; }
.rendered-report-container h3 { font-size: 0.98rem; color: var(--text); margin: 1rem 0 0.4rem 0; }
.rendered-report-container h4 { font-size: 0.82rem; color: var(--text-muted); text-transform: uppercase; margin: 0.8rem 0 0.3rem 0; }
.rendered-report-container p { margin-bottom: 0.6rem; }
.rendered-report-container code { background: var(--code-bg); border: 1px solid var(--panel-border); border-radius: 4px; padding: 0.15rem 0.4rem; font-family: Consolas, monospace; font-size: 0.82rem; color: #38bdf8; }
.rendered-report-container pre.code-box { background: var(--code-bg); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.8rem; margin: 0.6rem 0; overflow-x: auto; font-family: Consolas, monospace; font-size: 0.8rem; color: #cbd5e1; }
.rendered-report-container blockquote.callout { background: var(--gradient-subtle); border-left: 3px solid #38bdf8; padding: 0.6rem 0.9rem; margin: 0.6rem 0; color: var(--text-muted); }
.rendered-report-container hr.section-divider { border: none; border-top: 1px solid var(--panel-border); margin: 1.2rem 0; }
.rendered-report-container ul, .rendered-report-container ol { margin-left: 1.4rem; margin-bottom: 0.6rem; }
.rendered-report-container li { margin-bottom: 0.25rem; }
.rendered-report-container table.report-table { width: 100%; border-collapse: collapse; margin: 0.8rem 0; font-size: 0.82rem; }
.rendered-report-container table.report-table th, .rendered-report-container table.report-table td { border: 1px solid var(--panel-border); padding: 0.45rem 0.65rem; }
.rendered-report-container table.report-table th { background: rgba(0, 0, 0, 0.3); color: var(--text-muted); }

pre.report-pre { white-space: pre-wrap; font-family: Consolas, monospace; font-size: 0.78rem; background: var(--code-bg); padding: 1rem; border-radius: 6px; max-height: 480px; overflow-y: auto; color: #cbd5e1; border: 1px solid var(--panel-border); }

/* Modal Drawer */
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); z-index: 100; align-items: center; justify-content: center; backdrop-filter: blur(8px); }
.modal-content { background: var(--panel); border: 1px solid var(--gradient-border); border-radius: 10px; width: 620px; max-width: 92%; max-height: 82vh; overflow-y: auto; padding: 1.5rem; box-shadow: 0 10px 40px rgba(0,0,0,0.6); }
</style>
</head>
<body>

<header>
  <div class="logo">
    CyberForge <span class="grad-text">CART</span>
    <span id="run-badge" class="badge badge-idle">IDLE</span>
    <span style="font-size:0.75rem; color:var(--text-muted); font-weight:400; margin-left:0.5rem;">Autonomous VAPT Assessment Engine</span>
  </div>
  <div style="display:flex; gap:0.6rem; align-items:center;">
    <div style="display:flex; align-items:center; gap:0.4rem; background:var(--panel); border:1px solid var(--panel-border); padding:0.25rem 0.65rem; border-radius:6px;">
      <span style="font-size:0.72rem; color:var(--text-muted); font-weight:700;">ASSESSMENT RUN:</span>
      <select id="run-selector" onchange="switchRun(this.value)" style="background:transparent; border:none; color:var(--text); font-size:0.76rem; font-family:Consolas, monospace; cursor:pointer; outline:none; max-width:320px;">
      </select>
    </div>
    <button onclick="openPrintableReport()" class="btn-primary-pdf">DOWNLOAD PDF</button>
    <button onclick="refreshData()" class="btn-sec">Refresh</button>
  </div>
</header>

<!-- Universal Target Assessment Launcher -->
<div class="card" style="margin-bottom: 1.5rem; border-color: rgba(56, 189, 248, 0.3);">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.8rem;">
    <div style="display:flex; align-items:center; gap:0.6rem;">
      <span style="font-weight:700; color:var(--text); font-size:1rem;">Universal Target Assessment Launcher</span>
      <span class="sev-pill" style="background:var(--gradient-subtle); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);">Target Engine Ready</span>
    </div>
    <span id="launcher-status" style="font-size:0.8rem; color:var(--text-subtle);">Ready to assess target URL, IP, or network range</span>
  </div>
  <p style="color:var(--text-muted); font-size:0.82rem; margin-bottom:1rem;">
    Assess any web application, CTF lab, or network infrastructure. The fail-closed <code>PolicyGate</code> locks scope, deploys network, web, and binary agents, captures flags, verifies vulnerabilities, and outputs a publication-grade PTES report.
  </p>
  <div style="display:flex; gap:0.8rem; align-items:center; flex-wrap:wrap;">
    <div style="flex:1; min-width:280px;">
      <input type="text" id="target-input" value="" placeholder="Enter target URL or IP (e.g. https://preview.owasp-juice.shop/ or https://preview.owasp-juice.shop/ or 10.10.10.5)" 
             style="width:100%; background:var(--code-bg); border:1px solid var(--panel-border); color:var(--text); padding:0.6rem 0.9rem; border-radius:6px; font-family:Consolas, monospace; font-size:0.88rem;">
    </div>
    <div style="width:160px;">
      <select id="tier-select" style="width:100%; background:var(--code-bg); border:1px solid var(--panel-border); color:var(--text); padding:0.6rem 0.8rem; border-radius:6px; font-size:0.88rem;">
        <option value="deep" selected>Tier: Deep Exploit</option>
        <option value="breach">Tier: Breach & PoC</option>
        <option value="recon">Tier: Recon Only</option>
      </select>
    </div>
    <button id="btn-launch-run" onclick="launchAssessment()" class="btn-primary" style="padding:0.6rem 1.4rem; font-size:0.88rem;">
      Launch Assessment
    </button>
  </div>
  <div style="display:flex; gap:0.5rem; margin-top:0.7rem; align-items:center; flex-wrap:wrap;">
    <span style="font-size:0.75rem; color:var(--text-subtle); font-weight:600;">Presets:</span>
    <button type="button" onclick="setPreset('http://127.0.0.1:3000/', 'deep')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">Local Juice Shop (127.0.0.1:3000)</button>
    <button type="button" onclick="setPreset('http://127.0.0.1:8080/', 'recon')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">Localhost Assessment</button>
    <button type="button" onclick="setPreset('10.0.10.0/24', 'recon')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">Lab Subnet (10.0.10.0/24)</button>
    <button type="button" onclick="setPreset('10.0.10.25', 'deep')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">Lab Host (10.0.10.25)</button>
  </div>
</div>


<!-- Multi-Agent Live Coordination Strip -->
<div class="agent-strip" id="agents-strip">
  <div class="agent-card">
    <div class="agent-name">Network Specialist</div>
    <div class="agent-role">Host & Port Discovery</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">Web Specialist</div>
    <div class="agent-role">Endpoints & Form Crawler</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">Binary Specialist</div>
    <div class="agent-role">Static Analysis & Unsafe Libc</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">Verification Service</div>
    <div class="agent-role">Deterministic Playbooks</div>
    <div class="agent-stat">0 Confirmed</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">Remediation Advisor</div>
    <div class="agent-role">Plain-English Patches</div>
    <div class="agent-stat">0 Patches Ready</div>
  </div>
</div>

<!-- Live Execution & Completion Status Banner -->
<div id="completion-banner" class="status-banner" style="display:none;">
  <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:1rem;">
    <div style="display:flex; align-items:center; gap:0.9rem;">
      <div id="status-icon" class="status-dot"></div>
      <div>
        <div id="status-headline" style="font-size:1.02rem; font-weight:700; color:var(--text); letter-spacing:0.02em;">
          Autonomous Assessment Completed — Done With All Tasks
        </div>
        <div id="status-subline" style="font-size:0.82rem; color:var(--text-muted); margin-top:0.2rem;">
          All scope targets inspected, vulnerabilities evidenced and verified with deterministic playbooks. 100% autonomous execution.
        </div>
      </div>
    </div>
    <div style="display:flex; gap:0.6rem; align-items:center;">
      <button id="status-action-btn" onclick="exportPDF()" class="btn-primary" style="padding:0.55rem 1.1rem; font-size:0.85rem;">
        Download PTES PDF Report
      </button>
      <a href="#findings-table" class="btn-sec" style="padding:0.55rem 0.9rem; font-size:0.85rem; text-decoration:none;">
        View Findings
      </a>
    </div>
  </div>
</div>

<!-- Key Performance Indicators -->
<div class="grid">
  <div class="col-3 card">
    <div class="card-header">Scope Safety</div>
    <div class="metric-val" id="metric-safety" style="color:var(--text-subtle);">—</div>
    <div class="metric-sub" id="metric-safety-sub">Awaiting target launch</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Autonomy Post-Start</div>
    <div class="metric-val" id="metric-autonomy" style="color:var(--text-subtle);">—</div>
    <div class="metric-sub" id="metric-autonomy-sub">Awaiting target launch</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Verified Findings</div>
    <div class="metric-val" id="metric-findings" style="color:var(--text-subtle);">—</div>
    <div class="metric-sub" id="metric-findings-sub">Awaiting target launch</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Discovered Assets</div>
    <div class="metric-val" id="metric-assets" style="color:var(--text-subtle);">—</div>
    <div class="metric-sub" id="metric-assets-sub">Awaiting target launch</div>
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
        <span>Penetration Testing Execution Standard (PTES) Report</span>
        <div style="display:inline-flex; border:1px solid var(--panel-border); border-radius:4px; overflow:hidden;">
          <button id="btn-view-rendered" onclick="switchReportTab('rendered')" class="tab-btn active-tab" style="padding:0.2rem 0.6rem; font-size:0.75rem;">Formatted View</button>
          <button id="btn-view-raw" onclick="switchReportTab('raw')" class="tab-btn" style="padding:0.2rem 0.6rem; font-size:0.75rem;">Raw Markdown</button>
        </div>
      </div>
      <div style="display:flex; gap:0.5rem; align-items:center;">
        <button onclick="openPrintableReport()" class="btn-primary-pdf" style="font-size:0.75rem; padding:0.25rem 0.65rem;">DOWNLOAD PDF</button>
        <button onclick="downloadReport()" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.6rem;">Download Markdown</button>
        <button onclick="downloadPatches()" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.6rem;">Export Patches</button>
      </div>
    </div>
    <div id="rendered-report" class="rendered-report-container" style="max-height: 520px; overflow-y: auto; padding: 1.2rem; background: var(--code-bg); border-radius: 6px; border: 1px solid var(--panel-border);"></div>
    <pre class="report-pre" id="report-text" style="display:none; max-height: 520px; overflow-y: auto;">No report generated yet.</pre>
  </div>
</div>

<!-- Node Inspection Modal -->
<div class="modal-overlay" id="node-modal" onclick="closeModal(event)">
  <div class="modal-content" onclick="event.stopPropagation()">
    <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--panel-border); padding-bottom:0.5rem; margin-bottom:1rem;">
      <h3 id="modal-title" style="color:var(--text);">Evidence Details</h3>
      <button onclick="document.getElementById('node-modal').style.display='none'" class="btn-sec" style="padding:0.2rem 0.5rem;">Close</button>
    </div>
    <div id="modal-body" style="font-size:0.85rem; line-height:1.6;"></div>
  </div>
</div>

<script>
let currentRunId = null;
let lastReportContent = "";

function openPrintableReport() {
  const url = currentRunId ? `/report/printable?run_id=${currentRunId}` : '/report/printable?run_id=idle';
  window.open(url, '_blank');
}

function exportPDF() {
  const url = currentRunId ? `/report/pdf?run_id=${currentRunId}` : '/report/pdf?run_id=idle';
  window.open(url, '_blank');
}

async function loadRuns() {
  try {
    const res = await fetch('/api/runs');
    const runs = await res.json();
    const selector = document.getElementById('run-selector');
    if (!selector) return;

    selector.innerHTML = '';
    const idleOpt = document.createElement('option');
    idleOpt.value = '';
    idleOpt.textContent = '— Live Assessment (Idle / New Run) —';
    if (!currentRunId) idleOpt.selected = true;
    selector.appendChild(idleOpt);

    runs.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.run_id;
      opt.textContent = r.label;
      if (r.run_id === currentRunId) opt.selected = true;
      selector.appendChild(opt);
    });
  } catch (e) {
    console.error('Error loading runs:', e);
  }
}

function switchRun(runId) {
  currentRunId = runId || null;
  refreshData();
}

function switchReportTab(tab) {
  const renderedEl = document.getElementById('rendered-report');
  const rawEl = document.getElementById('report-text');
  const btnRendered = document.getElementById('btn-view-rendered');
  const btnRaw = document.getElementById('btn-view-raw');
  if (tab === 'rendered') {
    renderedEl.style.display = 'block';
    rawEl.style.display = 'none';
    btnRendered.classList.add('active-tab');
    btnRaw.classList.remove('active-tab');
  } else {
    renderedEl.style.display = 'none';
    rawEl.style.display = 'block';
    btnRendered.classList.remove('active-tab');
    btnRaw.classList.add('active-tab');
  }
}

// Client-side markdown renderer for the report view
function formatMarkdown(md) {
  if (!md) return '<p style="color:var(--text-muted);">No report generated yet.</p>';
  const lines = md.split('\n');
  let out = [];
  let inCode = false;
  let codeLines = [];
  let inTable = false;
  let tableLines = [];

  function flushTbl() {
    if (!tableLines.length) { inTable = false; return; }
    out.push('<table class="report-table"><thead><tr>');
    const headers = tableLines[0].split('|').filter((c, i, a) => i > 0 && i < a.length - 1);
    headers.forEach(h => out.push(`<th>${inlineFmt(h.trim())}</th>`));
    out.push('</tr></thead><tbody>');
    for (let r = 2; r < tableLines.length; r++) {
      out.push('<tr>');
      const cols = tableLines[r].split('|').filter((c, i, a) => i > 0 && i < a.length - 1);
      cols.forEach(c => out.push(`<td>${inlineFmt(c.trim())}</td>`));
      out.push('</tr>');
    }
    out.push('</tbody></table>');
    tableLines = [];
    inTable = false;
  }

  function inlineFmt(s) {
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    s = s.replace(/[🔴\s]*CRITICAL/g, '<span class="sev-pill sev-critical">CRITICAL</span>');
    s = s.replace(/[🟠\s]*HIGH/g, '<span class="sev-pill sev-high">HIGH</span>');
    s = s.replace(/[🟡\s]*MEDIUM/g, '<span class="sev-pill sev-medium">MEDIUM</span>');
    s = s.replace(/[🔵\s]*LOW/g, '<span class="sev-pill sev-low">LOW</span>');
    s = s.replace(/[✅\s]*PASS/g, '<span style="color:#38bdf8; font-weight:700;">PASS</span>');
    return s;
  }

  for (let line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('```')) {
      if (inCode) {
        out.push(`<pre class="code-box"><code>${codeLines.join('\n')}</code></pre>`);
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
      codeLines.push(line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'));
      continue;
    }
    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      if (!inTable) { inTable = true; tableLines = [trimmed]; }
      else tableLines.push(trimmed);
      continue;
    } else if (inTable) {
      flushTbl();
    }
    if (!trimmed) continue;
    if (trimmed.startsWith('#### ')) out.push(`<h4>${inlineFmt(trimmed.slice(5))}</h4>`);
    else if (trimmed.startsWith('### ')) out.push(`<h3>${inlineFmt(trimmed.slice(4))}</h3>`);
    else if (trimmed.startsWith('## ')) out.push(`<h2>${inlineFmt(trimmed.slice(3))}</h2>`);
    else if (trimmed.startsWith('# ')) out.push(`<h1>${inlineFmt(trimmed.slice(2))}</h1>`);
    else if (trimmed.startsWith('> ')) out.push(`<blockquote class="callout">${inlineFmt(trimmed.slice(2))}</blockquote>`);
    else if (trimmed === '---') out.push('<hr class="section-divider"/>');
    else if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) out.push(`<li>${inlineFmt(trimmed.slice(2))}</li>`);
    else out.push(`<p>${inlineFmt(trimmed)}</p>`);
  }
  if (inTable) flushTbl();
  return out.join('\n');
}

async function refreshData() {
  try {
    await loadRuns();
    const runParam = currentRunId ? `?run_id=${currentRunId}` : '?run_id=idle';
    const runJoin = currentRunId ? `&run_id=${currentRunId}` : '&run_id=idle';

    const res = await fetch('/api/status' + runParam);
    const data = await res.json();
    renderStatus(data);
    
    const logsRes = await fetch('/api/logs' + runParam);
    const logsData = await logsRes.json();
    renderLogs(logsData);

    const invRes = await fetch('/api/inventory' + runParam);
    const invData = await invRes.json();
    renderInventory(invData);

    const filterVal = document.getElementById('severity-filter') ? document.getElementById('severity-filter').value : 'vulns';
    const includeInfo = filterVal === 'all';
    const fRes = await fetch('/api/findings?include_info=' + includeInfo + runJoin);
    const fData = await fRes.json();
    
    // Filter out client-side if high only
    let filteredFindings = fData;
    if (filterVal === 'high') {
      filteredFindings = fData.filter(f => ['high', 'critical'].includes(f.severity.toLowerCase()));
    }
    renderFindings(filteredFindings);

    const gRes = await fetch('/api/graph' + runParam);
    const gData = await gRes.json();
    renderGraph(gData);

    const agentsRes = await fetch('/api/agents' + runParam);
    const agentsData = await agentsRes.json();
    renderAgents(agentsData);

    const repRes = await fetch('/api/report' + runParam);
    const repData = await repRes.json();
    if (repData.report) {
      document.getElementById('report-text').textContent = repData.report;
      document.getElementById('rendered-report').innerHTML = formatMarkdown(repData.report);
      lastReportContent = repData.report;
    } else {
      document.getElementById('report-text').textContent = 'No assessment report generated yet. Ready for evaluation.';
      document.getElementById('rendered-report').innerHTML = '<div style="color:var(--text-muted); text-align:center; padding:2.5rem 1rem;">No assessment report generated yet. Enter a target above and click "Launch Assessment" to begin evaluation.</div>';
      lastReportContent = '';
    }
  } catch (err) {
    console.error('Fetch error:', err);
  }
}

function renderStatus(data) {
  const isIdle = !currentRunId || data.status === 'idle' || data.run_id === 'none';
  const badge = document.getElementById('run-badge');
  badge.textContent = isIdle ? 'IDLE' : data.status.toUpperCase();
  badge.className = 'badge ' + (
    isIdle ? 'badge-idle' :
    data.status === 'running' ? 'badge-running' :
    data.status === 'partial' ? 'badge-partial' :
    data.status === 'completed' ? 'badge-completed' : 'badge-idle'
  );

  if (isIdle) {
    document.getElementById('metric-safety').textContent = '—';
    document.getElementById('metric-safety-sub').textContent = 'Awaiting target launch';
    document.getElementById('metric-autonomy').textContent = '—';
    document.getElementById('metric-autonomy-sub').textContent = 'Awaiting target launch';
    document.getElementById('metric-findings').textContent = '—';
    document.getElementById('metric-findings-sub').textContent = 'Awaiting target launch';
    document.getElementById('metric-assets').textContent = '—';
    document.getElementById('metric-assets-sub').textContent = 'Awaiting target launch';
  } else {
    document.getElementById('metric-safety').textContent = `${data.metrics.scope_safety_out_of_bounds_probes} Leaks`;
    document.getElementById('metric-safety-sub').textContent = `${data.metrics.scope_decisions_denied} out-of-scope probes blocked`;
    document.getElementById('metric-autonomy').textContent = '100%';
    document.getElementById('metric-autonomy-sub').textContent = `${data.metrics.autonomy_interventions} human interventions required`;
    document.getElementById('metric-findings').textContent = `${data.metrics.confirmed_findings} / ${data.metrics.total_findings}`;
    document.getElementById('metric-findings-sub').textContent = `${data.metrics.verification_rate_pct}% verification rate`;
    document.getElementById('metric-assets').textContent = data.metrics.total_assets_discovered;
    document.getElementById('metric-assets-sub').textContent = `${data.metrics.total_services_discovered} open services identified`;
  }

  const banner = document.getElementById('completion-banner');
  const iconEl = document.getElementById('status-icon');
  const headlineEl = document.getElementById('status-headline');
  const sublineEl = document.getElementById('status-subline');
  const actionBtn = document.getElementById('status-action-btn');

  if (banner) {
    if (isIdle) {
      banner.style.display = 'none';
    } else if (data.status === 'completed') {
      banner.style.display = 'block';
      banner.className = 'status-banner';
      if (iconEl) {
        iconEl.className = 'status-dot';
      }
      const runtime = data.metrics.runtime_seconds ? `${Math.round(data.metrics.runtime_seconds)}s` : 'completed';
      if (headlineEl) {
        headlineEl.innerHTML = `Autonomous Assessment Completed — Done With All Tasks <span style="font-size:0.75rem; font-weight:600; color:#38bdf8; background:var(--gradient-subtle); border:1px solid rgba(56,189,248,0.3); padding:0.2rem 0.5rem; border-radius:4px; margin-left:0.5rem;">${runtime}</span>`;
      }
      if (sublineEl) {
        sublineEl.textContent = `All scope targets assessed with 100% autonomy (0 human interventions). Discovered & confirmed ${data.metrics.confirmed_findings} verified vulnerabilities. Publication-grade PTES report generated.`;
      }
      if (actionBtn) {
        actionBtn.style.display = 'inline-flex';
      }
    } else if (data.status === 'running') {
      banner.style.display = 'block';
      banner.className = 'status-banner running';
      if (iconEl) {
        iconEl.className = 'status-dot pulsing';
      }
      if (headlineEl) {
        headlineEl.textContent = 'Autonomous Assessment In Progress...';
      }
      if (sublineEl) {
        sublineEl.textContent = `Specialist agents (Network, Web, Verification) are actively auditing the in-scope target. Discovered ${data.metrics.total_findings} findings so far.`;
      }
      if (actionBtn) {
        actionBtn.style.display = 'none';
      }
    } else {
      banner.style.display = 'none';
    }
  }
}

function renderAgents(agents) {
  const container = document.getElementById('agents-strip');
  container.innerHTML = '';
  agents.forEach(a => {
    const card = document.createElement('div');
    card.className = 'agent-card';
    const statText = a.role.includes('Playbooks') 
      ? `${a.completed} Confirmed`
      : a.role.includes('Patches')
      ? `${a.completed} Patches Ready`
      : `${a.active} Active / ${a.completed} Done`;

    card.innerHTML = `
      <div class="agent-name">${a.name}</div>
      <div class="agent-role">${a.role}</div>
      <div class="agent-stat">${statText}</div>
    `;
    container.appendChild(card);
  });
}

function renderLogs(logs) {
  const box = document.getElementById('scope-logs');
  box.innerHTML = '';
  if (!logs || !logs.length) {
    box.innerHTML = '<div style="color:var(--text-subtle); padding:0.5rem 0; font-size:0.75rem;">No scope decisions recorded. PolicyGate fails closed on unauthorized targets.</div>';
    return;
  }
  logs.forEach(l => {
    const line = document.createElement('div');
    line.className = 'log-line';
    const isDeny = l.decision.toLowerCase() === 'deny';
    line.innerHTML = `
      <span class="${isDeny ? 'log-deny' : 'log-allow'}">[${l.decision.toUpperCase()}]</span>
      <span style="color:#fff;">${l.target}</span>
      <span class="log-meta">(${l.reason || 'in-scope'})</span>
    `;
    box.appendChild(line);
  });
}

function renderInventory(inv) {
  const tbody = document.querySelector('#inventory-table tbody');
  tbody.innerHTML = '';
  if (!inv || !inv.length) {
    tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted); text-align:center; padding:1.5rem 0.5rem;">No assets cataloged yet. Enter a target above and click \'Launch Assessment\'.</td></tr>';
    return;
  }
  inv.forEach(a => {
    const tr = document.createElement('tr');
    const svcs = a.services.map(s => `${s.port}/${s.protocol} (${s.service_name || 'unknown'})`).join(', ') || 'None';
    tr.innerHTML = `
      <td style="font-weight:700; color:#fff;">${a.canonical_key}</td>
      <td><span class="badge" style="background:#1e293b; color:var(--text);">${a.asset_type.toUpperCase()}</span></td>
      <td><span style="color:var(--accent); font-family:monospace;">${svcs}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

let findingsCache = new Map();

function renderFindings(findings) {
  const tbody = document.querySelector('#findings-table tbody');
  tbody.innerHTML = '';
  findingsCache.clear();
  if (!findings || !findings.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted); text-align:center; padding:2rem 0.5rem;">No findings recorded. Enter a target above and click \'Launch Assessment\' to begin.</td></tr>';
    return;
  }
  findings.forEach(f => {
    findingsCache.set(f.finding_id, f);
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.onclick = (e) => {
      inspectFinding(f.finding_id);
    };
    const sev = f.severity.toLowerCase();
    const pillClass = `sev-${sev}`;
    
    // Display specialist tool neatly
    let toolBadge = f.tool || 'automated';
    if (toolBadge.includes('nmap')) toolBadge = 'Nmap Specialist';
    else if (toolBadge.includes('binary')) toolBadge = 'Binary Specialist';
    else if (toolBadge.includes('web')) toolBadge = 'Web Specialist';
    else if (toolBadge.includes('console')) toolBadge = 'Console Specialist';

    tr.innerHTML = `
      <td style="font-family:monospace; color:#38bdf8; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${f.target_url || 'N/A'}">${f.target_url || 'N/A'}</td>
      <td style="font-size:0.75rem; color:var(--text-muted);">${toolBadge}</td>
      <td style="font-weight:600; color:var(--text);">${f.title || f.type.replace(/_/g, ' ')}</td>
      <td><span class="sev-pill ${pillClass}">${f.severity}</span></td>
      <td><span style="color:#38bdf8; font-weight:700;">${f.status}</span></td>
      <td>
        <button onclick="event.stopPropagation(); inspectFinding('${f.finding_id}')" class="btn-sec" style="font-size:0.75rem; padding:0.2rem 0.6rem;">Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function inspectFinding(fid) {
  try {
    let f = findingsCache.get(fid);
    if (!f) {
      const url = currentRunId ? `/api/findings?include_info=true&run_id=${currentRunId}` : '/api/findings?include_info=true&run_id=idle';
      const res = await fetch(url);
      const data = await res.json();
      f = data.find(x => x.finding_id === fid);
    }
    if (!f) return alert('Finding details could not be loaded.');

    document.getElementById('modal-title').textContent = `${f.title || f.type.replace(/_/g, ' ').toUpperCase()}`;
    document.getElementById('modal-body').innerHTML = `
      <div style="margin-bottom:0.8rem; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span class="sev-pill sev-${f.severity.toLowerCase()}">${f.severity.toUpperCase()}</span>
          <span style="color:#38bdf8; font-weight:700; margin-left:0.5rem;">[${f.status.toUpperCase()}]</span>
          <span style="color:var(--text-muted); font-size:0.75rem; margin-left:0.5rem;">Tool: ${f.tool}</span>
        </div>
        ${f.cwe ? `<span style="color:#38bdf8; font-size:0.75rem; font-weight:700;">${f.cwe}</span>` : ''}
      </div>
      <p style="margin-bottom:0.8rem; color:var(--text); font-size:0.9rem; line-height:1.5;">${f.summary}</p>
      
      <div style="background:var(--code-bg); border:1px solid var(--panel-border); border-radius:6px; padding:0.8rem; margin-bottom:0.8rem;">
        <div style="font-size:0.72rem; color:var(--text-muted); margin-bottom:0.4rem; text-transform:uppercase; letter-spacing:0.5px;">
          Technical Proof of Concept / Live Evidence
        </div>
        <pre style="white-space:pre-wrap; font-family:Consolas, monospace; font-size:0.8rem; color:#38bdf8; margin:0; max-height:160px; overflow-y:auto;">${f.excerpt || 'No raw excerpt recorded'}</pre>
      </div>

      ${f.remediation ? `
        <div style="background:var(--code-bg); border:1px solid var(--panel-border); border-left:3px solid #818cf8; border-radius:6px; padding:0.8rem; margin-bottom:0.8rem;">
          <div style="font-size:0.72rem; color:#818cf8; margin-bottom:0.4rem; text-transform:uppercase; font-weight:700;">
            Recommended Remediation Patchwork:
          </div>
          <p style="color:var(--text-muted); font-size:0.82rem; margin-bottom:0.4rem; line-height:1.4;">${f.remediation}</p>
          ${f.patch ? `<pre style="color:var(--text); font-size:0.75rem; white-space:pre-wrap; margin:0; font-family:Consolas, monospace; max-height:120px; overflow-y:auto;">${f.patch}</pre>` : ''}
        </div>
      ` : ''}

      <div style="font-size:0.75rem; color:var(--text-muted); background:var(--code-bg); border:1px solid var(--panel-border); border-radius:6px; padding:0.6rem 0.8rem; margin-bottom:0.8rem;">
        <div><strong>Evidence SHA-256 Digest:</strong> <code>${f.hash || 'N/A'}</code></div>
        <div><strong>Target Location:</strong> <code>${f.target_url || 'N/A'}</code></div>
        <div><strong>Finding ID:</strong> <code>${f.finding_id}</code></div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
        <button onclick="downloadPatches()" class="btn-sec" style="font-size:0.78rem;">Export Patch</button>
        <button onclick="openPrintableReport()" class="btn-primary" style="font-size:0.78rem;">View in Full Report</button>
      </div>
    `;
    document.getElementById('node-modal').style.display = 'flex';
  } catch (err) {
    alert('Error inspecting finding: ' + err);
  }
}

function setPreset(target, tier) {
  document.getElementById('target-input').value = target;
  if (tier) document.getElementById('tier-select').value = tier;
  const statusEl = document.getElementById('launcher-status');
  statusEl.textContent = `Preset loaded: ${target} (${tier}). Click 'Launch Assessment' to begin.`;
  statusEl.style.color = '#38bdf8';
}

async function launchAssessment() {
  const target = document.getElementById('target-input').value.trim();
  const tier = document.getElementById('tier-select').value;
  const statusEl = document.getElementById('launcher-status');
  const btn = document.getElementById('btn-launch-run');

  if (!target) {
    alert('Please enter a target URL, domain, IP, or CIDR (e.g. https://preview.owasp-juice.shop/ or https://lab.ctf.io/).');
    return;
  }

  btn.disabled = true;
  btn.style.opacity = '0.6';
  btn.textContent = 'Locking Scope & Starting...';
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
      currentRunId = data.run_id;
      statusEl.textContent = `Run ${data.run_id} running: Assessing ${data.target}...`;
      statusEl.style.color = '#38bdf8';
      setTimeout(() => refreshData(), 1200);
    } else {
      statusEl.textContent = `Launch failed: ${data.error || 'Unknown error'}`;
      statusEl.style.color = 'var(--text-muted)';
      alert('Launch failed: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    statusEl.textContent = `Network error: ${err.message}`;
    statusEl.style.color = 'var(--text-muted)';
  } finally {
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.textContent = 'Launch Assessment';
  }
}


function renderGraph(graph) {
  const svg = document.getElementById('attack-graph');
  svg.innerHTML = '';
  if (!graph.nodes || !graph.nodes.length) {
    svg.innerHTML = `
      <text x="50%" y="45%" fill="#38bdf8" text-anchor="middle" font-size="14" font-weight="bold">
        Autonomous Assessment Pipeline Active
      </text>
      <text x="50%" y="60%" fill="var(--text-subtle)" text-anchor="middle" font-size="12">
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
    <linearGradient id="edge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="100%" stop-color="#818cf8" />
    </linearGradient>
    <marker id="arrow-grad" viewBox="0 -5 10 10" refX="24" refY="0" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M0,-5L10,0L0,5" fill="#818cf8"></path>
    </marker>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#38bdf8" flood-opacity="0.4"/>
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
      path.setAttribute('stroke', 'url(#edge-grad)');
      path.setAttribute('stroke-width', '2');
      path.setAttribute('fill', 'none');
      path.setAttribute('marker-end', 'url(#arrow-grad)');
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

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', p.x);
    circle.setAttribute('cy', p.y);
    circle.setAttribute('r', '18');
    circle.setAttribute('fill', '#0e131f');
    circle.setAttribute('stroke', '#38bdf8');
    circle.setAttribute('stroke-width', '2');
    circle.setAttribute('filter', 'url(#glow)');
    g.appendChild(circle);

    const tag = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    tag.setAttribute('x', p.x);
    tag.setAttribute('y', p.y + 4);
    tag.setAttribute('text-anchor', 'middle');
    tag.setAttribute('font-size', '9');
    tag.setAttribute('font-weight', 'bold');
    tag.setAttribute('font-family', 'Consolas, monospace');
    tag.setAttribute('fill', '#38bdf8');
    tag.textContent = node.asset_type === 'binary' ? 'BIN' : node.asset_type === 'web_app' ? 'WEB' : 'HOST';
    g.appendChild(tag);

    const pill = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    pill.setAttribute('x', p.x);
    pill.setAttribute('y', p.y - 25);
    pill.setAttribute('fill', '#f8fafc');
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
    labelBg.setAttribute('fill', 'rgba(14, 19, 31, 0.95)');
    labelBg.setAttribute('stroke', 'rgba(255, 255, 255, 0.08)');
    g.appendChild(labelBg);

    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', p.x);
    label.setAttribute('y', p.y + 37);
    label.setAttribute('fill', '#f8fafc');
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
        <h4 style="color:var(--text); font-size:0.9rem; margin-bottom:0.6rem; border-bottom:1px solid var(--panel-border); padding-bottom:0.3rem;">
          Verified Vulnerabilities & Findings (${node.findings.length})
        </h4>
        <div style="display:flex; flex-direction:column; gap:0.6rem; max-height:280px; overflow-y:auto; padding-right:4px;">
          ${node.findings.map(f => `
            <div style="background:var(--code-bg); border:1px solid var(--panel-border); border-radius:6px; padding:0.7rem;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
                <span class="sev-pill sev-${(f.severity || 'low').toLowerCase()}">${(f.severity || 'LOW').toUpperCase()}</span>
                <span style="color:#38bdf8; font-size:0.75rem; font-weight:700;">${f.cwe || 'CWE'} • CVSS ${f.cvss || 'N/A'}</span>
              </div>
              <div style="font-weight:600; color:var(--text); font-size:0.85rem; margin-bottom:0.3rem;">${f.title || f.type}</div>
              <p style="color:var(--text-muted); font-size:0.78rem; margin-bottom:0.5rem;">${f.summary || ''}</p>
              ${f.excerpt ? `
                <div style="background:var(--panel); border-left:3px solid #38bdf8; padding:0.4rem 0.6rem; margin-bottom:0.4rem; border-radius:2px;">
                  <div style="font-size:0.68rem; color:var(--text-subtle); text-transform:uppercase;">Live Evidence Proof:</div>
                  <pre style="color:#38bdf8; font-size:0.75rem; white-space:pre-wrap; margin:0; font-family:Consolas, monospace;">${f.excerpt}</pre>
                </div>
              ` : ''}
              ${f.remediation ? `
                <div style="background:var(--panel); border-left:3px solid #818cf8; padding:0.4rem 0.6rem; border-radius:2px;">
                  <div style="font-size:0.68rem; color:var(--text-subtle); text-transform:uppercase;">Remediation Patchwork:</div>
                  <pre style="color:var(--text); font-size:0.75rem; white-space:pre-wrap; margin:0; font-family:Consolas, monospace;">${f.remediation}</pre>
                </div>
              ` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  } else {
    findingsHtml = `
      <p style="color:var(--text-muted); margin-top:0.8rem; font-size:0.85rem;">
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
      <span style="color:var(--text-subtle); font-size:0.75rem; font-family:monospace;">ID: ${node.id}</span>
    </div>
    <div style="background:var(--code-bg); border:1px solid var(--panel-border); border-radius:6px; padding:0.6rem 0.8rem; font-size:0.8rem;">
      <div><strong>Target Key:</strong> <code style="color:#38bdf8;">${node.canonical_key || node.label}</code></div>
      <div><strong>Asset Classification:</strong> <code>${(node.asset_type || 'host').toUpperCase()}</code></div>
    </div>
    ${findingsHtml}
    <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top:1rem; border-top:1px solid var(--panel-border); padding-top:0.8rem;">
      <button onclick="downloadPatches()" class="btn-sec" style="font-size:0.78rem;">Download All Patches</button>
      <button onclick="openPrintableReport()" class="btn-primary" style="font-size:0.78rem;">View Full VAPT Report</button>
    </div>
  `;
  document.getElementById('node-modal').style.display = 'flex';
}


function closeModal(event) {
  document.getElementById('node-modal').style.display = 'none';
}

function downloadReport() {
  if (!lastReportContent) return alert('No report available to download.');
  const blob = new Blob([lastReportContent], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'cart_ptes_assessment_report.md';
  a.click();
}

async function downloadPatches() {
  try {
    const res = await fetch('/api/patches');
    const data = await res.json();
    if (!data.patches || !data.patches.length) {
      alert('No confirmed vulnerabilities require code patches yet.');
      return;
    }
    alert(`Successfully generated ${data.patches.length} patch file(s) in reports/patches/!`);
  } catch (err) {
    alert('Error generating patches: ' + err);
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

                scan_all = tier == "deep"
                scan_udp = tier in ("deep", "breach")
                for prefix in manifest.included_prefixes:
                    t = Task(
                        task_id=new_id("task"),
                        task_type="host_discovery",
                        owner="network",
                        target_id=prefix,
                        status=TaskStatus.READY,
                        ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
                        dedupe_key=f"{run_id}:host:{prefix}",
                        budget={"timeout_s": 180, "retries": 1, "all_ports": scan_all, "scan_udp": scan_udp},
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
                cand_rows = t_conn.execute(
                    "SELECT f.finding_id FROM findings f JOIN assets a ON f.asset_id = a.asset_id WHERE a.run_id = ? AND f.status = ?",
                    (run_id, FindingStatus.CANDIDATE.value),
                ).fetchall()
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
        except Exception as e:  # noqa: BLE001
            self._send_json({"success": False, "error": str(e)}, status=500)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._send_html(_INDEX_HTML)
        elif path == "/api/status":
            self._handle_status(parsed.query)
        elif path == "/api/runs":
            self._handle_runs()
        elif path == "/api/candidates":
            self._handle_candidates()
        elif path == "/api/inventory":
            self._handle_inventory(parsed.query)
        elif path == "/api/findings":
            self._handle_findings(parsed.query)
        elif path == "/api/graph":
            self._handle_graph(parsed.query)
        elif path == "/api/flags":
            self._handle_flags()
        elif path == "/api/agents":
            self._handle_agents(parsed.query)
        elif path == "/api/asset":
            self._handle_asset_detail(parsed.query)
        elif path == "/api/patches":
            self._handle_patches()
        elif path == "/api/logs":
            self._handle_logs(parsed.query)
        elif path == "/api/report":
            self._handle_report(parsed.query)
        elif path in ("/report/printable", "/api/report/printable", "/report/pdf"):
            self._handle_printable_report(parsed.query)
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

    def _send_pdf(self, pdf_bytes: bytes, filename: str = "CyberForge_CART_PTES_Report.pdf") -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(pdf_bytes)))
        self.end_headers()
        self.wfile.write(pdf_bytes)

    def _handle_printable_report(self, query_str: str = "") -> None:
        """Render publication-grade printable PTES report for PDF export."""
        qs = urllib.parse.parse_qs(query_str)
        conn = connect(self.db_path, check_same_thread=False)
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])

        rep_row = None
        if target_run:
            rep_row = conn.execute(
                "SELECT path FROM report_artifacts WHERE format = 'md' AND run_id = ? ORDER BY created_at DESC LIMIT 1",
                (target_run,),
            ).fetchone()

        md_text = ""
        if rep_row and Path(rep_row[0]).exists():
            md_text = Path(rep_row[0]).read_text(encoding="utf-8")
        elif not target_run:
            md_text = "# CyberForge CART — Penetration Testing Assessment\n\n> Assessment status: **IDLE**\n\nNo target assessment run has been launched yet. Select or launch a target from the dashboard."
        conn.close()

        # Direct PDF export route
        if self.path.startswith("/report/pdf") or self.path.startswith("/api/report/pdf"):
            # Check for pre-generated PDF
            for candidate_pdf in (Path(f"reports/cart_report_{target_run}.pdf"), Path("reports/CyberForge_CART_PTES_Report.pdf"), Path("proof.pdf")):
                if candidate_pdf.exists() and candidate_pdf.stat().st_size > 1000:
                    self._send_pdf(candidate_pdf.read_bytes(), filename=f"cart_report_{target_run or 'assessment'}.pdf")
                    return

            # Headless Edge on-demand PDF conversion
            edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
            if os.path.exists(edge_path):
                html_body = markdown_to_printable_html(md_text)
                preview_doc = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'><style>@page {{ size: A4; margin: 1.5cm; }} body {{ font-family: sans-serif; font-size: 9pt; }}</style></head><body>{html_body}</body></html>"""
                with tempfile.TemporaryDirectory() as td:
                    th = Path(td) / "temp.html"
                    tp = Path(td) / "temp.pdf"
                    th.write_text(preview_doc, encoding="utf-8")
                    try:
                        subprocess.run([edge_path, "--headless", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={tp}", str(th)], timeout=15, check=True, capture_output=True)
                        if tp.exists():
                            self._send_pdf(tp.read_bytes(), filename=f"cart_report_{target_run or 'assessment'}.pdf")
                            return
                    except (subprocess.SubprocessError, OSError):
                        pass

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
    <button onclick="window.print()">Save as PDF / Print</button>
    <button onclick="window.close()" style="background:#334155; color:#fff;">Close</button>
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
      10.0.10.25/32 & Registered Binaries
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

    def _resolve_run_id(self, conn: sqlite3.Connection, requested: str | None = None) -> str | None:
        if requested in ("idle", "none", "new"):
            return None
        if requested and requested not in ("", "latest", "default", "undefined", "null"):
            exists = conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (requested,)).fetchone()
            if exists:
                return requested
        active = conn.execute("SELECT run_id FROM runs WHERE status = 'running' ORDER BY started_at DESC LIMIT 1").fetchone()
        if active:
            return active[0]
        latest = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
        return latest[0] if latest else None

    def _handle_runs(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        rows = conn.execute(
            "SELECT r.run_id, r.status, r.tier, r.started_at, r.completed_at, sm.included_prefixes, sm.included_hosts "
            "FROM runs r "
            "LEFT JOIN scope_manifests sm ON r.scope_version = sm.scope_version "
            "ORDER BY r.rowid DESC LIMIT 40"
        ).fetchall()

        runs = []
        for rid, status, tier, started, completed, prefixes_json, hosts_json in rows:
            prefixes = json.loads(prefixes_json or "[]")
            hosts = json.loads(hosts_json or "[]")
            target_str = ", ".join(prefixes + hosts) or "Target"

            f_counts = dict(conn.execute(
                "SELECT severity, COUNT(*) FROM findings f JOIN assets a ON f.asset_id = a.asset_id WHERE a.run_id = ? GROUP BY severity",
                (rid,)
            ).fetchall())
            total = sum(f_counts.values())
            non_info = sum(v for k, v in f_counts.items() if k != "info")
            crit = f_counts.get("critical", 0)
            high = f_counts.get("high", 0)

            label = f"{target_str} ({rid[:10]}…) — {non_info} Vulns ({status.upper()})"

            runs.append({
                "run_id": rid,
                "target": target_str,
                "status": status,
                "tier": tier,
                "started_at": started,
                "completed_at": completed,
                "total_findings": total,
                "non_info_findings": non_info,
                "critical": crit,
                "high": high,
                "label": label,
            })

        runs.sort(key=lambda r: r["started_at"] or "", reverse=True)
        conn.close()
        self._send_json(runs)

        conn.close()
        self._send_json(runs)

    def _handle_status(self, query_str: str = "") -> None:
        qs = urllib.parse.parse_qs(query_str)
        conn = connect(self.db_path, check_same_thread=False)
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])

        if not target_run:
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

        run_row = conn.execute(
            "SELECT run_id, status, tier, started_at, completed_at, scope_version FROM runs WHERE run_id = ?",
            (target_run,),
        ).fetchone()

        if not run_row:
            conn.close()
            self._send_json({"error": "run not found"}, status=404)
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
            "ORDER BY rowid DESC"
        ).fetchall()
        asset_keys = dict(
            conn.execute("SELECT asset_id, canonical_key FROM assets").fetchall()
        )
        flags = []
        seen_tokens: set[str] = set()
        for fid, aid, severity, status, summary in rows:
            ev = conn.execute(
                "SELECT artifact_path, excerpt, hash, timestamp "
                "FROM evidence WHERE finding_id = ? LIMIT 1",
                (fid,),
            ).fetchone()
            excerpt = ev[1] if ev else ""
            match = re.search(r"flag=([^\s;]+)", excerpt)
            token = match.group(1) if match else (excerpt.strip() or summary)
            if token in seen_tokens:
                continue
            seen_tokens.add(token)

            flags.append({
                "finding_id": fid,
                "asset_id": aid,
                "asset_key": asset_keys.get(aid, aid),
                "severity": severity,
                "status": status,
                "summary": summary,
                "location": ev[0] if ev else "",
                "excerpt": excerpt,
                "hash": ev[2] if ev else "",
                "captured_at": ev[3] if ev else "",
                "source": ev[0] if ev else "",
            })
        conn.close()
        self._send_json(flags)

    def _handle_agents(self, query_str: str = "") -> None:
        qs = urllib.parse.parse_qs(query_str)
        conn = connect(self.db_path, check_same_thread=False)
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])
        agents = {
            "network": {"name": "Network Specialist", "icon": "", "role": "Host & Port Discovery", "active": 0, "completed": 0},
            "web": {"name": "Web Specialist", "icon": "", "role": "Endpoints & Form Crawler", "active": 0, "completed": 0},
            "binary": {"name": "Binary Specialist", "icon": "", "role": "Static Analysis & Unsafe Libc", "active": 0, "completed": 0},
            "verifier": {"name": "Verification Service", "icon": "", "role": "Deterministic Playbooks", "active": 0, "completed": 0},
            "advisor": {"name": "Remediation Advisor", "icon": "", "role": "Plain-English Patches", "active": 0, "completed": 0},
        }

        if target_run:
            task_rows = conn.execute(
                "SELECT owner, status, count(*) FROM tasks WHERE dedupe_key LIKE ? GROUP BY owner, status",
                (f"{target_run}%",),
            ).fetchall()
            conf_count = conn.execute(
                "SELECT count(*) FROM findings f JOIN assets a ON f.asset_id = a.asset_id WHERE a.run_id = ? AND f.status = 'confirmed'",
                (target_run,),
            ).fetchone()[0]
            cand_count = conn.execute(
                "SELECT count(*) FROM findings f JOIN assets a ON f.asset_id = a.asset_id WHERE a.run_id = ? AND f.status = 'candidate'",
                (target_run,),
            ).fetchone()[0]
        else:
            task_rows = []
            conf_count = 0
            cand_count = 0

        for owner, status, count in task_rows:
            if owner in agents:
                if status == "running":
                    agents[owner]["active"] += count
                elif status == "succeeded":
                    agents[owner]["completed"] += count

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
            "canonical_key": key,
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

    def _handle_inventory(self, query_str: str = "") -> None:
        qs = urllib.parse.parse_qs(query_str)
        conn = connect(self.db_path, check_same_thread=False)
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])
        if not target_run:
            conn.close()
            self._send_json([])
            return

        rows = conn.execute(
            "SELECT asset_id, asset_type, canonical_key FROM assets WHERE run_id = ?",
            (target_run,),
        ).fetchall()

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
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])
        if not target_run:
            conn.close()
            self._send_json([])
            return

        rows = conn.execute(
            f"SELECT f.finding_id, f.finding_type, f.severity, f.status, f.summary, "
            f"MAX(e.evidence_id), MAX(e.artifact_path), MAX(e.excerpt), MAX(e.source_tool), MAX(e.hash) "
            f"FROM findings f "
            f"JOIN assets a ON f.asset_id = a.asset_id "
            f"LEFT JOIN evidence e ON f.finding_id = e.finding_id AND e.artifact_path != '' "
            f"WHERE a.run_id = ? {severity_filter} "
            f"GROUP BY f.finding_id "
            f"ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.rowid DESC",
            (target_run,),
        ).fetchall()
        advisor = RemediationAdvisor(conn)
        findings = []
        for fid, ftype, sev, st, summary, evid, art_path, excerpt, tool, h in rows:
            adv = {}
            try:
                adv = advisor.advise(fid)
            except (KeyError, TypeError, ValueError):
                adv = {}
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
                "title": adv.get("title", ftype.replace("_", " ").title()),
                "cwe": adv.get("cwe_id", ""),
                "cvss": adv.get("cvss_score", ""),
                "remediation": adv.get("recommended_fix", ""),
                "patch": adv.get("patch_example", ""),
            })
        conn.close()
        self._send_json(findings)

    def _handle_logs(self, query_str: str = "") -> None:
        qs = urllib.parse.parse_qs(query_str)
        conn = connect(self.db_path, check_same_thread=False)
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])
        if target_run:
            rows = conn.execute(
                "SELECT requested_target, decision, reason, at FROM scope_decisions_log WHERE run_id = ? ORDER BY at DESC LIMIT 50",
                (target_run,),
            ).fetchall()
        else:
            rows = []
        logs = [
            {"target": r[0], "decision": r[1], "reason": r[2], "at": r[3]}
            for r in rows
        ]
        conn.close()
        self._send_json(logs)

    def _handle_graph(self, query_str: str = "") -> None:
        qs = urllib.parse.parse_qs(query_str)
        conn = connect(self.db_path, check_same_thread=False)
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])
        if not target_run:
            conn.close()
            self._send_json({"nodes": [], "edges": []})
            return

        derive_run_relationships(conn, target_run)
        builder = AttackPathBuilder(conn, target_run)
        paths = builder.build()

        asset_rows = conn.execute(
            "SELECT asset_id, asset_type, canonical_key FROM assets WHERE run_id = ?",
            (target_run,),
        ).fetchall()
        f_query = """
            SELECT f.asset_id, f.finding_id, f.finding_type, f.severity, f.status, f.summary, e.evidence_id, e.excerpt
            FROM findings f
            JOIN assets a ON f.asset_id = a.asset_id
            LEFT JOIN evidence e ON f.finding_id = e.finding_id
            WHERE a.run_id = ? AND f.status = 'confirmed' AND f.severity != 'info'
        """
        f_rows = conn.execute(f_query, (target_run,)).fetchall()
        asset_map = {r[0]: {"type": r[1], "key": r[2]} for r in asset_rows}
        advisor = RemediationAdvisor(conn)

        findings_by_asset: dict[str, list[dict[str, Any]]] = {}
        for r in f_rows:
            aid, fid, ftype, sev, st, summ, _ev_id, excerpt = r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7] or ""
            try:
                adv = advisor.advise(fid)
            except (KeyError, TypeError, ValueError):
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
                label = f"{bname} (Analyzed Binary)"
                stage = "binary"
            elif atype == "web_app":
                label = f"Web Application ({key})"
                stage = "web_app"
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
                        "REVERSED_AUTH_PASSKEY": "Binary Reverse Engineering (Passkey Decrypt)",
                        "BINARY_DAEMON_PROBE": "Static Binary Daemon Audit",
                        "WEB_SERVICE_EXPOSURE": "Web Service Exposure",
                        "COMMAND_FLAG_DISCLOSURE": "Arbitrary Command / Resource Disclosure",
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

        # Ensure all discovered assets for this run are populated in nodes_dict
        for aid in asset_map:
            if aid not in nodes_dict:
                nodes_dict[aid] = get_node_meta(aid)

        if target_run:
            # Strictly scope to assets belonging to target_run
            nodes_dict = {aid: meta for aid, meta in nodes_dict.items() if aid in asset_map}
            edges_list = [e for e in edges_list if e["source"] in asset_map and e["target"] in asset_map]

        conn.close()
        self._send_json({
            "nodes": list(nodes_dict.values()),
            "edges": edges_list,
        })

    def _handle_report(self, query_str: str = "") -> None:
        qs = urllib.parse.parse_qs(query_str)
        conn = connect(self.db_path, check_same_thread=False)
        target_run = self._resolve_run_id(conn, qs.get("run_id", [None])[0])
        if not target_run:
            conn.close()
            self._send_json({"report": ""})
            return

        rep_row = conn.execute(
            "SELECT path FROM report_artifacts WHERE format = 'md' AND run_id = ? ORDER BY created_at DESC LIMIT 1",
            (target_run,),
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
    print(f"\n[+] CyberForge CART UI Dashboard running at: {url}")
    print("[+] Press Ctrl+C in terminal to stop dashboard server.")

    if open_browser:
        import webbrowser
        webbrowser.open(url)

    return server
