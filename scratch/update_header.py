with open("src/cart/ui.py", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Add .btn-primary-pdf style
old_btn_css = "button.btn-sec:hover { background: var(--panel-border); }"
new_btn_css = """button.btn-sec:hover { background: var(--panel-border); }
button.btn-primary-pdf {
  background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
  color: #000;
  border: none;
  padding: 0.5rem 1.15rem;
  border-radius: 6px;
  font-weight: 800;
  cursor: pointer;
  font-size: 0.85rem;
  letter-spacing: 0.5px;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
  transition: all 0.2s;
}
button.btn-primary-pdf:hover {
  background: linear-gradient(135deg, #22d3ee 0%, #60a5fa 100%);
  box-shadow: 0 0 22px rgba(6, 182, 212, 0.65);
  transform: translateY(-1px);
}"""
assert old_btn_css in text, "old_btn_css not found"
text = text.replace(old_btn_css, new_btn_css)

# 2. Update Header: Replace timer and Export Patches with prominent DOWNLOAD PDF button
old_header = """<header>
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
</header>"""

new_header = """<header>
  <div class="logo">
    ⚡ <span>CyberForge</span> CART
    <span id="run-badge" class="badge badge-idle">IDLE</span>
    <span style="font-size:0.75rem; color:var(--text-muted); font-weight:400; margin-left:0.5rem;">Autonomous VAPT Assessment Engine</span>
  </div>
  <div style="display:flex; gap:0.6rem; align-items:center;">
    <button onclick="openPrintableReport()" class="btn-primary-pdf">📄 DOWNLOAD PDF</button>
    <button onclick="refreshData()" class="btn-sec">↻ Refresh</button>
  </div>
</header>"""
assert old_header in text, "old_header not found"
text = text.replace(old_header, new_header)

# 3. Update report tab header buttons to include Export Patches neatly
old_rep_header = """      <div style="display:flex; gap:0.5rem; align-items:center;">
        <button onclick="openPrintableReport()" class="btn-sec" style="color:var(--accent); border-color:var(--accent); font-size:0.75rem; padding:0.25rem 0.6rem; font-weight:700;">📄 Download / Print as PDF</button>
        <button onclick="downloadReport()" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.6rem;">📥 Download Markdown</button>
      </div>"""

new_rep_header = """      <div style="display:flex; gap:0.5rem; align-items:center;">
        <button onclick="openPrintableReport()" class="btn-primary-pdf" style="font-size:0.75rem; padding:0.25rem 0.65rem;">📄 DOWNLOAD PDF</button>
        <button onclick="downloadReport()" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.6rem;">📥 Download Markdown</button>
        <button onclick="downloadPatches()" class="btn-sec" style="color:var(--green); border-color:var(--green); font-size:0.75rem; padding:0.25rem 0.6rem;">💾 Export Patches</button>
      </div>"""
assert old_rep_header in text, "old_rep_header not found"
text = text.replace(old_rep_header, new_rep_header)

with open("src/cart/ui.py", "w", encoding="utf-8") as f:
    f.write(text)

print("Successfully updated ui.py header!")

