with open('src/cart/ui.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''    <button id="btn-launch-run" onclick="launchAssessment()" class="btn-primary" style="padding:0.6rem 1.4rem; font-size:0.88rem; display:flex; align-items:center; gap:0.5rem;">
      <span>🚀</span>
      <span>Launch Autonomous Run</span>
    </button>
  </div>
</div>'''

repl = '''    <button id="btn-launch-run" onclick="launchAssessment()" class="btn-primary" style="padding:0.6rem 1.4rem; font-size:0.88rem; display:flex; align-items:center; gap:0.5rem;">
      <span>🚀</span>
      <span>Launch Autonomous Run</span>
    </button>
  </div>
  <div style="display:flex; gap:0.5rem; margin-top:0.7rem; align-items:center; flex-wrap:wrap;">
    <span style="font-size:0.75rem; color:#64748b; font-weight:600;">⚡ Quick Target Presets:</span>
    <button type="button" onclick="setPreset('http://192.168.60.139/', 'deep')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">🎯 Mitigata Port 80 (Full Lab)</button>
    <button type="button" onclick="setPreset('http://192.168.60.139:1111/', 'deep')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">🔒 Port 1111 (Basic Auth)</button>
    <button type="button" onclick="setPreset('192.168.60.0/24', 'recon')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">🌐 192.168.60.0/24 Subnet</button>
    <button type="button" onclick="setPreset('http://127.0.0.1:8080/', 'recon')" class="btn-sec" style="font-size:0.75rem; padding:0.25rem 0.65rem;">💻 Localhost Assessment</button>
  </div>
</div>'''

if target in text:
    text = text.replace(target, repl, 1)

# Add setPreset to JS
js_target = 'async function launchAssessment() {'
js_repl = '''function setPreset(target, tier) {
  document.getElementById('target-input').value = target;
  if (tier) document.getElementById('tier-select').value = tier;
  const statusEl = document.getElementById('launcher-status');
  statusEl.textContent = `Preset loaded: ${target}. Click 'Launch Autonomous Run' to start.`;
  statusEl.style.color = '#38bdf8';
}

async function launchAssessment() {'''

if js_target in text and 'function setPreset' not in text:
    text = text.replace(js_target, js_repl, 1)

with open('src/cart/ui.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated UI with Quick Target Presets!')

