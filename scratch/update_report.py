with open('src/cart/report.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Update advisory_data in _collect_data
adv_target = '''            try:
                adv = self.advisor.advise(fid)
                advisory_data = {
                    "title": adv.get("title", ftype.replace("_", " ").title()),
                    "summary": adv.get("recommended_fix", summary),
                    "plain_english": adv.get("plain_english_summary", summary),
                    "impact": adv.get("impact", ""),
                    "remediation_patch": adv.get("patch_example", ""),
                    "references": [],
                }'''

adv_repl = '''            try:
                adv = self.advisor.advise(fid)
                advisory_data = {
                    "title": adv.get("title", ftype.replace("_", " ").title()),
                    "summary": adv.get("recommended_fix", summary),
                    "plain_english": adv.get("plain_english_summary", summary),
                    "impact": adv.get("impact", ""),
                    "remediation_patch": adv.get("patch_example", ""),
                    "cwe_id": adv.get("cwe_id", "CWE-699 (Software Security Flaw)"),
                    "cvss_score": adv.get("cvss_score", "7.5"),
                    "cvss_vector": adv.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
                    "threat_vector": adv.get("threat_vector", "Remote Network / Unauthenticated"),
                    "reproduction_command": adv.get("reproduction_command", "curl -v http://<target>/"),
                    "verification_test": adv.get("verification_test", "curl -v --fail http://<target>/"),
                    "references": [],
                }'''

if adv_target in text:
    text = text.replace(adv_target, adv_repl, 1)

# 2. Update markdown rendering in Phase 4
render_target = '''            md.extend([
                f"### 4.{idx}. {title}",
                "",
                f"- **Finding ID:** `{f['finding_id']}`",
                f"- **Severity:** **{badge}** | **Status:** `{f['status'].upper()}` | **Confidence:** `{f['confidence'].upper()}`",
                f"- **Vulnerability Category:** `{f['type']}`",
                f"- **PTES Phase:** `{f['ptes_phase']}`",
                f"- **Affected Endpoint / Asset:** `{loc}`",
                "",
                "#### Technical Overview",
                adv.get("plain_english", f["summary"]),
                "",
                "#### How and Where It Was Found (Proof of Concept)",
                f"- **Detection Vector:** Discovered autonomously by specialist worker `{tool}`.",
                f"- **Target Location:** `{loc}`",
                "- **Live Verification Excerpt:**",
                "```",
                f"{excerpt}",
                "```",
                f"- **Cryptographic Evidence Digest:** `SHA-256: {ev_hash}...`",
                "",
                "#### How It Can Be Patched (VAPT Expert Remediation)",
                adv.get("summary", "Apply defensive configuration and boundary validation."),
                "",
            ])

            patch = adv.get("remediation_patch", "")
            if patch:
                md.extend([
                    "**Actionable Remediation Patch / Configuration:**",
                    patch if patch.startswith("```") else f"```\\n{patch}\\n```",
                    "",
                ])

            md.append("---")
            md.append("")'''

render_repl = '''            cwe = adv.get("cwe_id", "CWE-699")
            cvss_sc = adv.get("cvss_score", "7.5")
            cvss_vec = adv.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
            threat_vec = adv.get("threat_vector", "Remote Network")
            repro_cmd = adv.get("reproduction_command", f"curl -v {loc}")
            verif_cmd = adv.get("verification_test", f"curl -v --fail {loc}")

            md.extend([
                f"### 4.{idx}. {title}",
                "",
                f"- **Finding ID:** `{f['finding_id']}`",
                f"- **Severity Rating:** **{badge}** (CVSS v3.1: `{cvss_sc}`) | **Status:** `{f['status'].upper()}` | **Confidence:** `{f['confidence'].upper()}`",
                f"- **Standard Classification:** `{cwe}`",
                f"- **CVSS v3.1 Vector:** `{cvss_vec}`",
                f"- **Threat Actor Vector:** `{threat_vec}`",
                f"- **Affected Endpoint / Asset:** `{loc}`",
                f"- **Vulnerability Category:** `{f['type']}`",
                "",
                "#### Technical Vulnerability Overview",
                adv.get("plain_english", f["summary"]),
                "",
                "#### How and Where It Was Found (Technical Proof of Concept)",
                f"- **Autonomous Detection Vector:** Discovered autonomously by specialist worker `{tool}`.",
                f"- **Target Location:** `{loc}`",
                "- **Step-by-Step Reproduction Command:**",
                "```bash",
                f"{repro_cmd}",
                "```",
                "- **Live Exploitation / Verification Excerpt:**",
                "```",
                f"{excerpt}",
                "```",
                f"- **Cryptographic Evidence Digest:** `SHA-256: {ev_hash}...`",
                "",
                "#### How It Can Be Patched (VAPT Expert Remediation & Hardening)",
                adv.get("summary", "Apply defensive configuration and boundary validation."),
                "",
            ])

            patch = adv.get("remediation_patch", "")
            if patch:
                md.extend([
                    "**Actionable Remediation Patch / Hardened Configuration:**",
                    patch if patch.startswith("```") else f"```\\n{patch}\\n```",
                    "",
                ])

            md.extend([
                "**Post-Fix Verification Test Command:**",
                "```bash",
                f"{verif_cmd}",
                "```",
                "",
                "---",
                "",
            ])'''

if render_target in text:
    text = text.replace(render_target, render_repl, 1)

with open('src/cart/report.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Successfully updated report.py!')

