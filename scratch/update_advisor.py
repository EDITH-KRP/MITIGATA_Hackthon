import re

with open('src/cart/advisor.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Fields to inject into advise()
advise_target = '''        template = _PATCH_EXAMPLES.get(finding_type, _DEFAULT_TEMPLATE)
        advisory: dict[str, str] = {
            "finding_id": finding_id,
            "title": template["title"],
            "plain_english_summary": template["plain_english_summary"],
            "impact": template["impact"],
            "recommended_fix": template["recommended_fix"],
            "patch_example": template["patch_example"],
        }'''

advise_repl = '''        template = _PATCH_EXAMPLES.get(finding_type, _DEFAULT_TEMPLATE)
        advisory: dict[str, str] = {
            "finding_id": finding_id,
            "title": template["title"],
            "plain_english_summary": template["plain_english_summary"],
            "impact": template["impact"],
            "recommended_fix": template["recommended_fix"],
            "patch_example": template["patch_example"],
            "cwe_id": template.get("cwe_id", "CWE-699"),
            "cvss_score": template.get("cvss_score", "7.5"),
            "cvss_vector": template.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            "threat_vector": template.get("threat_vector", "Remote Network / Unauthenticated"),
            "reproduction_command": template.get("reproduction_command", "curl -v http://<target>/"),
            "verification_test": template.get("verification_test", "curl -v --fail http://<target>/"),
        }'''

if advise_target in text:
    text = text.replace(advise_target, advise_repl, 1)

# Mapping of finding types to extra fields
vapt_meta = {
    "unencrypted_cleartext_service": {
        "cwe_id": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "threat_vector": "Adjacent Network / Remote Eavesdropping (Man-in-the-Middle)",
        "reproduction_command": "curl -v http://{target}:{port}/",
        "verification_test": "curl -v --fail --tlsv1.3 https://{target}:{port}/",
    },
    "non_standard_service_port": {
        "cwe_id": "CWE-200 (Exposure of Sensitive Information)",
        "cvss_score": "5.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "threat_vector": "Remote Network / Service Fingerprinting",
        "reproduction_command": "nc -zv {target} {port}",
        "verification_test": "nmap -sT -p {port} {target} -oG - | grep -i closed",
    },
    "network_service_fingerprint": {
        "cwe_id": "CWE-200 (Exposure of Sensitive System Details)",
        "cvss_score": "5.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "threat_vector": "Remote Network / Automated Banner Reconnaissance",
        "reproduction_command": "nc -nv {target} {port}",
        "verification_test": "printf 'QUIT\\n' | nc {target} {port}",
    },
    "cleartext_http_authentication": {
        "cwe_id": "CWE-523 (Unprotected Transport of Credentials) / CWE-319",
        "cvss_score": "8.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "threat_vector": "Network Interception / Credential Sniffing",
        "reproduction_command": "curl -i -u admin:test http://{target}:{port}/",
        "verification_test": "curl -i http://{target}:{port}/ -o /dev/null -w '%{http_code}' | grep 301",
    },
    "insecure_cookie_attributes": {
        "cwe_id": "CWE-614 (Sensitive Cookie in HTTPS Without Secure Flag) / CWE-1004",
        "cvss_score": "6.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "threat_vector": "Cross-Site Scripting (XSS) / Session Hijacking",
        "reproduction_command": "curl -i http://{target}/ | grep -i Set-Cookie",
        "verification_test": "curl -sI https://{target}/ | grep -E 'Secure;.*HttpOnly;.*SameSite=(Strict|Lax)'",
    },
    "missing_security_headers": {
        "cwe_id": "CWE-693 (Protection Mechanism Failure)",
        "cvss_score": "6.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "threat_vector": "Clickjacking / MIME Sniffing / Cross-Site Scripting",
        "reproduction_command": "curl -sI http://{target}/",
        "verification_test": "curl -sI https://{target}/ | grep -E '(Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)'",
    },
    "server_banner_disclosure": {
        "cwe_id": "CWE-200 (Exposure of Software Version Information)",
        "cvss_score": "5.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "threat_vector": "Automated Exploit Targeting / CVE Mapping",
        "reproduction_command": "curl -sI http://{target}/ | grep -i Server",
        "verification_test": "curl -sI https://{target}/ | grep -v -i 'Server: [a-zA-Z]'",
    },
    "web_form_endpoint": {
        "cwe_id": "CWE-352 (Cross-Site Request Forgery) / CWE-89 (SQL Injection Risk)",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "threat_vector": "Unauthenticated Form Submission / CSRF Impersonation",
        "reproduction_command": "curl -X POST -d 'username=admin&password=123' http://{target}/login",
        "verification_test": "curl -X POST -d 'username=admin&password=123' https://{target}/login -w '%{http_code}' | grep 403",
    },
    "binary_unsafe_function": {
        "cwe_id": "CWE-120 (Classic Buffer Overflow) / CWE-676 (Dangerous Function)",
        "cvss_score": "9.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "threat_vector": "Local / Remote Binary Exploitation / Control Flow Hijacking",
        "reproduction_command": "python3 -c 'print(\"A\"*512)' | ./binary",
        "verification_test": "nm -D target_binary | grep -E '(gets|strcpy|sprintf|system)' || echo 'No unsafe symbols'",
    },
    "binary_hardcoded_credential": {
        "cwe_id": "CWE-798 (Use of Hard-coded Credentials)",
        "cvss_score": "8.2",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "threat_vector": "Reverse Engineering / Static Secret Extraction",
        "reproduction_command": "strings -a target_binary | grep -E '(password|auth|secret|admin)'",
        "verification_test": "strings -a target_binary | grep -i 'secret' || echo 'Clean binary'",
    },
    "ctf_planted_flag": {
        "cwe_id": "CWE-200 (Exposure of Sensitive Information) / CWE-532",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "threat_vector": "Direct Object Exfiltration / Privilege Token Harvest",
        "reproduction_command": "curl -s http://{target}/path_with_flag",
        "verification_test": "curl -s http://{target}/path_with_flag | grep -v 'flag{'",
    },
    "reverse_proxy_ip_spoofing": {
        "cwe_id": "CWE-290 (Authentication Bypass by Spoofing) / CWE-345",
        "cvss_score": "9.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "threat_vector": "Remote Unauthenticated Reverse Proxy Header Injection",
        "reproduction_command": "curl -H 'X-Forwarded-For: 192.168.60.1' http://{target}/",
        "verification_test": "curl -i -H 'X-Forwarded-For: 192.168.60.1' http://{target}/ | grep '403 Forbidden'",
    },
    "unauthenticated_artifact_vault_exposure": {
        "cwe_id": "CWE-552 (Files or Directories Accessible to External Parties) / CWE-548",
        "cvss_score": "8.6",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "threat_vector": "Unauthenticated Directory Traversal & Proprietary Build Extraction",
        "reproduction_command": "curl -s http://{target}/vault/",
        "verification_test": "curl -sI http://{target}/vault/ | grep -E '(401 Unauthorized|403 Forbidden)'",
    },
    "weak_reversible_binary_passkey": {
        "cwe_id": "CWE-259 (Hard-coded Password) / CWE-327 (Broken Crypto Algorithm)",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "threat_vector": "Offline Cryptanalysis / Binary Disassembly of Validation Table",
        "reproduction_command": "objdump -d -j .text keykeeper | grep -A 20 '<main>'",
        "verification_test": "test client communicates with server over TLS with mutual auth",
    },
    "unauthenticated_console_service": {
        "cwe_id": "CWE-284 (Improper Access Control) / CWE-306",
        "cvss_score": "8.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "threat_vector": "Direct TCP Interactive Console Access without Transport Security",
        "reproduction_command": "nc {target} 8833",
        "verification_test": "nc -z -w 2 {target} 8833 || echo 'Port 8833 filtered/closed'",
    },
    "flag_disclosure_pidreq": {
        "cwe_id": "CWE-639 (Insecure Direct Object Reference) / CWE-200",
        "cvss_score": "9.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "threat_vector": "Arbitrary File Dereference / Memory-mapped Path Disclosure",
        "reproduction_command": "printf 'PIDREQ 58554 /Desktop/flag e068\\n' | nc {target} 8833",
        "verification_test": "printf 'PIDREQ 58554 /etc/passwd 0000\\n' | nc {target} 8833 | grep 'INVALID_PATH'",
    },
}

for ftype, meta in vapt_meta.items():
    pattern = rf'("{ftype}":\s*\{{)'
    m = re.search(pattern, text)
    if m:
        repl = m.group(1) + f"""
        "cwe_id": "{meta['cwe_id']}",
        "cvss_score": "{meta['cvss_score']}",
        "cvss_vector": "{meta['cvss_vector']}",
        "threat_vector": "{meta['threat_vector']}",
        "reproduction_command": "{meta['reproduction_command']}",
        "verification_test": "{meta['verification_test']}",
"""
        text = text[:m.start()] + repl + text[m.end():]

with open('src/cart/advisor.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Successfully updated advisor.py with VAPT metadata!')
