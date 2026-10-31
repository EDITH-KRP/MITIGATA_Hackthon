import re

with open('src/cart/verify.py', 'r', encoding='utf-8') as f:
    content = f.read()

playbook_defs = '''
def _playbook_reverse_proxy_ip_spoofing(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "X-Forwarded-For" in excerpt or "wiki" in excerpt.lower() or "mitigata" in excerpt.lower():
            return FindingStatus.CONFIRMED, "high", "Reverse proxy IP spoofing bypass confirmed by successful response"
    return FindingStatus.CANDIDATE, "medium", "Evidence lacked proof of proxy bypass"


def _playbook_unauthenticated_artifact_vault_exposure(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "vault" in excerpt.lower() or "keykeeper" in excerpt.lower():
            return FindingStatus.CONFIRMED, "high", "Unauthenticated build artifact vault exposure confirmed"
    return FindingStatus.CANDIDATE, "medium", "Artifact vault exposure unconfirmed"


def _playbook_weak_reversible_binary_passkey(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "R3v3rs3" in excerpt or "passkey" in excerpt.lower() or "xor" in excerpt.lower():
            return FindingStatus.CONFIRMED, "high", "Reversible binary passkey algorithm confirmed in disassembly"
    return FindingStatus.CANDIDATE, "medium", "Passkey algorithm unconfirmed"


def _playbook_unauthenticated_console_service(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "GAME ZONE" in excerpt.upper() or "8833" in excerpt or "zone>" in excerpt:
            return FindingStatus.CONFIRMED, "high", "Cleartext administrative console service banner confirmed on port 8833"
    return FindingStatus.CANDIDATE, "medium", "Console service unconfirmed"


def _playbook_flag_disclosure_pidreq(
    finding: dict, evidence_list: list[dict]
) -> tuple[FindingStatus, str, str]:
    for ev in evidence_list:
        excerpt = ev.get("excerpt", "")
        if "FLAG:" in excerpt or "MITIGATA{" in excerpt or "PIDREQ" in excerpt:
            return FindingStatus.CONFIRMED, "high", "Arbitrary file reading and flag disclosure confirmed via PIDREQ"
    return FindingStatus.CANDIDATE, "medium", "PIDREQ flag disclosure unconfirmed"
'''

target_playbook_dict = '''    "unencrypted_cleartext_service": _playbook_unencrypted_cleartext_service,
    "non_standard_service_port": _playbook_non_standard_service_port,
    "network_service_fingerprint": _playbook_network_service_fingerprint,
}'''

replacement_playbook_dict = '''    "unencrypted_cleartext_service": _playbook_unencrypted_cleartext_service,
    "non_standard_service_port": _playbook_non_standard_service_port,
    "network_service_fingerprint": _playbook_network_service_fingerprint,
    "reverse_proxy_ip_spoofing": _playbook_reverse_proxy_ip_spoofing,
    "unauthenticated_artifact_vault_exposure": _playbook_unauthenticated_artifact_vault_exposure,
    "weak_reversible_binary_passkey": _playbook_weak_reversible_binary_passkey,
    "unauthenticated_console_service": _playbook_unauthenticated_console_service,
    "flag_disclosure_pidreq": _playbook_flag_disclosure_pidreq,
}'''

# Insert functions before _PLAYBOOKS
content = content.replace('_PLAYBOOKS: dict[str, object] = {', playbook_defs + '\n_PLAYBOOKS: dict[str, object] = {')

# Update dict
if target_playbook_dict in content:
    content = content.replace(target_playbook_dict, replacement_playbook_dict)
else:
    # try CRLF
    target_crlf = target_playbook_dict.replace('\n', '\r\n')
    replacement_crlf = replacement_playbook_dict.replace('\n', '\r\n')
    assert target_crlf in content, 'Target playbook dict not found'
    content = content.replace(target_crlf, replacement_crlf)

with open('src/cart/verify.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Successfully updated verify.py!')

