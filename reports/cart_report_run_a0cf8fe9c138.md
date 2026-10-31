# CyberForge CART Assessment Report: `run_a0cf8fe9c138`

**Generated:** 2026-10-31T17:33:50+00:00  
**Run Status:** `COMPLETED` | **Tier:** `deep`  
**Started:** 2026-10-31T17:30:44+00:00 | **Completed:** 2026-10-31T17:33:50+00:00  

## 1. Executive Summary

Assessment run run_a0cf8fe9c138 (COMPLETED) discovered 0 asset(s) and 0 open service(s). Identified 480 finding(s) with 480 confirmed. Scope safety enforced 0 out-of-scope denials with 0 safety leaks.

## 2. PRD Assessment Metrics

| Measure | Target | Actual Result | Status |
|---|---|---|---|
| **Scope Safety** | 0 out-of-scope probes | **0 leaks** (0 denied by gate) | ✅ PASS |
| **Autonomy** | 0 human interventions post-start | **0 interventions** | ✅ PASS |
| **Verification Rate** | > 85% | **100.0%** (480 confirmed) | ✅ PASS |
| **False Alarms** | < 10% | **0.0%** | ✅ PASS |
| **Run Duration** | < 1200 s (20 min) | **186.0 s** | ✅ PASS |

## 3. Scope & Authority

- **Manifest Version:** `scope_3482b2635854`
- **Locked At:** `2026-10-31T14:53:22+00:00`
- **Included Prefixes:** `192.168.60.139/32`
- **Included Hosts:** `None`
- **Exclusions:** `None`
- **Registered Binaries:** `0 registered`

## 4. Discovered Assets & Services

_No assets discovered._

## 5. Findings & Weakness Analysis

| Finding ID | Type | Severity | Status | PTES Phase | Summary |
|---|---|---|---|---|---|
| `find_7994d6418340` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/: action='http://192.... |
| `find_c4b277f5b268` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/: action='http://192.... |
| `find_07b5c5b34267` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/: action='http://192.... |
| `find_b28d8d560a5d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=: action='http://1... |
| `find_0e35ff5a9cb3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=: action='http://1... |
| `find_092c6f6fdd8d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=: action='http://1... |
| `find_97a7babee45f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups: action='h... |
| `find_a93bfa4f02ed` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups: action='h... |
| `find_62910aaafb9e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups: action='h... |
| `find_0801f2a8ff81` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/: action='htt... |
| `find_88a02cb710fe` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/: action='htt... |
| `find_abbabea75d33` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/: action='htt... |
| `find_05c03574c81e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops: action='http:... |
| `find_c5e20036b445` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops: action='http:... |
| `find_d44105c871bb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops: action='http:... |
| `find_41fef5034305` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/: action='http://... |
| `find_1f408736e479` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/: action='http://... |
| `find_82be395bb0d9` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/: action='http://... |
| `find_dd9a091d8c12` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=edr_log_gene... |
| `find_735b5cd577bf` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=edr_log_gene... |
| `find_8ed7b9c71723` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=edr_log_gene... |
| `find_01ff47c7345a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py:... |
| `find_106c9bed2b33` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py:... |
| `find_270a70cc75b3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py:... |
| `find_97432e982e56` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=edr_log_genera... |
| `find_a41dcac285bb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=edr_log_genera... |
| `find_22c9677535f0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=edr_log_genera... |
| `find_914a073abba4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-50G.log:... |
| `find_0d0a2a212d4d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-50G.log:... |
| `find_f4b4ad476665` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-50G.log:... |
| `find_6e9c8c31c00e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=README.txt: ... |
| `find_564bea58ca83` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=README.txt: ... |
| `find_076c980fdcff` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=README.txt: ... |
| `find_26c26621068b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/README.txt: action='h... |
| `find_77348df5ebfd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/README.txt: action='h... |
| `find_61b0304257aa` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/README.txt: action='h... |
| `find_4d24a9f86a33` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=README.txt: ac... |
| `find_33649e33ead8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=README.txt: ac... |
| `find_b19654a30519` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=README.txt: ac... |
| `find_80eff0e8d43e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups: action='http... |
| `find_f128d43c3739` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups: action='http... |
| `find_1bbb5eac862f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups: action='http... |
| `find_dcb17d4722ea` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&view=place... |
| `find_3b274e556ff4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&view=place... |
| `find_292dd7f7815c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&view=place... |
| `find_776cbc1a962f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/placeholder.t... |
| `find_beeba59e062b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/placeholder.t... |
| `find_f3ba2910c439` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/placeholder.t... |
| `find_474be4f893b8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&dl=placeho... |
| `find_17ed648f166b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&dl=placeho... |
| `find_d1836d7930c5` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&dl=placeho... |
| `find_8d76add395c8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=: action='... |
| `find_19a7d4d6d713` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=: action='... |
| `find_0a038a0d9bb8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=: action='... |
| `find_2435bf9ec6ce` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=backups: a... |
| `find_eafeb048a638` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=backups: a... |
| `find_5423345e7fcc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=backups: a... |
| `find_3ac772ff84cb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=ops: actio... |
| `find_5fe1097d0e8b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=ops: actio... |
| `find_030844157e55` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=ops: actio... |
| `find_bce3e22c2f64` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=edr_... |
| `find_643f4789cf24` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=edr_... |
| `find_6d53c3290550` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=edr_... |
| `find_2af7b2b17872` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=edr_lo... |
| `find_831ad10bd975` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=edr_lo... |
| `find_7c4d1ea5031a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=edr_lo... |
| `find_23d09f6d022a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=firex-... |
| `find_0b3d6e6c4a4d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=firex-... |
| `find_4e3a0d355f9d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=firex-... |
| `find_02a5a9c3cdc4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=READ... |
| `find_aa032028f179` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=READ... |
| `find_1a9f829e47dc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=READ... |
| `find_131177c56766` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=README... |
| `find_d559e4be3cd1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=README... |
| `find_ea8067cff8f9` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=README... |
| `find_00d64d1f746f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops: action='http://1... |
| `find_df1af4507f52` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops: action='http://1... |
| `find_9fcd7aa60963` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops: action='http://1... |
| `find_0298ec668c5a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&view=netops-ha... |
| `find_a57eff6a420f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&view=netops-ha... |
| `find_e42e1596cfab` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&view=netops-ha... |
| `find_eaa00017b578` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/netops-handover.t... |
| `find_23c4417237e8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/netops-handover.t... |
| `find_3b3826c86185` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/netops-handover.t... |
| `find_5679d15d4457` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&dl=netops-hand... |
| `find_1eb720d336f0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&dl=netops-hand... |
| `find_5835f28c73a6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&dl=netops-hand... |
| `find_3cc462789423` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=: action='http... |
| `find_54f9da63a4d4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=: action='http... |
| `find_0bcd6e787a52` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=: action='http... |
| `find_b53396eea4e2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=backups: actio... |
| `find_42d9cb92e9b2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=backups: actio... |
| `find_497c625e2c6a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=backups: actio... |
| `find_2386ca3de437` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=ops: action='h... |
| `find_241718ed5209` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=ops: action='h... |
| `find_9d90db2f7f17` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=ops: action='h... |
| `find_77acdf4331c1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=edr_log_... |
| `find_d855778dc3b7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=edr_log_... |
| `find_ff34ca850c65` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=edr_log_... |
| `find_95639b9ba172` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=edr_log_ge... |
| `find_d7dd842422fd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=edr_log_ge... |
| `find_f7227eac1a5b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=edr_log_ge... |
| `find_952353a8ddcf` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=firex-50... |
| `find_5d1e77202dea` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=firex-50... |
| `find_a9413a45e425` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=firex-50G.... |
| `find_1077c65b0d68` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=firex-50G.... |
| `find_8bef8089a99c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=firex-50G.... |
| `find_2c7f3fce7b5b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=README.t... |
| `find_842f0a2f4f0d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=README.t... |
| `find_6fccb630b858` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=README.t... |
| `find_6537406d1bf9` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=README.txt... |
| `find_3e1fe9eb91b7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=README.txt... |
| `find_e910803a6603` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=README.txt... |
| `find_605be38cd74a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_94c9fc5fd912` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_9e710be629bf` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_3235bf75c0ae` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_3970672ac80b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_e2525e3f761b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_89168e562b2d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_0b61cfb17a48` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_ba7394e49eaf` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_4251285a27cb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_4255d49e59d9` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_9f39c05931c8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_6617ed6fd80a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_3139edbac640` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_ec8d72e97db1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_8cbf764bd8f6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_0d724189d791` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_07b9e3fe7dd8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/: action='http://192.... |
| `find_0fd84672b87f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/: action='http://192.... |
| `find_fbf43c898eb2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/: action='http://192.... |
| `find_b289512070cd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=: action='http://1... |
| `find_6b559a770ced` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=: action='http://1... |
| `find_e8ee524a1af4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=: action='http://1... |
| `find_3e6b54dbb582` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups: action='h... |
| `find_b96699987275` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups: action='h... |
| `find_2a0a092420a3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups: action='h... |
| `find_4f4f45f34965` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/: action='htt... |
| `find_1cd0c3db0c4f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/: action='htt... |
| `find_ca1cd3057e6e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/: action='htt... |
| `find_05ebe86e8f13` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops: action='http:... |
| `find_a2ee25e3d702` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops: action='http:... |
| `find_f7dd51351155` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops: action='http:... |
| `find_8011fa38cd85` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/: action='http://... |
| `find_2b77930b65f4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/: action='http://... |
| `find_2e9d33bdf91f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/: action='http://... |
| `find_1f2fb3ff4c28` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=edr_log_gene... |
| `find_a673250b620a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=edr_log_gene... |
| `find_0bdeadfa144c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=edr_log_gene... |
| `find_a699fa26fd89` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py:... |
| `find_b21971a890a4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py:... |
| `find_99a7aec56db8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py:... |
| `find_6d8cd4163aac` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=edr_log_genera... |
| `find_1a3771b26a5e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=edr_log_genera... |
| `find_9f367b2dc3bd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=edr_log_genera... |
| `find_4ba55af3c429` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-30G.log:... |
| `find_5e3725f3e8b5` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-30G.log:... |
| `find_db00177896a2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-30G.log:... |
| `find_2703bad85b7b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=firex-50G.lo... |
| `find_4b3dabb718ea` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=firex-50G.lo... |
| `find_73d038bb4557` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/firex-50G.log: action... |
| `find_94351f7979eb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/firex-50G.log: action... |
| `find_bb92df81c30e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/firex-50G.log: action... |
| `find_60b1deece49c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-50G.log:... |
| `find_2154104d76a3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-50G.log:... |
| `find_d37df364e274` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=firex-50G.log:... |
| `find_00b48cf11b91` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=README.txt: ... |
| `find_e2cc223261f2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=README.txt: ... |
| `find_1962fa0e8d5b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&view=README.txt: ... |
| `find_c56050fb1f74` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/README.txt: action='h... |
| `find_93c648b2a80b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/README.txt: action='h... |
| `find_d6048202d567` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/README.txt: action='h... |
| `find_f1f4e08351fd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=README.txt: ac... |
| `find_f8f804f7619c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=README.txt: ac... |
| `find_675a75099914` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=&dl=README.txt: ac... |
| `find_2b38a5acbd61` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups: action='http... |
| `find_3701c65f5cb1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups: action='http... |
| `find_3af0ac3ff6ab` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups: action='http... |
| `find_1aff3a637ad6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&view=place... |
| `find_bc91e2568c9c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&view=place... |
| `find_2d8c7d4f435e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&view=place... |
| `find_c8a0d8adc3e1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/placeholder.t... |
| `find_37f65b4fb6a7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/placeholder.t... |
| `find_7274767b8030` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/placeholder.t... |
| `find_5451b28290ed` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&dl=placeho... |
| `find_d0376a041e38` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&dl=placeho... |
| `find_d8e046d751e2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=backups&dl=placeho... |
| `find_0e40a023c8e6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=: action='... |
| `find_52fcbb64510b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=: action='... |
| `find_acdb916c5096` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=: action='... |
| `find_4c6ee4479f44` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=backups: a... |
| `find_1cb56bb547fe` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=backups: a... |
| `find_ba3da1bfa3b2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=backups: a... |
| `find_ab1f2e8682a1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=ops: actio... |
| `find_79bd18306832` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=ops: actio... |
| `find_d123f15c4ecc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=ops: actio... |
| `find_c56c803e1419` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=edr_... |
| `find_7dbf516e0329` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=edr_... |
| `find_ab1a2d86b6f4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=edr_... |
| `find_6fd8225dc431` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=edr_lo... |
| `find_67becaaad692` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=edr_lo... |
| `find_5ab7c5aa2093` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=edr_lo... |
| `find_c6114aac3b2a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=firex-... |
| `find_21af8940d530` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=firex-... |
| `find_05f877f0b34f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=firex-... |
| `find_9972a95380bc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=READ... |
| `find_fc26f5674435` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=READ... |
| `find_0b9225295ad3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&view=READ... |
| `find_a169d19c8454` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=README... |
| `find_b5452330061c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=README... |
| `find_3777a008111a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/backups/?p=&dl=README... |
| `find_4e8ed4c383f1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops: action='http://1... |
| `find_2ca041782817` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops: action='http://1... |
| `find_e43f7dcd2111` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops: action='http://1... |
| `find_dd7e2a984f63` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&view=netops-ha... |
| `find_b73efadb3a61` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&view=netops-ha... |
| `find_c1715022ec20` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&view=netops-ha... |
| `find_36f62543a948` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/netops-handover.t... |
| `find_a9244b142d0a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/netops-handover.t... |
| `find_8f593d00eed1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/netops-handover.t... |
| `find_d2a7acc17242` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&dl=netops-hand... |
| `find_211588246919` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&dl=netops-hand... |
| `find_ee761b0c20a1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/?p=ops&dl=netops-hand... |
| `find_3dd4ef3f6ff9` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=: action='http... |
| `find_795e24f9e7a7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=: action='http... |
| `find_4cf051d3d3ab` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=: action='http... |
| `find_17d48a5ffc6a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=backups: actio... |
| `find_129cc18108dc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=backups: actio... |
| `find_607470ef0cca` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=backups: actio... |
| `find_9a85a72d5e67` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=ops: action='h... |
| `find_ecb00e8414a1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=ops: action='h... |
| `find_314032398f95` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=ops: action='h... |
| `find_e96c4d1fe4b2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=edr_log_... |
| `find_35a6e0d3d473` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=edr_log_... |
| `find_84deaa08daf6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=edr_log_... |
| `find_7fd70bed4cc7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=edr_log_ge... |
| `find_6e220aa663c0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=edr_log_ge... |
| `find_6a500276ebba` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=edr_log_ge... |
| `find_5a0b955d35a1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=firex-50... |
| `find_1846890fe6b8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=firex-50... |
| `find_5c835ef6105a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=firex-50G.... |
| `find_2473efc414c0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=firex-50G.... |
| `find_09b491960807` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=firex-50G.... |
| `find_c1ade241fe3a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=README.t... |
| `find_f4f2e8edd129` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=README.t... |
| `find_76645bd55108` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&view=README.t... |
| `find_f75b4840fc9f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=README.txt... |
| `find_5cc9f8307660` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=README.txt... |
| `find_03be16818f98` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/ops/?p=&dl=README.txt... |
| `find_a58b5241e3ba` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_fff68b9d01e2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_00acb1b2c28b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_a553a676c3c8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_69d33a688a02` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_6e95c518360f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_72d8ebfb3b8c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_c8952966304d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_44547254bf49` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_f4449eb84301` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_7edf5a981ecb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_b588beb48d8c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_5d027cb454f3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_d74b04fa340d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_58e3036ed7ca` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139:80/edr_log_generator.py?... |
| `find_cdab97636630` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/: action='http://192.168... |
| `find_05c53f934c7e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/: action='http://192.168... |
| `find_dcdbe1dd762d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/: action='http://192.168... |
| `find_56a1e1c03f96` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=: action='http://192.... |
| `find_c2742cf03170` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=: action='http://192.... |
| `find_9a0e211e9f07` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=: action='http://192.... |
| `find_5504367dac46` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups: action='http... |
| `find_2a329c61341a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups: action='http... |
| `find_dbd6de759563` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups: action='http... |
| `find_670fc4f1cae1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/: action='http:/... |
| `find_ff94abd2ef58` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/: action='http:/... |
| `find_d7af2aaf571d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/: action='http:/... |
| `find_edcde5e21d37` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops: action='http://1... |
| `find_53486340cfb0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops: action='http://1... |
| `find_8e36418d6d10` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops: action='http://1... |
| `find_3c412257401a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/: action='http://192... |
| `find_2c49189b8f38` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/: action='http://192... |
| `find_bb0567b1ab5b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/: action='http://192... |
| `find_d7daa578c98b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=edr_log_generat... |
| `find_fed9f0753000` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=edr_log_generat... |
| `find_1335ebaac150` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=edr_log_generat... |
| `find_b21996c8f9eb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py: ac... |
| `find_9122ee5bf87b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py: ac... |
| `find_97793d3b79e8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py: ac... |
| `find_7b187e89bfcc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=edr_log_generator... |
| `find_30fd04961f6c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=edr_log_generator... |
| `find_8c1b19dcae6f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=edr_log_generator... |
| `find_a83e2793506e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-30G.log: ac... |
| `find_5922d6100cd4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-30G.log: ac... |
| `find_c0206fee8d7e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-30G.log: ac... |
| `find_4ec0bfebe3bb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-50G.log: ac... |
| `find_22640e19d593` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-50G.log: ac... |
| `find_b2bbaca6d256` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-50G.log: ac... |
| `find_e7e3d03886aa` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=README.txt: act... |
| `find_815c2bf2599f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=README.txt: act... |
| `find_01bf56f0579d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=README.txt: act... |
| `find_331ecd9f3b79` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/README.txt: action='http... |
| `find_a304e6f2b6b7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/README.txt: action='http... |
| `find_7ae8f93c7f54` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/README.txt: action='http... |
| `find_ac510742085f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=README.txt: actio... |
| `find_c474d37a89f1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=README.txt: actio... |
| `find_fff7f33a0aaa` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=README.txt: actio... |
| `find_9945ce894b3a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups: action='http://... |
| `find_dffefff94a14` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups: action='http://... |
| `find_a1e0ecb28010` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups: action='http://... |
| `find_3e66cd7dfde8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&view=placehol... |
| `find_cba64accdcb0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&view=placehol... |
| `find_bce8acd0431f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&view=placehol... |
| `find_957270a780d7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/placeholder.txt:... |
| `find_9e416ae28e0a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/placeholder.txt:... |
| `find_50cd9877b64c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/placeholder.txt:... |
| `find_031a4294a051` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&dl=placeholde... |
| `find_0a0b5d65e364` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&dl=placeholde... |
| `find_b18925fbc510` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&dl=placeholde... |
| `find_10500a47f6dd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=: action='htt... |
| `find_3fbc894f1d2c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=: action='htt... |
| `find_9d8651c026c6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=: action='htt... |
| `find_bfd9fc02f06f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=backups: acti... |
| `find_491a573ba812` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=backups: acti... |
| `find_be5737ebe733` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=backups: acti... |
| `find_d53d1952bb71` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=ops: action='... |
| `find_2ba3f824f7ad` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=ops: action='... |
| `find_22fa75968975` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=ops: action='... |
| `find_89d476189061` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=edr_log... |
| `find_f4f9f694cfe2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=edr_log... |
| `find_1fe318870a4c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=edr_log... |
| `find_9badd2e9e8d3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=edr_log_g... |
| `find_66829c3bc859` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=edr_log_g... |
| `find_a420d803ab40` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=edr_log_g... |
| `find_35b0ee06e889` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-30G... |
| `find_6afaedc3d81d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-30G... |
| `find_7e30994868db` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-30G... |
| `find_551269b69981` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-50G... |
| `find_91c25b59fdd5` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-50G... |
| `find_3b9ada181aa1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-50G... |
| `find_3ea16064b5cd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=README.tx... |
| `find_e10b8627d97f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=README.tx... |
| `find_5f2d0436193e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=README.tx... |
| `find_0102a0f7b660` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops: action='http://192.... |
| `find_b9bf3ea149d3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops: action='http://192.... |
| `find_455e4f225525` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops: action='http://192.... |
| `find_291e4c93d78b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&view=netops-hando... |
| `find_65e003a07947` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&view=netops-hando... |
| `find_6e845984d1e4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&view=netops-hando... |
| `find_a90838714c83` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/netops-handover.txt:... |
| `find_f88c5bd60fa9` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/netops-handover.txt:... |
| `find_ff75307f23b2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/netops-handover.txt:... |
| `find_a8228ce45d73` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&dl=netops-handove... |
| `find_a5a1c02f1039` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&dl=netops-handove... |
| `find_d8476bf333ae` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&dl=netops-handove... |
| `find_4c26283eb51b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/: action='http://192.168... |
| `find_0cf73eb24902` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/: action='http://192.168... |
| `find_6da7f72fc313` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/: action='http://192.168... |
| `find_713cb310c5ba` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=: action='http://192.... |
| `find_3ca7876a4ccc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=: action='http://192.... |
| `find_b65e0aa3c46f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=: action='http://192.... |
| `find_28b8d143f894` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups: action='http... |
| `find_7a18caa1b5e0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups: action='http... |
| `find_0696e9a67c85` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups: action='http... |
| `find_7b799425dd69` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/: action='http:/... |
| `find_d0aa68200b1c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/: action='http:/... |
| `find_ba1a4af801c6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/: action='http:/... |
| `find_f0b4058a1e9a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops: action='http://1... |
| `find_890aebbcd208` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops: action='http://1... |
| `find_2f51a3529b1c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops: action='http://1... |
| `find_7bd87afd71b7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/: action='http://192... |
| `find_01c23fc9628e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/: action='http://192... |
| `find_3958a5bcfbfc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/: action='http://192... |
| `find_5872dd4a389f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=edr_log_generat... |
| `find_d43add7d9003` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=edr_log_generat... |
| `find_2e5e9f4810b8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&view=edr_log_generat... |
| `find_2464146a378e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py: ac... |
| `find_cd1d5a5fc79f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py: ac... |
| `find_633c140cf757` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py: ac... |
| `find_34d5502d4522` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=edr_log_generator... |
| `find_5894834c3aea` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=edr_log_generator... |
| `find_8c51740a4cd3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=edr_log_generator... |
| `find_b5089df0d21b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/firex-30G.log: action='h... |
| `find_87d56bc04780` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/firex-30G.log: action='h... |
| `find_08aa7165904a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/firex-30G.log: action='h... |
| `find_6a444fe50b8a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-30G.log: ac... |
| `find_e6ae022fe252` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-30G.log: ac... |
| `find_62b807e5839b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=firex-30G.log: ac... |
| `find_42a21359de0d` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/README.txt: action='http... |
| `find_1ccf8fca715f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/README.txt: action='http... |
| `find_5fadd165e481` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/README.txt: action='http... |
| `find_b2ff9e59c13a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=README.txt: actio... |
| `find_c4d514750cf2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=README.txt: actio... |
| `find_9b37eee60907` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=&dl=README.txt: actio... |
| `find_fabfd35c68e5` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups: action='http://... |
| `find_1d9e1147a6a0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups: action='http://... |
| `find_53501671c7b4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups: action='http://... |
| `find_e4d6f32517fc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&view=placehol... |
| `find_afd78ef32234` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&view=placehol... |
| `find_d324c22384ad` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&view=placehol... |
| `find_0473e2bcb93c` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/placeholder.txt:... |
| `find_d6a93e13cef7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/placeholder.txt:... |
| `find_2c41c09e4602` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/placeholder.txt:... |
| `find_5022a98e74f0` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&dl=placeholde... |
| `find_728c82fbc157` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&dl=placeholde... |
| `find_3cc6836036d3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=backups&dl=placeholde... |
| `find_f1bf48193c03` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=: action='htt... |
| `find_82d7c9b70d88` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=: action='htt... |
| `find_5ad91315974f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=: action='htt... |
| `find_669d65e2fa23` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=backups: acti... |
| `find_136c9d0bbdc8` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=backups: acti... |
| `find_78218f7eb1a4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=backups: acti... |
| `find_055e0d9e58ff` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=ops: action='... |
| `find_30ada4f1a531` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=ops: action='... |
| `find_f02cd09e9ee2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=ops: action='... |
| `find_424d83707957` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=edr_log... |
| `find_802065846223` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=edr_log... |
| `find_06ca677890fd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=edr_log... |
| `find_1911a70fb056` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=edr_log_g... |
| `find_e44ae2dddc31` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=edr_log_g... |
| `find_587ef3a78ebb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=edr_log_g... |
| `find_3f728f5c85ba` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=firex-5... |
| `find_20b22c6601e1` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=firex-5... |
| `find_c29e691ad4ff` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-50G... |
| `find_c9e9c9f89139` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-50G... |
| `find_b6d0ff7d81f4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=firex-50G... |
| `find_4b0c7c06d6f4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=README.... |
| `find_f6ad967dad58` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=README.... |
| `find_cd2113152807` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&view=README.... |
| `find_acaeb7a84b9f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=README.tx... |
| `find_acd63074481e` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=README.tx... |
| `find_5859fc61c642` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/backups/?p=&dl=README.tx... |
| `find_544709ed43c6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops: action='http://192.... |
| `find_9eb1eb176839` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops: action='http://192.... |
| `find_32e47051d0ee` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops: action='http://192.... |
| `find_a7a49dc853dd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&view=netops-hando... |
| `find_3499659eabf6` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&view=netops-hando... |
| `find_811e9d1dcc51` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&view=netops-hando... |
| `find_dbfb6e783541` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&dl=netops-handove... |
| `find_2eb709f33633` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&dl=netops-handove... |
| `find_987739e7c082` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/?p=ops&dl=netops-handove... |
| `find_0aec65975edb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=backups: action='... |
| `find_dc04e71d46fb` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=backups: action='... |
| `find_7e33b73452dd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=backups: action='... |
| `find_96adc0e689fc` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=ops: action='http... |
| `find_b65455c09994` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=ops: action='http... |
| `find_69afa0f253d9` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=ops: action='http... |
| `find_8e4383fd00f7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=edr_log_gen... |
| `find_d1cad0661716` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=edr_log_gen... |
| `find_cae26160e368` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=edr_log_gen... |
| `find_d717c3bac47f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=edr_log_gener... |
| `find_306a8ffe4f5b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=edr_log_gener... |
| `find_3b855aed5b47` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=edr_log_gener... |
| `find_9790551321b5` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=firex-50G.l... |
| `find_cc7970c6bba2` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=firex-50G.l... |
| `find_709a99959e07` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=firex-50G.log... |
| `find_1005bb3e822b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=firex-50G.log... |
| `find_beb56f801a24` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=firex-50G.log... |
| `find_6d8c7063cb45` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=README.txt:... |
| `find_826d9aa9ab04` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=README.txt:... |
| `find_20d00bb806fa` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&view=README.txt:... |
| `find_c436a60565b7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=README.txt: a... |
| `find_1888fd71be96` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=README.txt: a... |
| `find_4a6b7860d34a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/ops/?p=&dl=README.txt: a... |
| `find_0772273f6872` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=:... |
| `find_b58210c0385a` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=:... |
| `find_a040812d3b98` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=:... |
| `find_35ecdf30bc15` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=b... |
| `find_dc8f848587e7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=b... |
| `find_96d7dbf7d096` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=b... |
| `find_b7fb6caad682` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=o... |
| `find_0ba03e68dcbd` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=o... |
| `find_325d4f6d44b3` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=o... |
| `find_5b4abdf652a4` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=&... |
| `find_46d8f40ed50b` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=&... |
| `find_b2d13f36d0c7` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=&... |
| `find_d4c613952088` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=&... |
| `find_135f189f1731` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=&... |
| `find_0b444c29a03f` | `web_form_endpoint` | **INFO** | `confirmed` | intelligence-gathering | Form found at http://192.168.60.139/edr_log_generator.py?p=&... |

## 6. Evidence-Backed Attack Paths

_No evidence-backed lateral attack paths found._

---
_Report generated autonomously by CyberForge CART._