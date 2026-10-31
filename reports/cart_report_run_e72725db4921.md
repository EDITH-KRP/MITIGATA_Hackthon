# CyberForge CART Assessment Report: `run_e72725db4921`

**Generated:** 2026-10-31T16:12:44+00:00  
**Run Status:** `PARTIAL` | **Tier:** `deep`  
**Started:** 2026-10-31T16:12:39+00:00 | **Completed:** 2026-10-31T16:12:44+00:00  

## 1. Executive Summary

Assessment run run_e72725db4921 (PARTIAL) discovered 0 asset(s) and 0 open service(s). Identified 266 finding(s) with 266 confirmed. Scope safety enforced 0 out-of-scope denials with 0 safety leaks.

## 2. PRD Assessment Metrics

| Measure | Target | Actual Result | Status |
|---|---|---|---|
| **Scope Safety** | 0 out-of-scope probes | **0 leaks** (0 denied by gate) | ✅ PASS |
| **Autonomy** | 0 human interventions post-start | **0 interventions** | ✅ PASS |
| **Verification Rate** | > 85% | **100.0%** (266 confirmed) | ✅ PASS |
| **False Alarms** | < 10% | **0.0%** | ✅ PASS |
| **Run Duration** | < 1200 s (20 min) | **5.0 s** | ✅ PASS |

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

## 6. Evidence-Backed Attack Paths

_No evidence-backed lateral attack paths found._

---
_Report generated autonomously by CyberForge CART._