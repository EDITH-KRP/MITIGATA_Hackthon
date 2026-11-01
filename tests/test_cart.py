"""Comprehensive test suite for CyberForge CART engine (stdlib unittest)."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cart.advisor import RemediationAdvisor
from cart.attackpath import AttackPathBuilder
from cart.budget import BudgetExceeded, RunBudget, TaskRetryBudget
from cart.models import (
    FindingStatus,
    ScopeDecision,
    ScopeManifest,
    Task,
    TaskStatus,
    utc_now,
)
from cart.orchestrator import Orchestrator
from cart.report import ReportGenerator
from cart.scope import PolicyGate, ScopeNotLockedError
from cart.store import connect
from cart.tracing import AgentTracer, Span
from cart.verify import VerificationService
from cart.workers.binary import (
    BinaryWorker,
    scan_unsafe_functions,
)
from cart.workers.binary import (
    scan_flags as bin_scan_flags,
)
from cart.workers.web import (
    WebWorker,
    extract_html_comments,
    looks_like_binary_url,
)
from cart.workers.web import (
    scan_flags as web_scan_flags,
)


class TestPolicyGate(unittest.TestCase):
    def setUp(self):
        self.manifest = ScopeManifest(
            scope_version="test_v1",
            included_prefixes=["192.168.1.0/24"],
            included_hosts=["10.0.0.5"],
            exclusions=["192.168.1.254"],
            binary_hashes={"/bin/sample": "abcdef123456"},
            locked_at=utc_now(),
        )
        self.gate = PolicyGate(self.manifest)

    def test_unlocked_manifest_raises(self):
        unlocked = ScopeManifest(scope_version="unlocked")
        with self.assertRaises(ScopeNotLockedError):
            PolicyGate(unlocked)

    def test_in_scope_destination(self):
        res = self.gate.check_destination("192.168.1.50")
        self.assertEqual(res.decision, ScopeDecision.ALLOW)

    def test_in_scope_host(self):
        res = self.gate.check_destination("10.0.0.5")
        self.assertEqual(res.decision, ScopeDecision.ALLOW)

    def test_exclusion_always_wins(self):
        res = self.gate.check_destination("192.168.1.254")
        self.assertEqual(res.decision, ScopeDecision.DENY)
        self.assertIn("excluded", res.reason)

    def test_out_of_scope_destination(self):
        res = self.gate.check_destination("8.8.8.8")
        self.assertEqual(res.decision, ScopeDecision.DENY)

    def test_unparseable_destination(self):
        res = self.gate.check_destination("not-a-valid-ip-or-cidr")
        self.assertEqual(res.decision, ScopeDecision.DENY)
        self.assertIn("unparseable", res.reason)

    def test_binary_file_check(self):
        res = self.gate.check_binary_file("/bin/sample")
        self.assertEqual(res.decision, ScopeDecision.ALLOW)
        res_bad = self.gate.check_binary_file("/bin/unknown")
        self.assertEqual(res_bad.decision, ScopeDecision.DENY)

    def test_audit_log_recording(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "audit_test.db"
            conn = connect(db_path)
            self.gate.bind_store(conn)
            self.gate.gate("192.168.1.10", run_id="run_test")
            row = conn.execute("SELECT requested_target, decision FROM scope_decisions_log").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "192.168.1.10")
            self.assertEqual(row[1], "allow")
            conn.close()


class TestBudgetAndOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_orch.db"
        self.conn = connect(self.db_path)

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_retry_budget_backoff_and_cap(self):
        rb = TaskRetryBudget(task_id="t1", max_retries=2, backoff_base=2.0)
        self.assertTrue(rb.can_retry())
        w1 = rb.consume()
        self.assertEqual(w1, 1.0)
        w2 = rb.consume()
        self.assertEqual(w2, 2.0)
        self.assertFalse(rb.can_retry())
        with self.assertRaises(BudgetExceeded):
            rb.consume()

    def test_run_budget_expiration(self):
        rb = RunBudget(run_id="r1", total_seconds=0, max_tasks=10)
        self.assertTrue(rb.is_expired())
        with self.assertRaises(BudgetExceeded):
            rb.check_time()

    def test_orchestrator_dedup(self):
        orch = Orchestrator(conn=self.conn, run_id="run_test")
        t1 = Task(
            task_id="t1",
            task_type="discovery",
            owner="network",
            target_id="10.0.0.1",
            dedupe_key="dup_key_1",
            status=TaskStatus.READY,
        )
        t2 = Task(
            task_id="t2",
            task_type="discovery",
            owner="network",
            target_id="10.0.0.1",
            dedupe_key="dup_key_1",
            status=TaskStatus.READY,
        )
        id1 = orch.create_task(t1)
        id2 = orch.create_task(t2)
        self.assertEqual(id1, id2)
        self.assertEqual(id1, "t1")

    def test_orchestrator_transitions(self):
        orch = Orchestrator(conn=self.conn, run_id="run_test")
        t1 = Task(
            task_id="t1",
            task_type="discovery",
            owner="network",
            target_id="10.0.0.1",
            status=TaskStatus.PENDING,
        )
        orch.create_task(t1)
        orch.transition("t1", TaskStatus.READY)
        self.assertEqual(orch.get_task("t1").status, TaskStatus.READY)
        orch.transition("t1", TaskStatus.RUNNING)
        self.assertEqual(orch.get_task("t1").status, TaskStatus.RUNNING)
        orch.transition("t1", TaskStatus.SUCCEEDED)
        self.assertEqual(orch.get_task("t1").status, TaskStatus.SUCCEEDED)

        # Illegal transition
        with self.assertRaises(ValueError):
            orch.transition("t1", TaskStatus.RUNNING)


class TestAttackPathBuilder(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_attackpath.db"
        self.conn = connect(self.db_path)

        # Insert run first for FK integrity
        self.conn.execute("INSERT INTO runs (run_id, status, tier) VALUES ('r1', 'running', 'recon')")

        # Insert assets
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a1', 'r1', 'host', '10.0.0.1', '', '')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a2', 'r1', 'host', '10.0.0.2', '', '')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a3', 'r1', 'host', '10.0.0.3', '', '')")

        # Insert findings & evidence
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f1', 'a2', 'ssh', 'high', 'confirmed')")
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp) VALUES ('ev1', 'f1', 'tool', '', 'h1', '')")
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp) VALUES ('ev2', 'f1', 'tool', '', 'h2', '')")

        # Insert relationships
        self.conn.execute("INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES ('a1', 'a2', 'SSH_BRUTE', 'ev1', 'high')")
        self.conn.execute("INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES ('a2', 'a3', 'PASS_HASH', 'ev2', 'medium')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_attack_path_traversal_and_scoring(self):
        builder = AttackPathBuilder(self.conn, "r1")
        paths = builder.build(entry_points=["a1"], high_value_targets=["a3"])
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p.hop_count, 2)
        # 0.9 * 0.7 = 0.63
        self.assertAlmostEqual(p.score, 0.63, places=2)
        report = builder.format_paths_report(paths)
        self.assertIn("10.0.0.1", report)
        self.assertIn("10.0.0.3", report)


class TestVerificationService(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_verify.db"
        self.conn = connect(self.db_path)
        # Insert run first for FK integrity
        self.conn.execute("INSERT INTO runs (run_id, status, tier) VALUES ('r1', 'running', 'recon')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a1', 'r1', 'host', '10.0.0.1', '', '')")

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_verify_web_form(self):
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f_web', 'a1', 'web_form_endpoint', 'info', 'candidate')")
        ev_excerpt = json.dumps({"action": "/login", "inputs": [{"name": "username"}, {"name": "password"}]})
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt) VALUES ('e1', 'f_web', 'crawler', '', 'h1', '', ?)", (ev_excerpt,))
        self.conn.commit()

        svc = VerificationService(self.conn, "r1")
        svc.queue(["f_web"])
        res = svc.verify_one("f_web")
        self.assertEqual(res, FindingStatus.CONFIRMED)


class TestReportGenerator(unittest.TestCase):
    def test_generate_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            conn = connect(db_path)
            conn.execute("INSERT INTO runs (run_id, status, tier, started_at, completed_at, scope_version) VALUES ('r_test', 'completed', 'recon', '2026-01-01T00:00:00', '2026-01-01T00:05:00', 's1')")
            conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s1', '[\"192.168.1.0/24\"]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00')")
            conn.commit()

            rep = ReportGenerator(conn, output_dir=tmpdir)
            out = rep.generate("r_test")
            self.assertTrue(Path(out["json_report"]).exists())
            self.assertTrue(Path(out["md_report"]).exists())
            md_text = Path(out["md_report"]).read_text(encoding="utf-8")
            self.assertIn("CyberForge CART Assessment Report", md_text)
            self.assertIn("PRD Assessment Metrics", md_text)
            conn.close()


class TestPlantedFlagAndUnsafeBinary(unittest.TestCase):
    """Judge requirement 1: flag hunter + unsafe C function detection."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.bin_path = Path(self.tmpdir.name) / "vuln_sample.bin"
        # Printable blob: unsafe libc names + a planted CTF flag
        payload = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"strcpy gets sprintf system popen strcat\x00"
            b"flag{test_123}\x00logo.png\x00"
        )
        self.bin_path.write_bytes(payload)

        self.db_path = Path(self.tmpdir.name) / "test_binary.db"
        self.conn = connect(self.db_path)
        self.conn.execute(
            "INSERT INTO runs (run_id, status, tier) VALUES ('run_bin', 'running', 'recon')"
        )
        self.conn.commit()

        manifest = ScopeManifest(
            scope_version="scope_bin_v1",
            included_prefixes=["192.168.1.0/24"],
            # Register the crafted binary by its true SHA-256 (worker re-verifies)
            binary_hashes={str(self.bin_path): hashlib.sha256(payload).hexdigest()},
            locked_at=utc_now(),
        )
        self.gate = PolicyGate(manifest)
        self.gate.bind_store(self.conn)
        self.worker = BinaryWorker(conn=self.conn, gate=self.gate, run_id="run_bin")
        # tool_events has FK to tasks — persist the task record first
        self.conn.execute(
            "INSERT INTO tasks (task_id, task_type, owner, target_id, status) "
            "VALUES ('task_bin', 'binary_static_analysis', 'binary', ?, 'running')",
            (str(self.bin_path),),
        )
        self.conn.commit()
        self.task = Task(
            task_id="task_bin",
            task_type="binary_static_analysis",
            owner="binary",
            target_id=str(self.bin_path),
        )

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def _finding_rows(self, finding_type: str) -> list[tuple]:
        return self.conn.execute(
            "SELECT finding_type, severity, status, summary FROM findings "
            "WHERE finding_type=?",
            (finding_type,),
        ).fetchall()

    def test_flag_detection(self):
        result = self.worker.run(self.task)
        rows = self._finding_rows("ctf_planted_flag")
        self.assertEqual(len(rows), 1, f"expected planted flag finding: {result}")
        _ftype, severity, status, summary = rows[0]
        self.assertEqual(severity, "high")
        self.assertEqual(status, "candidate")  # never auto-confirmed
        self.assertIn("flag{test_123}", summary)

    def test_unsafe_functions_flagged(self):
        self.worker.run(self.task)
        rows = self._finding_rows("binary_unsafe_function")
        flagged = {r[3].split("'")[1] for r in rows}  # summary: "...'strcpy' found..."
        expected = {"strcpy", "gets", "system", "sprintf", "popen", "strcat"}
        self.assertEqual(flagged & expected, expected)
        for _, severity, status, _ in rows:
            self.assertEqual(severity, "high")
            self.assertEqual(status, "candidate")
        # unsafe findings must carry the CWE explanation in the summary
        strcpy_row = next(r for r in rows if "strcpy" in r[3])
        self.assertIn("CWE-120", strcpy_row[3])

    def test_scan_helpers_no_false_positive(self):
        # 'fgets' must NOT trigger the 'gets' rule
        triggered = scan_unsafe_functions(["fgets(buf, sizeof(buf), stdin)"])
        self.assertNotIn("gets", triggered)
        self.assertEqual(
            bin_scan_flags(["flag{a}", "CTF{b})", "flag{a}"]),
            ["flag{a}", "CTF{b}"],  # trailing ')' is not part of the brace match
        )


class TestWebFlagHelpers(unittest.TestCase):
    """Judge requirement 1 (web side): regex, comments and links."""

    def test_scan_flags_in_body_comment_header(self):
        body = "<html><!-- flag{admin_area} -->\nflag{main_page}\n</html>"
        self.assertEqual(
            web_scan_flags(body), ["flag{admin_area}", "flag{main_page}"]
        )
        self.assertEqual(web_scan_flags("X-Flag: CyberForge{hdr-leak}"),
                         ["CyberForge{hdr-leak}"])

    def test_extract_html_comments(self):
        self.assertEqual(
            extract_html_comments("a<!-- one -->b<!-- two\nlines -->c"),
            ["one", "two\nlines"],
        )

    def test_binary_link_detection(self):
        for path in ("/downloads/tool.exe", "/x/impl.so", "/a.ELF", "/b.BIN",
                     "/lib.dll", "/thing.bin"):
            self.assertTrue(looks_like_binary_url(f"https://lab.local{path}"))
        for path in ("/index.html", "/notes.txt", "/api/users", "/no/ext"):
            self.assertFalse(looks_like_binary_url(f"https://lab.local{path}"))


class TestWebWorkerDiscoveredPort(unittest.TestCase):
    """Web crawling must honor discovered non-default HTTP service ports."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.conn = connect(Path(self.tmpdir.name) / "web_port.db")
        self.conn.execute(
            "INSERT INTO runs (run_id, status, tier) VALUES ('run_local', 'running', 'breach')"
        )
        self.conn.execute(
            "INSERT INTO assets "
            "(asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) "
            "VALUES ('asset_local', 'run_local', 'host', '127.0.0.1', '', '')"
        )
        self.conn.execute(
            "INSERT INTO services "
            "(service_id, asset_id, protocol, port, service_name, version, state) "
            "VALUES ('svc_local', 'asset_local', 'tcp', 8080, 'http-proxy', '', 'open')"
        )
        self.conn.commit()
        self.gate = PolicyGate(
            ScopeManifest(
                scope_version="local_v1",
                included_hosts=["127.0.0.1"],
                locked_at=utc_now(),
            )
        )
        self.gate.bind_store(self.conn)
        self.worker = WebWorker(self.conn, self.gate, "run_local", request_delay_s=0)

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_run_uses_discovered_http_port(self):
        task = Task(
            task_id="web_local",
            task_type="web_crawl_endpoint_discovery",
            owner="web",
            target_id="asset_local",
            status=TaskStatus.READY,
        )
        Orchestrator(self.conn, "run_local").create_task(task)
        with patch.object(self.worker, "_crawl", return_value=([], [], [], [])):
            result = self.worker.run(task)

        self.assertEqual(result["base_url"], "http://127.0.0.1:8080/")
        decision = self.conn.execute(
            "SELECT decision FROM scope_decisions_log ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(decision[0], "allow")


class TestPolicyGateDynamicBinary(unittest.TestCase):
    """Scope safety for the web→binary hand-off registrations."""

    def setUp(self):
        self.manifest = ScopeManifest(
            scope_version="dyn_v1",
            included_prefixes=["192.168.1.0/24"],
            locked_at=utc_now(),
        )
        self.tmpdir = tempfile.TemporaryDirectory()
        self.conn = connect(Path(self.tmpdir.name) / "dyn.db")
        self.gate = PolicyGate(self.manifest)
        self.gate.bind_store(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_unregistered_binary_still_denied(self):
        # Fail closed unchanged: anything not organiser-registered is DENY
        res = self.gate.check_binary_file("/tmp/unknown_download.bin")
        self.assertEqual(res.decision, ScopeDecision.DENY)

    def test_register_dynamic_binary_allows_and_audits(self):
        path = str(Path(self.tmpdir.name) / "downloaded.so")
        self.gate.register_dynamic_binary(
            path, "abc123", run_id="run_dyn",
            reason="downloaded binary from in-scope URL",
        )
        res = self.gate.check_binary_file(path)
        self.assertEqual(res.decision, ScopeDecision.ALLOW)
        before = self.conn.execute("SELECT COUNT(*) FROM scope_decisions_log").fetchone()[0]
        self.assertGreaterEqual(before, 1)  # registration was audit-logged

    def test_locked_manifest_never_mutated(self):
        path = str(Path(self.tmpdir.name) / "downloaded.bin")
        self.gate.register_dynamic_binary(path, "def456", run_id="run_dyn")
        stored = self.conn.execute(
            "SELECT binary_hashes FROM scope_manifests LIMIT 1"
        ).fetchone()
        self.assertIsNone(stored)  # manifest untouched (even not written here)
        self.assertEqual(self.gate.manifest.binary_hashes, {})


class TestWebToBinaryHandoff(unittest.TestCase):
    """Judge requirement 2: automatic binary task enqueue from web results."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.conn = connect(Path(self.tmpdir.name) / "handoff.db")
        self.orch = Orchestrator(conn=self.conn, run_id="run_ho")
        self.source = Task(
            task_id="web_task",
            task_type="web_crawl_endpoint_discovery",
            owner="web",
            target_id="asset_x",
            status=TaskStatus.SUCCEEDED,
        )

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_enqueue_binary_task(self):
        new_id_task = self.orch.on_binary_discovered(
            "/cache/run_ho/abc123.so", source_task=self.source
        )
        task = self.orch.get_task(new_id_task)
        self.assertEqual(task.owner, "binary")
        self.assertEqual(task.task_type, "binary_static_analysis")
        self.assertEqual(task.status, TaskStatus.READY)
        self.assertEqual(task.parent_task_id, "web_task")

    def test_dedupe_prevents_second_enqueue(self):
        first = self.orch.on_binary_discovered("/cache/x/bin.elf")
        second = self.orch.on_binary_discovered("/cache/x/bin.elf")
        self.assertEqual(first, second)
        count = self.conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE task_type='binary_static_analysis'"
        ).fetchone()[0]
        self.assertEqual(count, 1)


class TestRemediationAdvisor(unittest.TestCase):
    """Judge requirement 3: rule-based remediation + patch examples."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.conn = connect(Path(self.tmpdir.name) / "advisor.db")
        self.conn.execute("INSERT INTO runs (run_id, status, tier) VALUES ('r_adv', 'running', 'recon')")
        self.conn.execute(
            "INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) "
            "VALUES ('a_adv', 'r_adv', 'host', '10.0.0.1', '', '')"
        )
        self.conn.commit()
        self.advisor = RemediationAdvisor(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def _insert_finding(self, fid: str, finding_type: str, severity: str, summary: str):
        self.conn.execute(
            "INSERT INTO findings (finding_id, asset_id, finding_type, severity, status, confidence, summary) "
            "VALUES (?, 'a_adv', ?, ?, 'confirmed', 'high', ?)",
            (fid, finding_type, severity, summary),
        )
        self.conn.commit()

    def test_unsafe_function_patch(self):
        self._insert_finding(
            "f_unsafe", "binary_unsafe_function", "high",
            "unsafe C functions found: 'strcpy', 'gets'"
        )
        adv = self.advisor.advise("f_unsafe")
        self.assertTrue(
            {"finding_id", "title", "plain_english_summary", "impact",
             "recommended_fix", "patch_example"}.issubset(set(adv.keys()))
        )
        self.assertEqual(adv["finding_id"], "f_unsafe")
        # targeted patches for the exact functions found
        self.assertIn("strncpy", adv["patch_example"])
        self.assertIn("fgets", adv["patch_example"])
        self.assertIn("snprintf", adv["recommended_fix"])

    def test_web_form_patch(self):
        self._insert_finding(
            "f_form", "web_form_endpoint", "info",
            "Form found at http://10.0.0.1/login"
        )
        adv = self.advisor.advise("f_form")
        self.assertIn("csrf", adv["patch_example"].lower())
        self.assertIn("parameterised", adv["recommended_fix"].lower())
        self.assertIn("SELECT", adv["patch_example"])

    def test_planted_flag_advisory(self):
        self._insert_finding(
            "f_flag", "ctf_planted_flag", "high",
            "Planted CTF flag flag{test_123} captured in body"
        )
        adv = self.advisor.advise("f_flag")
        self.assertIn("revok", adv["recommended_fix"].lower())

    def test_hardcoded_credential_advisory(self):
        self._insert_finding(
            "f_cred", "binary_hardcoded_credential", "medium",
            "Binary strings matching hardcoded credential pattern"
        )
        self.conn.execute(
            "INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt) "
            "VALUES ('ev_cred', 'f_cred', 'binary_static_analysis', '', 'h', '', '{\"matches\":[\"password=hunter2\"]}')"
        )
        self.conn.commit()
        adv = self.advisor.advise("f_cred")
        self.assertIn("environment", adv["recommended_fix"].lower())
        self.assertIn("os.environ", adv["patch_example"])

    def test_unknown_finding_falls_back(self):
        self._insert_finding("f_odd", "exotic_curve_weakness", "low", "Weird curve param")
        adv = self.advisor.advise("f_odd")
        self.assertIn("defence-in-depth", adv["recommended_fix"].lower())
        self.assertTrue(adv["patch_example"])

    def test_missing_finding_raises(self):
        with self.assertRaises(KeyError):
            self.advisor.advise("f_missing")


    def test_export_patches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._insert_finding("f_conf", "binary_unsafe_function", "high", "unsafe strcpy")
            self.conn.execute("UPDATE findings SET status = 'confirmed' WHERE finding_id = 'f_conf'")
            self.conn.commit()
            patch_files = self.advisor.export_patches(output_dir=tmpdir)
            self.assertEqual(len(patch_files), 1)
            self.assertTrue(Path(patch_files[0]).exists())
            content = Path(patch_files[0]).read_text(encoding="utf-8")
            # Real git unified diff: starts with diff header, contains index with
            # a 10-char SHA-1 hash, and new-file mode line.
            self.assertIn("diff --git", content)
            self.assertIn("new file mode 100644", content)
            self.assertIn("index ", content)
            self.assertIn("+/* safe_io.h", content)


class TestAgentTracer(unittest.TestCase):
    """Judge requirement 4: span logging to disk, never raising."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmpdir.name) / "traces"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_spans_written_to_jsonl(self):
        tracer = AgentTracer(run_id="r_trace", output_dir=str(self.out_dir))
        span = tracer.start_span("task_1", "web", "web_crawl_endpoint_discovery")
        self.assertIsInstance(span, Span)
        self.assertEqual(span.agent_name, "web")
        tracer.end_span(span, "succeeded", result_summary="12 endpoints")

        span2 = tracer.start_span("task_2", "binary", "binary_static_analysis")
        tracer.end_span(span2, "failed", result_summary="hash mismatch")

        path = self.out_dir / "agent_traces.jsonl"
        self.assertTrue(path.exists())
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["task_id"], "task_1")
        self.assertEqual(first["agent_name"], "web")
        self.assertEqual(first["status"], "succeeded")
        self.assertEqual(first["result_summary"], "12 endpoints")
        self.assertIn("start_time", first)
        self.assertIn("end_time", first)

    def test_creates_output_dir_and_never_raises(self):
        nested = Path(self.tmpdir.name) / "deep" / "nested" / "traces"
        tracer = AgentTracer(run_id="r_trace", output_dir=str(nested))
        span = tracer.start_span("t", "network", "host_discovery")
        tracer.end_span(span, "ok")
        self.assertTrue((nested / "agent_traces.jsonl").exists())

    def test_end_span_rejects_non_span(self):
        tracer = AgentTracer(run_id="r_trace", output_dir=str(self.out_dir))
        with self.assertRaises(TypeError):
            tracer.end_span({"not": "a span"}, "ok")  # type: ignore[arg-type]


class TestUIDashboard(unittest.TestCase):
    def test_ui_handler_methods(self):
        import io

        from cart.ui import DashboardHandler

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_ui.db"
            conn = connect(db_path)
            conn.execute("INSERT INTO runs (run_id, status, tier, started_at, completed_at, scope_version) VALUES ('r_ui', 'completed', 'recon', '2026-01-01T00:00:00', '2026-01-01T00:05:00', 's_ui')")
            conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s_ui', '[\"192.168.1.0/24\"]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00')")
            conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_ui', 'r_ui', 'host', '10.0.0.1', '', '')")
            conn.commit()
            conn.close()

            # Mock a minimal request
            class MockHandler(DashboardHandler):
                def __init__(self):
                    self.db_path = str(db_path)
                    self.wfile = io.BytesIO()
                    self._headers_buffer = []

                def send_response(self, code, message=None):
                    self.response_code = code

                def send_header(self, keyword, value):
                    pass

                def end_headers(self):
                    pass

            handler = MockHandler()

            # Test _handle_status
            handler._handle_status()
            res = json.loads(handler.wfile.getvalue())
            self.assertEqual(res["run_id"], "r_ui")
            self.assertIn("metrics", res)

            # Test _handle_inventory
            handler.wfile = io.BytesIO()
            handler._handle_inventory()
            inv = json.loads(handler.wfile.getvalue())
            self.assertEqual(len(inv), 1)
            self.assertEqual(inv[0]["canonical_key"], "10.0.0.1")

            # Test _handle_candidates
            handler.wfile = io.BytesIO()
            handler._handle_candidates()
            cand = json.loads(handler.wfile.getvalue())
            self.assertIsInstance(cand, list)

            # Test _handle_graph
            handler.wfile = io.BytesIO()
            handler._handle_graph()
            gdata = json.loads(handler.wfile.getvalue())
            self.assertIn("nodes", gdata)
            self.assertIn("edges", gdata)

            # Test _handle_flags
            handler.wfile = io.BytesIO()
            handler._handle_flags()
            flags = json.loads(handler.wfile.getvalue())
            self.assertIsInstance(flags, list)

            # Test _handle_agents
            handler.wfile = io.BytesIO()
            handler._handle_agents()
            agents = json.loads(handler.wfile.getvalue())
            self.assertEqual(len(agents), 5)

            # Test _handle_asset_detail
            handler.wfile = io.BytesIO()
            handler._handle_asset_detail("id=a_ui")
            detail = json.loads(handler.wfile.getvalue())
            self.assertEqual(detail["canonical_key"], "10.0.0.1")

            # Test _handle_patches
            handler.wfile = io.BytesIO()
            handler._handle_patches()
            patches = json.loads(handler.wfile.getvalue())
            self.assertIn("patches", patches)


class TestUniversalTargetAndAttackGraph(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_setup_scope_for_target_url(self):
        from cart.scope import setup_scope_for_target
        manifest, seed_url = setup_scope_for_target(self.conn, "http://10.0.10.25:1111/ops")
        self.assertIsNotNone(manifest.locked_at)
        self.assertIn("10.0.10.25/32", manifest.included_prefixes)
        self.assertIn("10.0.10.25", manifest.included_hosts)
        self.assertEqual(seed_url, "http://10.0.10.25:1111/ops")

    def test_setup_scope_for_target_cidr(self):
        from cart.scope import setup_scope_for_target
        manifest, seed_url = setup_scope_for_target(self.conn, "10.0.0.0/24")
        self.assertIsNotNone(manifest.locked_at)
        self.assertIn("10.0.0.0/24", manifest.included_prefixes)
        self.assertIsNone(seed_url)

    def test_derive_run_relationships(self):
        from cart.attackpath import AttackPathBuilder, derive_run_relationships
        self.conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s1', '[]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES ('r1', 'completed', 'recon', '2026-01-01T00:00:00Z', 's1')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_h', 'r1', 'host', '192.168.1.5', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_w', 'r1', 'web_app', '192.168.1.5', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f1', 'a_h', 'reverse_proxy_ip_spoofing', 'high', 'confirmed')")
        self.conn.execute("INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt) VALUES ('e1', 'f1', 'test_tool', 'test_path', 'hash123', '2026-01-01T00:00:00Z', 'Spoofed XFF')")
        self.conn.commit()

        count = derive_run_relationships(self.conn)
        self.assertGreaterEqual(count, 1)
        builder = AttackPathBuilder(self.conn, "current")
        paths = builder.build()
        self.assertGreaterEqual(len(paths), 1)

    def test_new_web_verification_playbooks(self):
        from cart.models import FindingStatus
        from cart.verify import VerificationService

        self.conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s2', '[]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES ('r2', 'active', 'deep', '2026-01-01T00:00:00Z', 's2')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_web', 'r2', 'web_app', 'test.com', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")

        test_cases = [
            ("f_cors", "cors_wildcard_misconfiguration", "Access-Control-Allow-Origin: *"),
            ("f_robots", "robots_txt_disclosure", "Disallow: /admin"),
            ("f_api", "unauthenticated_api_exposure", '{"version": "1.0", "status": "ok"}'),
            ("f_dir", "directory_listing_disclosure", "<h1>Index of /ftp</h1>"),
            ("f_env", "sensitive_file_exposure", "DB_PASSWORD=supersecret"),
        ]

        svc = VerificationService(self.conn, "r2")
        for fid, ftype, excerpt in test_cases:
            self.conn.execute(
                "INSERT INTO findings (finding_id, asset_id, finding_type, severity, status, confidence, ptes_phase, summary) VALUES (?, 'a_web', ?, 'medium', 'candidate', 'high', 'vulnerability_analysis', 'test summary')",
                (fid, ftype),
            )
            self.conn.execute(
                "INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt) VALUES (?, ?, 'web_crawler', 'http://test.com', 'h1', '2026-01-01T00:00:00Z', ?)",
                (f"ev_{fid}", fid, excerpt),
            )
            svc.queue([fid])
            verdict = svc.verify_one(fid)
            self.assertEqual(verdict, FindingStatus.CONFIRMED, f"Failed confirming {ftype}")

    def test_new_remediation_advisor_templates(self):
        from cart.advisor import RemediationAdvisor

        self.conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s3', '[]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES ('r3', 'active', 'deep', '2026-01-01T00:00:00Z', 's3')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a3', 'r3', 'web_app', 'test.com', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")

        types = [
            "cors_wildcard_misconfiguration",
            "robots_txt_disclosure",
            "unauthenticated_api_exposure",
            "directory_listing_disclosure",
            "sensitive_file_exposure",
        ]
        advisor = RemediationAdvisor(self.conn)
        for i, ftype in enumerate(types):
            fid = f"find_adv_{i}"
            self.conn.execute(
                "INSERT INTO findings (finding_id, asset_id, finding_type, severity, status, confidence, ptes_phase, summary) VALUES (?, 'a3', ?, 'medium', 'confirmed', 'high', 'vulnerability_analysis', 'summary')",
                (fid, ftype),
            )
            adv = advisor.advise(fid)
            self.assertTrue(adv["cwe_id"].startswith("CWE-"))
            self.assertIn("recommended_fix", adv)
            self.assertIn("patch_example", adv)


class TestSecurityAndArchitectureRegressions(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_cidr_large_network_memory_safe(self):
        manifest = ScopeManifest(
            scope_version="large_cidr",
            included_prefixes=["10.0.0.0/8"],
            exclusions=["10.254.0.0/16"],
            locked_at=utc_now(),
        )
        gate = PolicyGate(manifest)
        # Check contained subnet
        res = gate.check_destination("10.50.0.0/16")
        self.assertEqual(res.decision, ScopeDecision.ALLOW)
        # Check exclusion overlap fails closed
        res_ex = gate.check_destination("10.254.10.0/24")
        self.assertEqual(res_ex.decision, ScopeDecision.DENY)
        # Check host
        res_host = gate.check_destination("10.1.2.3")
        self.assertEqual(res_host.decision, ScopeDecision.ALLOW)

    def test_ipv6_url_prefix_setup(self):
        from cart.scope import setup_scope_for_target
        manifest, _seed = setup_scope_for_target(self.conn, "http://[2001:db8::1]:8080/path")
        self.assertIn("2001:db8::1/128", manifest.included_prefixes)
        self.assertNotIn("2001:db8::1/32", manifest.included_prefixes)
        self.assertIn("2001:db8::1", manifest.included_hosts)

    def test_dns_rebinding_rejected(self):
        manifest = ScopeManifest(
            scope_version="dns_test",
            included_prefixes=["192.168.1.0/24"],
            locked_at=utc_now(),
        )
        gate = PolicyGate(manifest)

        # Initial benign resolution to in-scope IP
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("192.168.1.10", 80))]):
            res1 = gate.check_url("http://dynamic.attacker.lab/")
            self.assertEqual(res1.decision, ScopeDecision.ALLOW)
            self.assertEqual(gate.get_pinned_ip("dynamic.attacker.lab"), "192.168.1.10")

        # Rebinding resolution changes IP
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("10.0.0.99", 80))]):
            res2 = gate.check_url("http://dynamic.attacker.lab/")
            self.assertEqual(res2.decision, ScopeDecision.DENY)
            self.assertIn("rebinding detected", res2.reason.lower())

    def test_scope_guarded_redirect_enforcement(self):
        import urllib.request

        from cart.workers.web import ScopeGuardedRedirectHandler

        manifest = ScopeManifest(
            scope_version="redir_scope",
            included_prefixes=["192.168.1.0/24"],
            exclusions=["192.168.1.250/32"],
            locked_at=utc_now(),
        )
        gate = PolicyGate(manifest)
        handler = ScopeGuardedRedirectHandler(gate, "test_run")
        req = urllib.request.Request("http://192.168.1.10/")

        # In-scope redirect allowed
        res_ok = handler.redirect_request(req, None, 302, "Found", {}, "http://192.168.1.20/dashboard")
        self.assertIsNotNone(res_ok)

        # Excluded redirect dropped (returns None)
        res_blocked = handler.redirect_request(req, None, 302, "Found", {}, "http://192.168.1.250/secret")
        self.assertIsNone(res_blocked)

        # External redirect dropped
        res_ext = handler.redirect_request(req, None, 302, "Found", {}, "http://8.8.8.8/evil")
        self.assertIsNone(res_ext)

    def test_report_metrics_evidence_based(self):
        self.conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s_rep', '[\"192.168.1.0/24\"]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES ('run_rep', 'completed', 'deep', '2026-01-01T00:00:00Z', 's_rep')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_rep', 'run_rep', 'host', '192.168.1.10', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")

        # 2 criticals: 1 confirmed, 1 candidate (50% verification rate)
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f_c1', 'a_rep', 'type1', 'critical', 'confirmed')")
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f_c2', 'a_rep', 'type2', 'critical', 'candidate')")
        # 1 medium: candidate (0% confirmed)
        self.conn.execute("INSERT INTO findings (finding_id, asset_id, finding_type, severity, status) VALUES ('f_m1', 'a_rep', 'type3', 'medium', 'candidate')")
        self.conn.commit()

        rep = ReportGenerator(self.conn)
        result = rep.generate("run_rep")
        metrics = result["metrics"]
        self.assertEqual(metrics["total_findings"], 3)
        self.assertEqual(metrics["confirmed_findings"], 1)

        md_content = Path(result["md_report"]).read_text(encoding="utf-8")
        self.assertIn("50.0%", md_content)
        self.assertIn("0.0%", md_content)

    def test_orchestrator_run_isolation_and_idempotence(self):
        orch_a = Orchestrator(self.conn, run_id="run_AAA", max_tasks=10, total_time_budget_s=60)
        orch_b = Orchestrator(self.conn, run_id="run_BBB", max_tasks=10, total_time_budget_s=60)

        task_a = Task(task_id="t_a1", task_type="scan", owner="network_worker", target_id="target1", dedupe_key="run_AAA:t1", status=TaskStatus.READY)
        task_b = Task(task_id="t_b1", task_type="scan", owner="network_worker", target_id="target2", dedupe_key="run_BBB:t1", status=TaskStatus.READY)
        orch_a.create_task(task_a)
        orch_b.create_task(task_b)

        ready_a = orch_a.ready_tasks()
        ready_b = orch_b.ready_tasks()
        self.assertEqual(len(ready_a), 1)
        self.assertEqual(ready_a[0].task_id, "t_a1")
        self.assertEqual(len(ready_b), 1)
        self.assertEqual(ready_b[0].task_id, "t_b1")

        # Test idempotency: transitioning succeeded -> succeeded should not throw
        orch_a.transition("t_a1", TaskStatus.RUNNING)
        orch_a.transition("t_a1", TaskStatus.SUCCEEDED)
        # Repeated transition to same status should safely no-op
        orch_a.transition("t_a1", TaskStatus.SUCCEEDED)

        # Budget exhaustion on run_AAA should not cancel run_BBB
        orch_a.on_run_budget_exhausted()
        t_b_row = self.conn.execute("SELECT status FROM tasks WHERE task_id='t_b1'").fetchone()
        self.assertEqual(t_b_row[0], TaskStatus.READY.value)

    def test_verification_hardening_prevents_false_positives(self):
        self.conn.execute("INSERT INTO scope_manifests (scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at) VALUES ('s_hard', '[\"192.168.1.0/24\"]', '[]', '[]', '{}', 'test', '2026-01-01T00:00:00Z')")
        self.conn.execute("INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES ('r_hard', 'active', 'deep', '2026-01-01T00:00:00Z', 's_hard')")
        self.conn.execute("INSERT INTO assets (asset_id, run_id, asset_type, canonical_key, first_seen, last_seen) VALUES ('a_hard', 'r_hard', 'web_app', 'test.app', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")

        # State-changing POST form without anti-CSRF token should return NEEDS_REVIEW, not CONFIRMED
        fid = "f_form_unverified"
        form_payload = json.dumps({
            "action": "/api/transfer",
            "method": "POST",
            "inputs": [{"name": "recipient", "type": "text"}, {"name": "amount", "type": "number"}],
        })
        self.conn.execute(
            "INSERT INTO findings (finding_id, asset_id, finding_type, severity, status, summary) VALUES (?, 'a_hard', 'web_form_endpoint', 'medium', 'candidate', 'Form test')",
            (fid,),
        )
        self.conn.execute(
            "INSERT INTO evidence (evidence_id, finding_id, source_tool, artifact_path, hash, timestamp, excerpt) VALUES ('ev_form', ?, 'web_crawler', 'http://test.app/api/transfer', 'h1', '2026-01-01T00:00:00Z', ?)",
            (fid, form_payload),
        )
        svc = VerificationService(self.conn, "r_hard")
        svc.queue([fid])
        verdict = svc.verify_one(fid)
        self.assertEqual(verdict, FindingStatus.NEEDS_REVIEW)

    def test_network_worker_udp_and_all_ports_config(self):
        from cart.workers.network import NetworkWorker
        manifest = ScopeManifest(
            scope_version="net_scope",
            included_prefixes=["192.168.1.0/24"],
            locked_at=utc_now(),
        )
        gate = PolicyGate(manifest)
        worker = NetworkWorker(self.conn, gate, "run_net", all_ports=True, scan_udp=True)
        self.assertTrue(worker.all_ports)
        self.assertTrue(worker.scan_udp)


if __name__ == "__main__":
    unittest.main()
