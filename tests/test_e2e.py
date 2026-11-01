"""Comprehensive end-to-end integration test for the CyberForge CART pipeline.

Spins up a local HTTP lab server and validates:
1. Scope manifest creation & cryptographic lock.
2. Network worker host & service discovery.
3. Web worker crawling, header auditing, and scope-guarded redirect blocking.
4. Web-to-binary hand-off and Binary worker static ELF inspection.
5. Deterministic verification service confirming genuine findings.
6. Multi-hop attack path graph derivation.
7. Final PTES report and JSON deliverables generation.
"""

from __future__ import annotations

import http.server
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from cart.attackpath import AttackPathBuilder, derive_run_relationships
from cart.models import Task, TaskStatus, utc_now
from cart.orchestrator import Orchestrator
from cart.report import ReportGenerator
from cart.scope import PolicyGate, setup_scope_for_target
from cart.store import connect
from cart.verify import VerificationService
from cart.workers.binary import BinaryWorker
from cart.workers.network import NetworkWorker
from cart.workers.web import WebWorker


class _MockLabHandler(http.server.BaseHTTPRequestHandler):
    """Realistic local HTTP testbed server."""

    def log_message(self, format: str, *args) -> None:
        pass  # Suppress HTTP access logging in test output

    def do_GET(self) -> None:
        path = self.path

        if path == "/":
            body = (
                b"<html><head><title>CART Local Lab</title></head><body>"
                b"<h1>Welcome to CART Local Lab</h1>"
                b"<a href='/login'>Login Portal</a>"
                b"<a href='/robots.txt'>Robots</a>"
                b"<a href='/ftp'>Directory Listing</a>"
                b"<a href='/download/sample.elf'>Download Agent</a>"
                b"<a href='/in_scope_redirect'>Redirect In Scope</a>"
                b"<a href='/out_of_scope_redirect'>Redirect Out of Scope</a>"
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Werkzeug/2.0.1 Python/3.11")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Access-Control-Allow-Origin", "*")
            # Intentionally omit X-Frame-Options, CSP, HSTS
            self.end_headers()
            self.wfile.write(body)

        elif path == "/login":
            body = (
                b"<html><body>"
                b"<form action='/api/auth' method='POST'>"
                b"<input type='text' name='username'>"
                b"<input type='password' name='password'>"
                b"<input type='submit' value='Login'>"
                b"</form></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        elif path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\nDisallow: /secrets\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        elif path == "/ftp":
            body = b"<html><head><title>Index of /ftp</title></head><body><h1>Index of /ftp</h1><a href='secret.txt'>secret.txt</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        elif path == "/download/sample.elf":
            # Valid ELF header with embedded strcpy string reference
            elf_header = (
                b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x02\x00\x3e\x00\x01\x00\x00\x00"
            )
            body = elf_header + b"\x00" * 32 + b"strcpy\x00system\x00FLAG{local_lab_test_flag_123}\x00"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(body)

        elif path == "/in_scope_redirect":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

        elif path == "/out_of_scope_redirect":
            self.send_response(302)
            self.send_header("Location", "http://198.51.100.254/forbidden")
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()


class TestEndToEndAssessment(unittest.TestCase):
    """End-to-end assessment test against local HTTP lab target."""

    @classmethod
    def setUpClass(cls) -> None:
        # Find a free local ephemeral port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.server = http.server.HTTPServer(("127.0.0.1", cls.port), _MockLabHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_e2e.db"
        self.conn = connect(self.db_path)
        self.run_id = "run_e2e_test"

    def tearDown(self) -> None:
        self.conn.close()
        self.tmpdir.cleanup()

    def test_full_pipeline_end_to_end(self) -> None:
        target_url = f"http://127.0.0.1:{self.port}/"

        # -------------------------------------------------------------
        # Step 1: Scope Setup & Cryptographic Locking
        # -------------------------------------------------------------
        manifest, seed_url = setup_scope_for_target(self.conn, target_url)
        self.assertIsNotNone(manifest.locked_at)
        self.assertIn("127.0.0.1/32", manifest.included_prefixes)
        self.assertEqual(seed_url, target_url)

        # Record active run in SQLite
        self.conn.execute(
            "INSERT INTO runs (run_id, status, tier, started_at, scope_version) VALUES (?, ?, ?, ?, ?)",
            (self.run_id, "active", "deep", utc_now(), manifest.scope_version),
        )
        self.conn.commit()

        gate = PolicyGate(manifest)
        gate.bind_store(self.conn)

        # -------------------------------------------------------------
        # Step 2: Initialize Orchestrator & Workers
        # -------------------------------------------------------------
        orchestrator = Orchestrator(self.conn, run_id=self.run_id, max_concurrency=4)

        net_worker = NetworkWorker(self.conn, gate, self.run_id, all_ports=False, scan_udp=False)
        web_worker = WebWorker(
            self.conn,
            gate,
            self.run_id,
            max_pages=25,
            binary_cache_dir=Path(self.tmpdir.name) / "binaries",
        )
        bin_worker = BinaryWorker(self.conn, gate, self.run_id)

        # -------------------------------------------------------------
        # Step 3: Network Discovery Task
        # -------------------------------------------------------------
        net_task = Task(
            task_id="t_net",
            task_type="network_recon",
            owner="network_worker",
            target_id="127.0.0.1",
            dedupe_key=f"{self.run_id}:net:127.0.0.1",
            status=TaskStatus.READY,
            budget={"ports": [self.port], "scan_udp": False},
        )
        orchestrator.create_task(net_task)
        orchestrator.transition("t_net", TaskStatus.RUNNING)

        net_result = net_worker.run(net_task)
        self.assertGreaterEqual(len(net_result["assets"]), 1)
        self.assertGreaterEqual(net_result["services"], 1)
        orchestrator.transition("t_net", TaskStatus.SUCCEEDED)

        # -------------------------------------------------------------
        # Step 4: Web Application Crawl & Audit Task
        # -------------------------------------------------------------
        web_task = Task(
            task_id="t_web",
            task_type="web_crawl",
            owner="web_worker",
            target_id=target_url,
            dedupe_key=f"{self.run_id}:web:{target_url}",
            status=TaskStatus.READY,
        )
        orchestrator.create_task(web_task)
        orchestrator.transition("t_web", TaskStatus.RUNNING)

        web_result = web_worker.run(web_task)
        self.assertIn("endpoints", web_result)
        self.assertGreater(len(web_result["endpoints"]), 1)
        orchestrator.transition("t_web", TaskStatus.SUCCEEDED)

        # Verify binary file was discovered and downloaded into local cache
        discovered_bins = web_result.get("discovered_binaries", [])
        self.assertGreaterEqual(len(discovered_bins), 1)
        bin_entry = discovered_bins[0]
        self.assertTrue(Path(bin_entry["path"]).exists())

        # Verify out-of-scope redirect was blocked by ScopeGuardedRedirectHandler
        self.assertNotIn("http://198.51.100.254/forbidden", web_result["endpoints"])

        # -------------------------------------------------------------
        # Step 5: Binary Static Inspection Task
        # -------------------------------------------------------------
        bin_task = Task(
            task_id="t_bin",
            task_type="binary_audit",
            owner="binary_worker",
            target_id=bin_entry["path"],
            dedupe_key=f"{self.run_id}:bin:{bin_entry['path']}",
            status=TaskStatus.READY,
        )
        orchestrator.create_task(bin_task)
        orchestrator.transition("t_bin", TaskStatus.RUNNING)

        bin_result = bin_worker.run(bin_task)
        self.assertIn("findings", bin_result)
        orchestrator.transition("t_bin", TaskStatus.SUCCEEDED)

        # -------------------------------------------------------------
        # Step 6: Verification Service Evaluation
        # -------------------------------------------------------------
        candidate_ids = [
            r[0]
            for r in self.conn.execute("SELECT finding_id FROM findings WHERE status = 'candidate'").fetchall()
        ]
        self.assertGreaterEqual(len(candidate_ids), 1)

        verifier = VerificationService(self.conn, run_id=self.run_id)
        verifier.queue(candidate_ids)
        verdicts = verifier.verify_all_queued()
        self.assertGreaterEqual(len(verdicts), 1)

        # Check findings recorded in SQLite
        confirmed_count = self.conn.execute(
            "SELECT count(*) FROM findings WHERE status = 'confirmed'",
        ).fetchone()[0]
        self.assertGreaterEqual(confirmed_count, 1)

        # -------------------------------------------------------------
        # Step 7: Attack Path Graph Derivation
        # -------------------------------------------------------------
        rel_count = derive_run_relationships(self.conn)
        self.assertGreaterEqual(rel_count, 1)

        path_builder = AttackPathBuilder(self.conn, self.run_id)
        paths = path_builder.build()
        self.assertGreaterEqual(len(paths), 1)

        # -------------------------------------------------------------
        # Step 8: Final Report Generation & Inspection
        # -------------------------------------------------------------
        # Mark run completed
        self.conn.execute(
            "UPDATE runs SET status = 'completed', completed_at = ? WHERE run_id = ?",
            (utc_now(), self.run_id),
        )
        self.conn.commit()

        rep = ReportGenerator(self.conn)
        report_data = rep.generate(self.run_id)

        # Assert deliverables generated
        self.assertTrue(Path(report_data["md_report"]).exists())
        self.assertTrue(Path(report_data["json_report"]).exists())

        metrics = report_data["metrics"]
        self.assertGreaterEqual(metrics["total_findings"], 1)
        self.assertGreaterEqual(metrics["confirmed_findings"], 1)
        # Verify evidence-based scope metric: 0 leaks
        self.assertEqual(metrics["scope_safety_out_of_bounds_probes"], 0)
        # Verify non-hardcoded autonomy and false alarm indicators
        self.assertEqual(metrics["autonomy_interventions"], "Not measured")
        self.assertEqual(metrics["false_alarm_rate"], "Not measured")

        # Inspect generated markdown content
        md_text = Path(report_data["md_report"]).read_text(encoding="utf-8")
        self.assertIn("PTES Standard", md_text)
        self.assertIn("Vulnerability Severity & Verification Matrix", md_text)
        self.assertIn("Scope Boundary Leaks", md_text)
        self.assertIn("✅ PASS", md_text)


if __name__ == "__main__":
    unittest.main()
