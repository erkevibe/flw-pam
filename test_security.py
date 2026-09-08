"""Independent negative acceptance checks for the documented laboratory API."""
import concurrent.futures
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from workflow import Workflow


class SecurityAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "lab.sqlite"
        self.now = 100.0
        self.workflow = Workflow(self.db, clock=lambda: self.now)

    def request(self, **changes):
        args = dict(actor="alice", resource="db-read", reason="maintenance", ttl=10)
        args.update(changes)
        return self.workflow.request(**args)

    def test_bad_ttl_and_clock_never_commit(self):
        for ttl in (0, -1, 3601, True, False, 1.0, float("nan"), float("inf"), "1", None):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                self.request(ttl=ttl)
        self.assertEqual(self.workflow.audit(), [])
        for timestamp in (-1, True, float("nan"), float("inf"), None, "100"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                clocked = Workflow(self.db, clock=lambda: timestamp)
                clocked.request("alice", "db-read", "clock check")
        self.assertEqual(self.workflow.audit(), [])

    def test_self_approval_denial_and_unauthorized_revoke(self):
        request_id = self.request()["id"]
        for action in (lambda: self.workflow.approve("alice", request_id),
                       lambda: self.workflow.deny("alice", request_id, "self-deny")):
            with self.assertRaises(ValueError):
                action()
        self.assertEqual(len(self.workflow.audit()), 1)
        self.workflow.approve("bob", request_id)
        with self.assertRaises(ValueError):
            self.workflow.revoke("mallory", request_id, "unauthorized")
        self.assertEqual(self.workflow.get(request_id)["status"], "approved")
        self.assertEqual(len(self.workflow.audit()), 2)

    def test_expiry_boundary_reason_priority_and_expired_revoke(self):
        request_id = self.request()["id"]
        self.workflow.approve("bob", request_id)
        self.now = 109.999
        self.assertTrue(self.workflow.check(request_id, "alice", "db-read")["allowed"])
        self.now = 110
        self.assertEqual(self.workflow.check(request_id, "alice", "db-read")["reason"], "expired")
        self.assertEqual(self.workflow.check(request_id, "mallory", "server-shell")["reason"], "resource_mismatch")
        self.assertEqual(self.workflow.check(request_id, "mallory", "db-read")["reason"], "actor_mismatch")
        self.assertEqual(self.workflow.check("missing", "mallory", "db-read")["reason"], "unknown_request")
        self.assertEqual(len(self.workflow.audit()), 2)
        self.workflow.revoke("alice", request_id, "cleanup expired approval")
        self.assertEqual(self.workflow.get(request_id)["status"], "revoked")

    def test_expired_pending_cannot_be_approved_or_denied(self):
        request_id = self.request()["id"]
        self.now = 110
        for action in (lambda: self.workflow.approve("bob", request_id),
                       lambda: self.workflow.deny("bob", request_id, "late")):
            with self.assertRaises(ValueError):
                action()
        self.assertEqual(len(self.workflow.audit()), 1)
        self.assertEqual(self.workflow.get(request_id)["status"], "pending")

    def test_allowlist_persistence_and_sql_values(self):
        with self.assertRaises(ValueError):
            self.request(resource="unknown")
        actor = "alice'; DROP TABLE requests; --"
        record = self.request(actor=actor, reason="'; SELECT * FROM audit; --")
        reopened = Workflow(self.db, clock=lambda: self.now)
        self.assertEqual(reopened.get(record["id"])["actor"], actor)
        self.assertEqual(len(reopened.audit()), 1)
        with self.assertRaises(ValueError):
            Workflow(self.db, resources=("different",))
        self.assertEqual(reopened.get(record["id"]), record)

    def test_concurrent_approval_single_winner(self):
        request_id = self.request()["id"]
        barrier = threading.Barrier(2)

        def approve(actor):
            barrier.wait(timeout=5)
            try:
                self.workflow.approve(actor, request_id)
                return actor
            except ValueError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(approve, ("bob", "carol")))
        winners = [actor for actor in results if actor is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(self.workflow.get(request_id)["approved_by"], winners[0])
        self.assertEqual([event["action"] for event in self.workflow.audit()], ["request", "approve"])

    def test_audit_write_failure_rolls_back_approval(self):
        request_id = self.request()["id"]
        with sqlite3.connect(self.db) as connection:
            audit_tables = []
            for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                quoted = '"' + name.replace('"', '""') + '"'
                columns = {row[1] for row in connection.execute("PRAGMA table_info(" + quoted + ")")}
                if {"action", "actor", "request_id"} <= columns:
                    audit_tables.append(quoted)
            self.assertEqual(len(audit_tables), 1, "Cannot identify unique audit table")
            connection.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON " + audit_tables[0] +
                               " BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END")
        with self.assertRaises(Exception):
            self.workflow.approve("bob", request_id)
        self.assertEqual(self.workflow.get(request_id)["status"], "pending")
        self.assertIsNone(self.workflow.get(request_id)["approved_by"])
        self.assertEqual(len(self.workflow.audit()), 1)

    def test_cli_json_exit_codes(self):
        script = Path(__file__).with_name("workflow.py")

        def invoke(*args):
            result = subprocess.run([sys.executable, "-B", str(script), "--db", str(self.db), *args],
                                    capture_output=True, text=True, timeout=10)
            return result.returncode, json.loads(result.stdout or result.stderr)

        code, record = invoke("request", "--actor", "alice", "--resource", "db-read", "--reason", "CLI")
        self.assertEqual(code, 0)
        request_id = record["id"]
        self.assertEqual(invoke("check", request_id, "--actor", "alice", "--resource", "db-read")[0], 1)
        self.assertEqual(invoke("approve", request_id, "--actor", "alice")[0], 2)
        self.assertEqual(invoke("approve", request_id, "--actor", "bob")[0], 0)
        self.assertEqual(invoke("check", request_id, "--actor", "alice", "--resource", "db-read")[0], 0)


if __name__ == "__main__":
    unittest.main()
