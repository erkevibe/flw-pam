"""Independent tests of CONTRACT.md; all databases live in temporary directories."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from workflow import Workflow


SCRIPT = Path(__file__).resolve().with_name("workflow.py")
BAD_TEXT = (None, True, 17, 1.5, [], {}, "", " ", "\t\n")


def quote_identifier(name):
    # Identifiers come only from SQLite's schema, never from workflow inputs.
    return '"' + name.replace('"', '""') + '"'


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workflow-qa-")
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "workflow.sqlite"
        self.now = 1000.25
        self.workflow = Workflow(self.db, clock=lambda: self.now)

    def snapshot(self, db=None):
        """Observe committed application rows, including otherwise hidden requests."""
        with closing(sqlite3.connect(db or self.db)) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            return {
                name: sorted(connection.execute(
                    "SELECT * FROM " + quote_identifier(name)
                ).fetchall(), key=repr)
                for (name,) in tables
            }

    def invalid(self, call):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            call()
        self.assertEqual(self.snapshot(), before, "invalid operation mutated storage")

    def request(self, **kwargs):
        args = dict(actor="alice", resource="db-read", reason="investigation", ttl=30)
        args.update(kwargs)
        return self.workflow.request(**args)

    def assert_record(self, record, *, actor="alice", resource="db-read",
                      reason="investigation", ttl=30, created_at=1000.25,
                      status="pending", approved_by=None):
        self.assertIsInstance(record, dict)
        self.assertIsInstance(record["id"], str)
        self.assertTrue(record["id"].strip())
        for key, value in dict(actor=actor, resource=resource, reason=reason, ttl=ttl,
                               created_at=created_at, expires_at=created_at + ttl,
                               status=status, approved_by=approved_by).items():
            self.assertEqual(record[key], value, key)
        json.dumps(record, allow_nan=False)

    def assert_decision(self, request_id, reason, actor="alice", resource="db-read"):
        before = self.snapshot()
        result = self.workflow.check(request_id, actor, resource)
        self.assertIsInstance(result, dict)
        self.assertIs(type(result["allowed"]), bool)
        self.assertEqual(result["allowed"], reason == "allowed")
        self.assertEqual(result["reason"], reason)
        json.dumps(result, allow_nan=False)
        self.assertEqual(self.snapshot(), before, "check must be read-only")

    def assert_events(self, expected):
        """Expected tuples: (action, actor, id, timestamp, required details)."""
        events = self.workflow.audit()
        self.assertIsInstance(events, list)
        self.assertEqual(len(events), len(expected))
        sequences = []
        for event, (action, actor, request_id, timestamp, details) in zip(events, expected):
            self.assertIs(type(event["seq"]), int)
            sequences.append(event["seq"])
            self.assertIsInstance(event["timestamp"], (int, float))
            self.assertNotIsInstance(event["timestamp"], bool)
            self.assertTrue(math.isfinite(event["timestamp"]))
            self.assertEqual(event["timestamp"], timestamp)
            self.assertEqual(event["action"], action)
            self.assertEqual(event["actor"], actor)
            self.assertEqual(event["request_id"], request_id)
            self.assertIsInstance(event["details"], dict)
            for key, value in details.items():
                self.assertEqual(event["details"][key], value)
        self.assertEqual(sequences, sorted(set(sequences)))
        json.dumps(events, allow_nan=False)

    def test_full_lifecycle_and_audit(self):
        record = self.request()
        self.assert_record(record)
        request_id = record["id"]
        self.assert_decision(request_id, "not_approved")
        self.now += 5
        approved = self.workflow.approve(actor="bob", request_id=request_id)
        self.assert_record(approved, status="approved", approved_by="bob")
        self.assertEqual(approved["id"], request_id)
        self.assert_decision(request_id, "allowed")
        self.now += 5
        revoked = self.workflow.revoke("alice", request_id, "finished")
        self.assert_record(revoked, status="revoked", approved_by="bob")
        self.assertEqual(revoked["id"], request_id)
        self.assert_decision(request_id, "not_approved")
        before = self.snapshot()
        self.assertEqual(self.workflow.get(request_id=request_id), revoked)
        self.assert_events([
            ("request", "alice", request_id, 1000.25,
             {"resource": "db-read", "reason": "investigation", "ttl": 30}),
            ("approve", "bob", request_id, 1005.25, {}),
            ("revoke", "alice", request_id, 1010.25, {"reason": "finished"}),
        ])
        self.assertEqual(self.snapshot(), before, "get/audit must be read-only")

    def test_defaults_ttl_endpoints_and_unique_ids(self):
        default = self.workflow.request("alice", "server-shell", "maintenance")
        self.assert_record(default, resource="server-shell", reason="maintenance", ttl=300)
        records = [default] + [self.request(ttl=ttl) for ttl in (1, 3600, 30, 30)]
        self.assertEqual(len({r["id"] for r in records}), len(records))
        for record, ttl in zip(records[1:], (1, 3600, 30, 30)):
            self.assert_record(record, ttl=ttl)
        self.assertEqual(len(self.workflow.audit()), len(records))

    def test_invalid_request_inputs_leave_no_rows_or_events(self):
        for field in ("actor", "reason", "resource"):
            for value in BAD_TEXT:
                with self.subTest(field=field, value=value):
                    self.invalid(lambda: self.request(**{field: value}))
        for ttl in (True, False, 0, -1, 3601, 10**100, 1.0, "300", None, [], {}):
            with self.subTest(ttl=ttl):
                self.invalid(lambda: self.request(ttl=ttl))
        for resource in ("admin", "DB-READ", "db-read ", "*", "../db-read"):
            with self.subTest(resource=resource):
                self.invalid(lambda: self.request(resource=resource))
        self.assertEqual(self.workflow.audit(), [])

    def test_resource_configuration_validation_and_durable_policy(self):
        invalid_lists = (None, "db-read", {"db-read"}, [], (), [""], [1], [True],
                         [None], [["nested"]], ["same", "same"])
        for index, resources in enumerate(invalid_lists):
            with self.subTest(resources=resources):
                with self.assertRaises(ValueError):
                    Workflow(Path(self.temp.name) / f"bad-{index}.db",
                             resources=resources, clock=lambda: self.now)
        custom_db = Path(self.temp.name) / "custom.db"
        resources = ["reports", "custom-shell"]
        custom = Workflow(custom_db, resources, lambda: self.now)
        record = custom.request("alice", "reports", "custom access")
        reopened = Workflow(str(custom_db), tuple(resources), lambda: self.now)
        self.assertEqual(reopened.get(record["id"]), record)
        self.assertEqual(reopened.audit(), custom.audit())
        before = self.snapshot(custom_db)
        for different in (["reports"], ["reports", "custom-shell", "admin"],
                          ["other", "custom-shell"], ("db-read", "server-shell")):
            with self.subTest(different=different):
                with self.assertRaises(ValueError):
                    Workflow(custom_db, different, lambda: self.now)
                self.assertEqual(self.snapshot(custom_db), before)
        with self.assertRaises(ValueError):
            reopened.request("alice", "db-read", "not configured")
        self.assertEqual(self.snapshot(custom_db), before)

    def test_persistence_and_idempotent_initialization(self):
        pending = self.request()
        approved = self.request(resource="server-shell")
        self.workflow.approve("bob", approved["id"])
        denied = self.request()
        self.workflow.deny("carol", denied["id"], "policy")
        revoked = self.request()
        self.workflow.approve("bob", revoked["id"])
        self.workflow.revoke("bob", revoked["id"], "done")
        before = self.snapshot()
        for _ in range(2):
            other = Workflow(str(self.db), clock=lambda: self.now)
            for record in (pending, approved, denied, revoked):
                self.assertEqual(other.get(record["id"]), self.workflow.get(record["id"]))
            self.assertEqual(other.audit(), self.workflow.audit())
            self.assertEqual(self.snapshot(), before)
        other.approve("dave", pending["id"])
        self.assertEqual(self.workflow.get(pending["id"])["approved_by"], "dave")
        self.assertEqual(self.workflow.audit(), other.audit())

    def test_self_approval_self_denial_and_unauthorized_revocation(self):
        request_id = self.request()["id"]
        self.invalid(lambda: self.workflow.approve("alice", request_id))
        self.invalid(lambda: self.workflow.deny("alice", request_id, "self"))
        self.invalid(lambda: self.workflow.revoke("alice", request_id, "pending"))
        self.workflow.approve("bob", request_id)
        for actor in ("carol", "admin", "root", "administrator"):
            with self.subTest(actor=actor):
                self.invalid(lambda: self.workflow.revoke(actor, request_id, "override"))
                self.assert_decision(request_id, "actor_mismatch", actor=actor)
        self.assert_decision(request_id, "actor_mismatch", actor="bob")
        revoked = self.workflow.revoke(actor="bob", request_id=request_id, reason="done")
        self.assertEqual(revoked["status"], "revoked")

    def test_denial_audit_and_terminal_states(self):
        request_id = self.request()["id"]
        self.now += 1
        denied = self.workflow.deny(actor="bob", request_id=request_id, reason="policy")
        self.assert_record(denied, status="denied")
        self.assert_decision(request_id, "not_approved")
        self.assert_events([
            ("request", "alice", request_id, 1000.25,
             {"resource": "db-read", "reason": "investigation", "ttl": 30}),
            ("deny", "bob", request_id, 1001.25, {"reason": "policy"}),
        ])
        for status in ("denied", "revoked"):
            if status == "revoked":
                request_id = self.request()["id"]
                self.workflow.approve("bob", request_id)
                self.workflow.revoke("alice", request_id, "done")
            for actor in ("alice", "bob", "carol"):
                with self.subTest(status=status, actor=actor):
                    self.invalid(lambda: self.workflow.approve(actor, request_id))
                    self.invalid(lambda: self.workflow.deny(actor, request_id, "again"))
                    self.invalid(lambda: self.workflow.revoke(actor, request_id, "again"))

    def test_approved_cannot_be_approved_or_denied_again(self):
        request_id = self.request()["id"]
        self.workflow.approve("bob", request_id)
        for actor in ("bob", "carol"):
            with self.subTest(actor=actor):
                self.invalid(lambda: self.workflow.approve(actor, request_id))
                self.invalid(lambda: self.workflow.deny(actor, request_id, "too late"))

    def test_expiry_boundary_and_approval_does_not_extend_lifetime(self):
        pending = self.request()["id"]
        approved = self.request()["id"]
        self.now = 1030.249
        result = self.workflow.approve("bob", approved)
        self.assertEqual(result["expires_at"], 1030.25)
        self.assert_decision(approved, "allowed")
        self.assert_decision(pending, "not_approved")
        for timestamp in (1030.25, 1031.25):
            self.now = timestamp
            with self.subTest(timestamp=timestamp):
                self.assert_decision(approved, "expired")
                self.assert_decision(pending, "expired")
                self.invalid(lambda: self.workflow.approve("bob", pending))
                self.invalid(lambda: self.workflow.deny("bob", pending, "too late"))
        self.assertEqual(self.workflow.get(pending)["status"], "pending")
        self.assertEqual(self.workflow.get(approved)["status"], "approved")

    def test_expired_approved_request_can_be_revoked_by_either_authorized_actor(self):
        for actor in ("alice", "bob"):
            with self.subTest(actor=actor):
                record = self.request()
                self.workflow.approve("bob", record["id"])
                self.now = record["expires_at"]
                revoked = self.workflow.revoke(actor, record["id"], "expired cleanup")
                self.assertEqual(revoked["status"], "revoked")
                self.assertEqual(revoked["expires_at"], record["expires_at"])
                self.assert_decision(record["id"], "expired")
                self.assertEqual(self.workflow.audit()[-1]["action"], "revoke")

    def test_check_precedence_and_unknown_ids(self):
        request_id = self.request()["id"]
        self.now = 1030.25
        self.assert_decision("missing", "unknown_request", "other", "unlisted")
        self.assert_decision(request_id, "resource_mismatch", "other", "unlisted")
        self.assert_decision(request_id, "actor_mismatch", "other")
        self.assert_decision(request_id, "expired")
        self.now = 1000.25
        self.assert_decision(request_id, "not_approved")
        self.workflow.approve("bob", request_id)
        self.assert_decision(request_id, "resource_mismatch", resource="server-shell")
        self.assert_decision(request_id, "actor_mismatch", actor="bob")
        self.assert_decision(request_id, "allowed")
        self.invalid(lambda: self.workflow.get("missing"))
        self.invalid(lambda: self.workflow.approve("bob", "missing"))
        self.invalid(lambda: self.workflow.deny("bob", "missing", "policy"))
        self.invalid(lambda: self.workflow.revoke("alice", "missing", "done"))

    def test_invalid_check_arguments(self):
        request_id = self.request()["id"]
        for field in ("request_id", "actor", "resource"):
            for value in BAD_TEXT:
                with self.subTest(field=field, value=value):
                    args = dict(request_id=request_id, actor="alice", resource="db-read")
                    args[field] = value
                    self.invalid(lambda: self.workflow.check(**args))

    def test_invalid_transition_arguments(self):
        pending = self.request()["id"]
        approved = self.request()["id"]
        self.workflow.approve("bob", approved)
        # The transition contract says nonempty, while check/request explicitly
        # reject whitespace; avoid imposing extra whitespace semantics here.
        for value in (None, True, 17, 1.5, [], {}, ""):
            with self.subTest(value=value):
                self.invalid(lambda: self.workflow.approve(value, pending))
                self.invalid(lambda: self.workflow.deny(value, pending, "policy"))
                self.invalid(lambda: self.workflow.revoke(value, approved, "done"))
                self.invalid(lambda: self.workflow.deny("bob", pending, value))
                self.invalid(lambda: self.workflow.revoke("alice", approved, value))

    def test_clock_validation_at_initialization_and_during_operations(self):
        bad_values = (True, False, None, "1000", -1, float("nan"),
                      float("inf"), float("-inf"), 1j, [], {})
        for index, value in enumerate(bad_values):
            with self.subTest(initial_clock=value):
                with self.assertRaises(ValueError):
                    Workflow(Path(self.temp.name) / f"clock-{index}.db", clock=lambda: value)
        with self.assertRaises(ValueError):
            Workflow(Path(self.temp.name) / "not-callable.db", clock=1000)
        pending = self.request()["id"]
        approved = self.request()["id"]
        self.workflow.approve("bob", approved)
        for value in bad_values:
            self.now = value
            with self.subTest(runtime_clock=value):
                self.invalid(lambda: self.request())
                self.invalid(lambda: self.workflow.approve("bob", pending))
                self.invalid(lambda: self.workflow.deny("bob", pending, "policy"))
                self.invalid(lambda: self.workflow.revoke("alice", approved, "done"))
                self.invalid(lambda: self.workflow.check(approved, "alice", "db-read"))
        self.now = 0
        self.assert_record(self.request(), created_at=0)

    def test_sql_payloads_are_literal_data(self):
        payload = "x'); DROP TABLE requests; --\n雪\x00"
        reason = "' OR 1=1; UPDATE audit SET actor='root'; --"
        db = Path(self.temp.name) / "quoted.db"
        custom = Workflow(db, resources=(payload,), clock=lambda: self.now)
        record = custom.request(payload, payload, reason, 300)
        self.assert_record(record, actor=payload, resource=payload, reason=reason, ttl=300)
        approver = "bob' OR '1'='1"
        custom.approve(approver, record["id"])
        self.assertEqual(custom.check(record["id"], payload, payload)["reason"], "allowed")
        before = self.snapshot(db)
        malicious_id = "' OR 1=1 --"
        for operation in (
            lambda: custom.get(malicious_id),
            lambda: custom.approve(approver, malicious_id),
            lambda: custom.deny(approver, malicious_id, reason),
            lambda: custom.revoke(payload, malicious_id, reason),
        ):
            with self.assertRaises(ValueError):
                operation()
            self.assertEqual(self.snapshot(db), before)
        self.assertEqual(custom.check(malicious_id, payload, payload)["reason"], "unknown_request")
        self.assertEqual(self.snapshot(db), before)
        custom.revoke(payload, record["id"], reason)
        second = custom.request(payload, payload, reason)
        custom.deny(approver, second["id"], reason)
        self.assertEqual(custom.get(record["id"])["reason"], reason)
        events = custom.audit()
        self.assertEqual([event["action"] for event in events],
                         ["request", "approve", "revoke", "request", "deny"])
        for event in events:
            if event["action"] != "approve":
                self.assertEqual(event["details"]["reason"], reason)
        reopened = Workflow(db, (payload,), lambda: self.now)
        self.assertEqual(reopened.audit(), events)
        json.dumps(events, allow_nan=False)

    def test_concurrent_approval_has_exactly_one_winner(self):
        other = Workflow(self.db, clock=lambda: self.now)
        for shared_instance in (True, False):
            for round_number in range(3):
                with self.subTest(shared_instance=shared_instance, round=round_number):
                    request_id = self.request()["id"]
                    before_count = len(self.workflow.audit())
                    barrier = threading.Barrier(4)

                    def compete(index):
                        instance = self.workflow if shared_instance or index % 2 == 0 else other
                        actor = f"approver-{index}"
                        barrier.wait(timeout=10)
                        try:
                            return actor, instance.approve(actor, request_id)
                        except ValueError:
                            return actor, None

                    with ThreadPoolExecutor(max_workers=4) as pool:
                        futures = [pool.submit(compete, index) for index in range(4)]
                        results = [future.result(timeout=40) for future in futures]
                    winners = [(actor, record) for actor, record in results if record is not None]
                    self.assertEqual(len(winners), 1, results)
                    actor, record = winners[0]
                    self.assert_record(record, status="approved", approved_by=actor)
                    self.assertEqual(self.workflow.get(request_id), record)
                    events = self.workflow.audit()
                    self.assertEqual(len(events), before_count + 1)
                    self.assertEqual(events[-1]["action"], "approve")
                    self.assertEqual(events[-1]["request_id"], request_id)
                    self.assertEqual(events[-1]["actor"], actor)

    def test_audit_insertion_failure_rolls_back_every_mutation(self):
        for action in ("request", "approve", "deny", "revoke"):
            with self.subTest(action=action):
                request_id = self.request()["id"]
                if action == "revoke":
                    self.workflow.approve("bob", request_id)
                operations = {
                    "request": lambda: self.request(reason="must roll back"),
                    "approve": lambda: self.workflow.approve("bob", request_id),
                    "deny": lambda: self.workflow.deny("bob", request_id, "policy"),
                    "revoke": lambda: self.workflow.revoke("alice", request_id, "done"),
                }
                with closing(sqlite3.connect(self.db, isolation_level=None)) as connection:
                    tables = connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                    audit_tables = []
                    for (name,) in tables:
                        columns = {row[1] for row in connection.execute(
                            "PRAGMA table_info(" + quote_identifier(name) + ")"
                        )}
                        if {"action", "request_id", "details"} <= columns:
                            audit_tables.append(name)
                    self.assertEqual(len(audit_tables), 1, "identify the audit table by its schema")
                    connection.execute(
                        "CREATE TRIGGER qa_reject_audit AFTER INSERT ON "
                        + quote_identifier(audit_tables[0])
                        + " BEGIN SELECT RAISE(ABORT, 'QA injected audit failure'); END"
                    )
                before = self.snapshot()
                before_events = self.workflow.audit()
                try:
                    # The contract requires rollback but does not prescribe the
                    # exception class for an underlying SQLite storage failure.
                    with self.assertRaises(Exception):
                        operations[action]()
                    self.assertEqual(self.snapshot(), before, "request mutation escaped rollback")
                    reopened = Workflow(self.db, clock=lambda: self.now)
                    self.assertEqual(reopened.audit(), before_events)
                    self.assertEqual(reopened.get(request_id), self.workflow.get(request_id))
                finally:
                    with closing(sqlite3.connect(self.db, isolation_level=None)) as connection:
                        connection.execute("DROP TRIGGER qa_reject_audit")
                recovered = operations[action]()
                self.assertEqual(recovered["status"], {
                    "request": "pending", "approve": "approved", "deny": "denied", "revoke": "revoked"
                }[action])
                self.assertEqual(len(self.workflow.audit()), len(before_events) + 1)
                self.assertEqual(self.workflow.audit()[-1]["action"], action)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workflow-cli-qa-")
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "cli.sqlite"

    def cli(self, *args, code=0):
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--db", str(self.db), *args],
            cwd=self.temp.name, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, code, (result.stdout, result.stderr))
        # json.loads rejects trailing documents and non-JSON status output.
        try:
            document = json.loads(result.stdout)
        except ValueError as error:
            self.fail(f"CLI did not print one JSON document: {result.stdout!r}; {error}")
        if code == 2:
            self.assertIsInstance(document, dict)
            self.assertIn("error", document)
            self.assertTrue(document["error"])
        return document

    def create(self):
        return self.cli("request", "--actor", "alice", "--resource", "db-read",
                        "--reason", "CLI demo", "--ttl", "3600")

    def test_cli_lifecycle_exit_codes_and_persistence(self):
        record = self.create()
        request_id = record["id"]
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["ttl"], 3600)
        self.assertEqual(self.cli("show", request_id), record)
        self.assertEqual(self.cli("check", request_id, "--actor", "alice",
                                  "--resource", "db-read", code=1)["reason"], "not_approved")
        approved = self.cli("approve", request_id, "--actor", "bob")
        self.assertEqual(approved["approved_by"], "bob")
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["expires_at"], record["expires_at"])
        decision = self.cli("check", request_id, "--actor", "alice", "--resource", "db-read")
        self.assertIs(decision["allowed"], True)
        self.assertEqual(decision["reason"], "allowed")
        before = self.cli("audit")
        self.cli("approve", request_id, "--actor", "carol", code=2)
        self.cli("revoke", request_id, "--actor", "root", "--reason", "override", code=2)
        self.assertEqual(self.cli("audit"), before)
        revoked = self.cli("revoke", request_id, "--actor", "alice", "--reason", "finished")
        self.assertEqual(revoked["status"], "revoked")
        decision = self.cli("check", request_id, "--actor", "alice", "--resource", "db-read", code=1)
        self.assertIs(decision["allowed"], False)
        self.assertEqual(decision["reason"], "not_approved")
        events = self.cli("audit")
        self.assertEqual([event["action"] for event in events], ["request", "approve", "revoke"])
        self.assertEqual(events[-1]["details"]["reason"], "finished")
        self.assertEqual(Workflow(self.db).get(request_id), revoked)

    def test_cli_denial_unknown_request_and_invalid_inputs(self):
        request_id = self.create()["id"]
        before = self.cli("audit")
        for args in (
            ("approve", request_id, "--actor", "alice"),
            ("deny", request_id, "--actor", "alice", "--reason", "self"),
            ("show", "missing"),
            ("approve", "missing", "--actor", "bob"),
            ("deny", "missing", "--actor", "bob", "--reason", "policy"),
            ("revoke", "missing", "--actor", "alice", "--reason", "done"),
            ("request", "--actor", "alice", "--resource", "admin", "--reason", "invalid"),
            ("request", "--actor", "alice", "--resource", "db-read", "--reason", "invalid", "--ttl", "3601"),
            ("request", "--actor", " ", "--resource", "db-read", "--reason", "invalid"),
        ):
            with self.subTest(args=args):
                self.cli(*args, code=2)
                self.assertEqual(self.cli("audit"), before)
        for target, actor, resource, reason in (
            ("missing", "alice", "db-read", "unknown_request"),
            (request_id, "other", "db-read", "actor_mismatch"),
            (request_id, "alice", "server-shell", "resource_mismatch"),
        ):
            result = self.cli("check", target, "--actor", actor, "--resource", resource, code=1)
            self.assertIs(result["allowed"], False)
            self.assertEqual(result["reason"], reason)
        denied = self.cli("deny", request_id, "--actor", "bob", "--reason", "policy")
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(denied["reason"], "CLI demo")
        self.cli("approve", request_id, "--actor", "bob", code=2)
        self.assertEqual(self.cli("show", request_id), denied)
        events = self.cli("audit")
        self.assertEqual([event["action"] for event in events], ["request", "deny"])
        self.assertEqual(events[-1]["details"]["reason"], "policy")

    def test_help_and_usage_errors(self):
        for arguments, code in ((["--help"], 0), ([], 2),
                                (["--db", str(self.db), "request"], 2)):
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), *arguments],
                                    cwd=self.temp.name, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertIn("usage:", (result.stdout + result.stderr).lower())

    def test_import_has_no_output_or_filesystem_side_effects(self):
        before = set(Path(self.temp.name).rglob("*"))
        result = subprocess.run(
            [sys.executable, "-B", "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); import workflow",
             str(SCRIPT.parent)], cwd=self.temp.name, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(set(Path(self.temp.name).rglob("*")), before)


if __name__ == "__main__":
    unittest.main()
