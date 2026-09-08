"""Local SQLite workflow lab; actors are trusted strings, not authenticated users."""

import argparse
from contextlib import contextmanager
import json
import math
from numbers import Number
import sqlite3
import time
import uuid


class Workflow:
    def __init__(self, db_path, resources=("db-read", "server-shell"), clock=time.time):
        if not isinstance(resources, (list, tuple)) or not resources:
            raise ValueError("resources must be a nonempty list or tuple")
        for resource in resources:
            self._text(resource, "resource")
        if len(set(resources)) != len(resources):
            raise ValueError("resources must be distinct")
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._clock = clock
        self._now()
        self._db_path = db_path
        self._resources = frozenset(resources)
        configured = json.dumps(sorted(resources))
        with self._connection(write=True) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS workflow_config "
                "(id INTEGER PRIMARY KEY CHECK (id = 1), resources TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT resources FROM workflow_config WHERE id = ?", (1,)
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO workflow_config (id, resources) VALUES (?, ?)",
                    (1, configured),
                )
            elif row["resources"] != configured:
                raise ValueError("resource allowlist differs from the stored allowlist")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS requests ("
                "id TEXT PRIMARY KEY, actor TEXT NOT NULL, resource TEXT NOT NULL, "
                "reason TEXT NOT NULL, ttl INTEGER NOT NULL, created_at REAL NOT NULL, "
                "expires_at REAL NOT NULL, status TEXT NOT NULL, approved_by TEXT)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS audit ("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, "
                "action TEXT NOT NULL, actor TEXT NOT NULL, request_id TEXT NOT NULL, "
                "details TEXT NOT NULL)"
            )

    @staticmethod
    def _text(value, name):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a nonempty string")

    def _now(self):
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, Number):
            raise ValueError("clock must return a finite nonnegative number")
        try:
            value = float(value)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("clock must return a finite nonnegative number") from error
        if not math.isfinite(value) or value < 0:
            raise ValueError("clock must return a finite nonnegative number")
        return value

    @contextmanager
    def _connection(self, write=False):
        connection = sqlite3.connect(self._db_path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            if write:
                # Acquire the writer lock before reading the state being changed.
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _record(connection, request_id):
        row = connection.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise ValueError("unknown request")
        return dict(row)

    @staticmethod
    def _event(connection, timestamp, action, actor, request_id, details):
        connection.execute(
            "INSERT INTO audit (timestamp, action, actor, request_id, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, action, actor, request_id, json.dumps(details, allow_nan=False)),
        )

    def request(self, actor, resource, reason, ttl=300):
        self._text(actor, "actor")
        self._text(resource, "resource")
        self._text(reason, "reason")
        if resource not in self._resources:
            raise ValueError("resource is not allowed")
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("ttl must be an integer from 1 through 3600")
        with self._connection(write=True) as connection:
            now = self._now()
            request_id = uuid.uuid4().hex
            connection.execute(
                "INSERT INTO requests "
                "(id, actor, resource, reason, ttl, created_at, expires_at, status, approved_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (request_id, actor, resource, reason, ttl, now, now + ttl, "pending", None),
            )
            self._event(connection, now, "request", actor, request_id,
                        {"resource": resource, "reason": reason, "ttl": ttl})
            return self._record(connection, request_id)

    def approve(self, actor, request_id):
        return self._transition(actor, request_id, "approve")

    def deny(self, actor, request_id, reason):
        self._text(reason, "reason")
        return self._transition(actor, request_id, "deny", reason)

    def revoke(self, actor, request_id, reason):
        self._text(reason, "reason")
        return self._transition(actor, request_id, "revoke", reason)

    def _transition(self, actor, request_id, action, reason=None):
        self._text(actor, "actor")
        self._text(request_id, "request_id")
        with self._connection(write=True) as connection:
            record = self._record(connection, request_id)
            now = self._now()
            if action == "revoke":
                if record["status"] != "approved":
                    raise ValueError("only approved requests may be revoked")
                if actor not in (record["actor"], record["approved_by"]):
                    raise ValueError("only the requester or approver may revoke")
                status = "revoked"
            else:
                if record["status"] != "pending" or now >= record["expires_at"]:
                    raise ValueError("request must be pending and unexpired")
                if actor == record["actor"]:
                    raise ValueError("actor must differ from the requester")
                status = "approved" if action == "approve" else "denied"
            approved_by = actor if action == "approve" else record["approved_by"]
            connection.execute(
                "UPDATE requests SET status = ?, approved_by = ? WHERE id = ?",
                (status, approved_by, request_id),
            )
            details = {} if action == "approve" else {"reason": reason}
            self._event(connection, now, action, actor, request_id, details)
            return self._record(connection, request_id)

    def get(self, request_id):
        self._text(request_id, "request_id")
        with self._connection() as connection:
            return self._record(connection, request_id)

    def check(self, request_id, actor, resource):
        self._text(request_id, "request_id")
        self._text(actor, "actor")
        self._text(resource, "resource")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM requests WHERE id = ?", (request_id,)
            ).fetchone()
        if row is None:
            reason = "unknown_request"
        elif resource != row["resource"]:
            reason = "resource_mismatch"
        elif actor != row["actor"]:
            reason = "actor_mismatch"
        elif self._now() >= row["expires_at"]:
            reason = "expired"
        elif row["status"] != "approved":
            reason = "not_approved"
        else:
            reason = "allowed"
        return {"allowed": reason == "allowed", "reason": reason}

    def audit(self):
        with self._connection() as connection:
            events = [dict(row) for row in connection.execute("SELECT * FROM audit ORDER BY seq")]
        for event in events:
            event["details"] = json.loads(event["details"])
        return events


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request")
    request.add_argument("--actor", required=True)
    request.add_argument("--resource", required=True)
    request.add_argument("--reason", required=True)
    request.add_argument("--ttl", type=int, default=300)
    for action in ("approve", "deny", "revoke", "check", "show"):
        command = commands.add_parser(action)
        command.add_argument("request_id")
        if action != "show":
            command.add_argument("--actor", required=True)
        if action in ("deny", "revoke"):
            command.add_argument("--reason", required=True)
        if action == "check":
            command.add_argument("--resource", required=True)
    commands.add_parser("audit")
    args = vars(parser.parse_args(argv))
    db_path = args.pop("db")
    action = args.pop("command")
    try:
        workflow = Workflow(db_path)
        result = getattr(workflow, "get" if action == "show" else action)(**args)
        print(json.dumps(result, allow_nan=False))
        return int(action == "check" and not result["allowed"])
    except (ValueError, sqlite3.Error, OSError) as error:
        print(json.dumps({"error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
