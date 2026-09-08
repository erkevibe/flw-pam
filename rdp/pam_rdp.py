#!/usr/bin/env python3
"""Local Guacamole 1.6.0 RDP approval fixture; no target connection is made."""

import argparse
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE_URL = "http://127.0.0.1:18080/guacamole/"
PREFIX = "api/session/data/postgresql/"
LOCAL = Path(__file__).resolve().parent / ".local"
MANAGED_PREFIX = "pam-restart02-rdp-requester-"
PRINCIPALS = {"requester": "requester", "approver": "approver", "outsider": "outsider"}
SERVICE = "pam-rdp-service"
SECRET_KEYS = ("POSTGRES_PASSWORD", "ADMIN_PASSWORD", "SERVICE_PASSWORD",
               "REQUESTER_PASSWORD", "APPROVER_PASSWORD", "OUTSIDER_PASSWORD", "RDP_PASSWORD")
ENV_KEYS = {*SECRET_KEYS, "POSTGRES_IMAGE", "COMPOSE_PROJECT_NAME"}
DEFAULT_POLICY = {"resource": "windows-rdp", "max_ttl": 300, "roles": PRINCIPALS}


class FixtureError(Exception):
    """Safe fixed-message error. Never contains remote data or credential values."""


class APIError(FixtureError):
    def __init__(self, status):
        self.status = status if isinstance(status, int) else 0
        super().__init__(f"Guacamole HTTP {self.status}; response withheld.")


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid values, which may be misplaced secrets.
        self.exit(2, "Error: invalid command arguments; use --help.\n")


def private_file(path, mode=0o600):
    try:
        info = Path(path).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1):
            raise FixtureError("Unsafe local file ownership, type, or mode.")
    except OSError:
        raise FixtureError("Required private file is unavailable.") from None


def read_json(path):
    private_file(path)
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise FixtureError("Invalid private JSON file; contents withheld.") from None


def atomic_write(path, contents, mode=0o600):
    """Durably replace a runtime file in its private directory."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        private_file(path, mode)
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), mode)
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextlib.contextmanager
def local_lock(local=LOCAL, create=False):
    local = Path(local)
    old_umask = os.umask(0o077)
    fd = None
    try:
        if create:
            local.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = local.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise FixtureError("Local directory must be owned by the operator with mode 0700.")
        fd = os.open(local, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        # ponytail: one directory lock serializes this small fixture's operations.
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield local
    except OSError:
        raise FixtureError("Private state is unavailable; run bootstrap prepare first.") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.umask(old_umask)


def read_env(local=LOCAL):
    path = Path(local) / "private.env"
    private_file(path)
    try:
        values = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in ENV_KEYS or key in values:
                raise FixtureError("Invalid private.env structure.")
            values[key] = value
        if set(values) != ENV_KEYS:
            raise FixtureError("Incomplete private.env; restore original credentials.")
        if any(not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", values[k]) for k in SECRET_KEYS):
            raise FixtureError("Invalid generated credential format.")
        if len({values[k] for k in SECRET_KEYS}) != len(SECRET_KEYS):
            raise FixtureError("Generated credentials must be distinct.")
        if not re.fullmatch(r"postgres:16@sha256:[a-f0-9]{64}", values["POSTGRES_IMAGE"]):
            raise FixtureError("PostgreSQL must be pinned to the prepared image digest.")
        if not re.fullmatch(r"pam_restart02_rdp_[a-z0-9_]+", values["COMPOSE_PROJECT_NAME"]):
            raise FixtureError("Invalid isolated Compose project name.")
        return values
    except (OSError, UnicodeError):
        raise FixtureError("Cannot read private.env.") from None


def read_policy(local=LOCAL):
    policy = read_json(Path(local) / "policy.json")
    if (not isinstance(policy, dict) or set(policy) != set(DEFAULT_POLICY)
            or policy.get("roles") != PRINCIPALS or policy.get("resource") != "windows-rdp"
            or type(policy.get("max_ttl")) is not int or not 1 <= policy["max_ttl"] <= 3600):
        raise FixtureError("Invalid protected fixture policy.")
    return policy


def credentials(path):
    value = read_json(path)
    if (not isinstance(value, dict) or set(value) != {"username", "password"}
            or not all(isinstance(value[k], str) and value[k] for k in value)
            or len(value["username"]) > 128 or len(value["password"]) > 4096):
        raise FixtureError("Credentials require exactly username and password strings.")
    return value


def quote(value):
    return urllib.parse.quote(str(value), safe="")


def pointer(value):
    return str(value).replace("~", "~0").replace("/", "~1")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FixtureError("Gateway redirect refused.")


class GuacamoleAPI:
    """Fixed loopback HTTP client; tokens stay in memory and URLs are never logged."""
    def __init__(self):
        self.token = None
        self.username = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, body=None, form=False):
        if (not isinstance(path, str) or not path.startswith("api/")
                or any(c in path for c in "?#\\") or ".." in path):
            raise FixtureError("Invalid API path.")
        url = BASE_URL + path
        data, headers = None, {}
        if self.token:
            headers["Guacamole-Token"] = self.token
        try:
            if body is not None:
                data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode("utf-8")
                headers["Content-Type"] = ("application/x-www-form-urlencoded" if form
                                           else "application/json")
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise FixtureError("Gateway response exceeds fixture limit.")
            return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise APIError(status) from None
        except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException):
            raise FixtureError("Loopback gateway unavailable or timed out.") from None
        except (ValueError, TypeError, UnicodeError):
            raise FixtureError("Invalid API data; contents withheld.") from None

    def login(self, username, password, allowed=None):
        """Login, require canonical PostgreSQL principal, validate self; return username."""
        self.token = self.username = None
        result = self.request("POST", "api/tokens", {"username": username, "password": password}, True)
        if (not isinstance(result, dict) or result.get("dataSource") != "postgresql"
                or not isinstance(result.get("authToken"), str) or not result["authToken"]
                or not isinstance(result.get("username"), str)):
            raise FixtureError("Invalid PostgreSQL login session.")
        self.token = result["authToken"]
        canonical = result["username"]
        if canonical not in (allowed if allowed is not None else PRINCIPALS):
            self.logout()
            raise FixtureError("Authenticated principal is not allowed.")
        try:
            effective = self.request("GET", PREFIX + "self/effectivePermissions")
            if not isinstance(effective, dict) or "connectionPermissions" not in effective:
                raise FixtureError("Invalid self permission response.")
            if canonical == SERVICE and "ADMINISTER" not in effective.get("systemPermissions", []):
                raise FixtureError("Trusted service requires verified ADMINISTER privilege.")
        except BaseException:
            self.logout()
            raise
        self.username = canonical
        return canonical

    def logout(self):
        if self.token:
            with contextlib.suppress(FixtureError):
                self.request("DELETE", "api/tokens/" + quote(self.token))
        self.token = self.username = None


@contextlib.contextmanager
def session(username, password, allowed):
    api = GuacamoleAPI()
    try:
        api.login(username, password, allowed)
        yield api
    finally:
        api.logout()


def windows_target(local=LOCAL, *, require_store=True):
    """Optional private operator target; never persisted in workflow state."""
    path = Path(local) / "windows-target.json"
    if not path.exists() and not path.is_symlink():
        return None
    target = read_json(path)
    keys = {"hostname", "port", "username", "domain", "password",
            "cert_fingerprint", "certificate_trust"}
    if not isinstance(target, dict) or set(target) != keys:
        raise FixtureError("Invalid private Windows target configuration.")
    if (type(target["port"]) is not int or not 1 <= target["port"] <= 65535
            or any(not isinstance(target[k], str) for k in keys - {"port"})
            or not 1 <= len(target["username"]) <= 256
            or not 1 <= len(target["password"]) <= 4096
            or len(target["domain"]) > 253
            or any(any(ord(c) < 32 or ord(c) == 127 for c in target[k])
                   for k in keys - {"port"})
            or not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", target["cert_fingerprint"])
            or not 1 <= len(target["certificate_trust"]) <= 256):
        raise FixtureError("Invalid private Windows target configuration.")
    host = target["hostname"]
    try:
        ipaddress.ip_address(host)
        valid_host = "%" not in host
    except ValueError:
        valid_host = (len(host) <= 253 and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
            for part in host.split(".")))
    if not valid_host:
        raise FixtureError("Invalid private Windows target configuration.")
    if not require_store:
        return target
    # FreeRDP2 native host-key store: configured pin path; runtime TLS still unresolved.
    # Reject config/pin drift before any grant; never enroll a changed key here.
    trust = Path(local) / "windows-trust"
    try:
        info = trust.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise FixtureError("Unsafe private Windows trust directory.")
        store = trust / "known_hosts2"
        private_file(store)
        fields = store.read_text(encoding="ascii").split()
        digest = target["cert_fingerprint"].split(":", 1)[1].lower()
        expected = [host, str(target["port"]), ":".join(
            digest[i:i + 2] for i in range(0, 64, 2))]
        if len(fields) != 5 or fields[:3] != expected:
            raise FixtureError("Windows native trust pin differs; maintenance required.")
    except (OSError, UnicodeError):
        raise FixtureError("Private Windows trust unavailable; maintenance required.") from None
    return target


def connection_spec(request_id, values, local=LOCAL):
    if not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise FixtureError("Invalid request identifier.")
    target = windows_target(local)
    spec = {
        "parentIdentifier": "ROOT", "name": MANAGED_PREFIX + request_id, "protocol": "rdp",
        "parameters": {
            "hostname": "windows.invalid", "port": "3389", "username": "pam-rdp-lab",
            "domain": "", "password": values["RDP_PASSWORD"], "security": "nla",
            "ignore-cert": "false", "cert-tofu": "false", "disable-auth": "false",
            "recording-path": "${HISTORY_PATH}/${HISTORY_UUID}",
            "recording-name": "grant-" + request_id + "-${HISTORY_UUID}",
            "create-recording-path": "true", "recording-exclude-output": "false",
            "recording-include-keys": "false", "recording-write-existing": "false",
            "disable-copy": "true", "disable-paste": "true", "enable-drive": "false",
            "disable-upload": "true", "disable-download": "true", "enable-printing": "false",
            "enable-sftp": "false", "enable-audio-input": "false", "disable-audio": "true",
            "wol-send-packet": "false",
        },
        "attributes": {},
    }
    if target is not None:
        spec["parameters"].update({k: target[k] for k in
                                   ("hostname", "username", "domain", "password")})
        spec["parameters"]["port"] = str(target["port"])
        digest = target["cert_fingerprint"][7:].lower()
        spec["parameters"]["cert-fingerprints"] = "sha256:" + ":".join(
            digest[i:i + 2] for i in range(0, 64, 2))
    return spec


def get_map(api, path):
    result = api.request("GET", PREFIX + path)
    if not isinstance(result, dict):
        raise FixtureError("Invalid API object map.")
    return result


def connections(api):
    result = get_map(api, "connections")
    if any(not isinstance(i, str) or not re.fullmatch(r"[0-9]+", i)
           or not isinstance(v, dict) or not isinstance(v.get("name"), str)
           for i, v in result.items()):
        raise FixtureError("Invalid connection listing.")
    return result


def managed_connections(api):
    result = {}
    for identifier, value in connections(api).items():
        if value["name"].startswith(MANAGED_PREFIX):
            if not re.fullmatch(re.escape(MANAGED_PREFIX) + r"[a-f0-9]{32}", value["name"]):
                raise FixtureError("Malformed managed connection; maintenance required.")
            result[str(identifier)] = value
    return result


def rights(api, username, effective=False):
    kind = "effectivePermissions" if effective else "permissions"
    result = get_map(api, "users/" + quote(username) + "/" + kind)
    grants = result.get("connectionPermissions")
    if not isinstance(grants, dict) or any(not isinstance(v, list) for v in grants.values()):
        raise FixtureError("Invalid native permission response.")
    return grants


def set_read(api, username, identifier, present):
    """PATCH exact READ membership; accept uncertain writes only after a fresh GET."""
    path = PREFIX + "users/" + quote(username) + "/permissions"
    if ("READ" in rights(api, username).get(identifier, [])) != present:
        try:
            api.request("PATCH", path, [{"op": "add" if present else "remove",
                        "path": "/connectionPermissions/" + pointer(identifier), "value": "READ"}])
        except FixtureError:
            if ("READ" in rights(api, username).get(identifier, [])) != present:
                raise
    if ("READ" in rights(api, username).get(identifier, [])) != present:
        raise FixtureError("Native READ verification failed.")
    if ("READ" in rights(api, username, True).get(identifier, [])) != present:
        raise FixtureError("Effective READ verification failed.")


def active_for(api, identifier):
    active = get_map(api, "activeConnections")
    result = []
    for active_id, value in active.items():
        if not isinstance(value, dict) or "connectionIdentifier" not in value or "username" not in value:
            raise FixtureError("Invalid active connection response.")
        if str(value["connectionIdentifier"]) == identifier:
            if value["username"] != "requester":
                raise FixtureError("Foreign session on managed connection; refusing unscoped termination.")
            result.append(str(active_id))
    return result


def cleanup_connection(api, identifier):
    """Remove user READ, kill only grant/owner sessions, delete, then verify absence."""
    # Dedicated connection deletion removes every residual object permission too.
    for username in PRINCIPALS:
        set_read(api, username, identifier, False)
    active = active_for(api, identifier)
    if active:
        try:
            api.request("PATCH", PREFIX + "activeConnections",
                        [{"op": "remove", "path": "/" + pointer(i)} for i in active])
        except FixtureError:
            if active_for(api, identifier):
                raise
    if active_for(api, identifier):
        raise FixtureError("Owned sessions remain; cleanup is pending.")
    if identifier in connections(api):
        try:
            api.request("DELETE", PREFIX + "connections/" + quote(identifier))
        except FixtureError:
            if identifier in connections(api):
                raise
    if identifier in connections(api) or active_for(api, identifier):
        raise FixtureError("Connection cleanup could not be verified.")
    for username in PRINCIPALS:
        if "READ" in rights(api, username, True).get(identifier, []):
            raise FixtureError("Effective access remains; cleanup is pending.")
    return len(active)


def open_db(local):
    path = Path(local) / "state.sqlite3"
    for suffix in ("", "-journal", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists() or candidate.is_symlink():
            private_file(candidate)
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY, requester TEXT NOT NULL CHECK(requester='requester'),
            resource TEXT NOT NULL CHECK(resource='windows-rdp'), ttl INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN
              ('pending','denied','granting','approved','revoking','revoked')),
            created_at REAL NOT NULL, approved_by TEXT, approved_at REAL, expires_at REAL,
            connection_id TEXT, revoked_at REAL
        );
        CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
            request_id TEXT, actor TEXT NOT NULL, event TEXT NOT NULL
        );
    """)
    return db


def audit(db, request_id, actor, event):
    db.execute("INSERT INTO audit(at,request_id,actor,event) VALUES(?,?,?,?)",
               (time.time(), request_id, actor, event))


def row_for(db, request_id):
    if not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise FixtureError("Invalid request identifier.")
    row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
    if row is None:
        raise FixtureError("Request does not exist.")
    return row


def fingerprint(local):
    try:
        digest = hashlib.sha256((Path(local) / "state.sqlite3").read_bytes()).hexdigest()
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return {"sha256": digest, "boot_id": boot}
    except OSError:
        raise FixtureError("Cannot validate local startup generation.") from None


def seal(local, ready):
    atomic_write(Path(local) / "gate.json", json.dumps({**fingerprint(local), "ready": ready}) + "\n")


def is_ready(local):
    path = Path(local) / "gate.json"
    if not path.exists() and not path.is_symlink():
        return False
    gate = read_json(path)
    return isinstance(gate, dict) and gate == {**fingerprint(local), "ready": True}


def revoke_row(db, api, row, actor):
    with db:
        db.execute("UPDATE requests SET state='revoking' WHERE id=?", (row["id"],))
        audit(db, row["id"], actor, "revoke_intent")
    matches = {i for i, c in managed_connections(api).items()
               if c["name"] == MANAGED_PREFIX + row["id"]}
    if row["connection_id"]:
        identifier = row["connection_id"]
        current = connections(api).get(identifier)
        if current and current["name"] != MANAGED_PREFIX + row["id"]:
            raise FixtureError("Connection mapping changed; refusing foreign cleanup.")
        matches.add(identifier)
    killed = sum(cleanup_connection(api, i) for i in sorted(matches))
    with db:
        db.execute("UPDATE requests SET state='revoked',revoked_at=? WHERE id=?", (time.time(), row["id"]))
        audit(db, row["id"], actor, "revoked")
    return killed


def startup_cleanup(db, api, local, actor):
    # Gate is persisted BEFORE any external or SQLite mutation. Never grant here.
    seal(local, False)
    with db:
        db.execute("UPDATE requests SET state='revoking' WHERE state IN ('pending','granting','approved')")
        audit(db, None, actor, "startup_cleanup_intent")
    killed = 0
    # Scan native state, including orphaned grants absent from an old SQLite backup.
    for identifier in managed_connections(api):
        killed += cleanup_connection(api, identifier)
    for row in db.execute("SELECT * FROM requests WHERE state='revoking'").fetchall():
        killed += revoke_row(db, api, row, actor)
    if managed_connections(api):
        raise FixtureError("Startup cleanup incomplete; grants remain blocked.")
    with db:
        audit(db, None, actor, "startup_cleanup_complete")
    seal(local, True)
    return killed


def reconcile_rows(db, api, actor):
    killed, expired = 0, 0
    for row in db.execute("SELECT * FROM requests WHERE state IN ('granting','approved','revoking')").fetchall():
        if row["state"] != "approved" or row["expires_at"] <= time.time():
            killed += revoke_row(db, api, row, actor)
            expired += 1
    return {"cleaned_requests": expired, "observed_sessions_terminated": killed}


def approve_row(db, api, row, actor, values, local=LOCAL):
    if row["state"] != "pending":
        raise FixtureError("Decision replay or invalid request state.")
    if actor == row["requester"]:
        raise FixtureError("Self approval is forbidden.")
    now = time.time()
    with db:
        db.execute("UPDATE requests SET state='granting',approved_by=?,approved_at=?,expires_at=? WHERE id=?",
                   (actor, now, now + row["ttl"], row["id"]))
        audit(db, row["id"], actor, "grant_intent")
    expected = connection_spec(row["id"], values, local)
    matches = [i for i, c in managed_connections(api).items() if c["name"] == expected["name"]]
    if matches:
        # No adoption from native state or from a restored snapshot.
        raise FixtureError("Existing native grant requires cleanup and a new request.")
    try:
        api.request("POST", PREFIX + "connections", expected)
    except FixtureError:
        # POST may have committed despite a lost reply. Read; never retry POST.
        matches = [i for i, c in managed_connections(api).items() if c["name"] == expected["name"]]
        if len(matches) != 1:
            raise
    matches = [i for i, c in managed_connections(api).items() if c["name"] == expected["name"]]
    if len(matches) != 1:
        raise FixtureError("Single grant creation could not be verified.")
    identifier = matches[0]
    with db:
        db.execute("UPDATE requests SET connection_id=? WHERE id=?", (identifier, row["id"]))
        audit(db, row["id"], actor, "connection_created")
    current = get_map(api, "connections/" + quote(identifier))
    params = get_map(api, "connections/" + quote(identifier) + "/parameters")
    if (any(current.get(k) != expected[k] for k in ("name", "protocol", "parentIdentifier"))
            or any(params.get(k) != v and not (v == "" and params.get(k) is None)
                   for k, v in expected["parameters"].items())
            or any(v not in ("", None) for k, v in params.items() if k not in expected["parameters"])):
        raise FixtureError("Native connection scope verification failed.")
    for username in ("approver", "outsider"):
        if rights(api, username, True).get(identifier):
            raise FixtureError("Unexpected principal has access to grant.")
    if time.time() >= now + row["ttl"]:
        raise FixtureError("Grant expired during preparation; reconcile cleanup required.")
    set_read(api, row["requester"], identifier, True)
    if time.time() >= now + row["ttl"]:
        raise FixtureError("Grant expired during permission update; reconcile cleanup required.")
    with db:
        db.execute("UPDATE requests SET state='approved' WHERE id=?", (row["id"],))
        audit(db, row["id"], actor, "approved")


def execute(command, credentials_file=None, *, request_id=None, resource=None, ttl=None, local=LOCAL):
    """One locked command. User mutations always authenticate freshly; returns safe JSON data."""
    if command not in {"request", "approve", "deny", "revoke", "reconcile", "startup", "status"}:
        raise FixtureError("Unknown command.")
    with local_lock(local) as local:
        values, policy = read_env(local), read_policy(local)
        if command == "status":
            path = local / "state.sqlite3"
            if not path.exists():
                return {"ready": False, "requests": []}
            private_file(path)
            db = sqlite3.connect("file:" + quote(str(path)) + "?mode=ro", uri=True)
            db.row_factory = sqlite3.Row
            try:
                return {"ready": is_ready(local), "requests": [dict(r) for r in db.execute("SELECT * FROM requests ORDER BY created_at,id")]}
            finally:
                db.close()
        if credentials_file is None:
            raise FixtureError("A private username/password file is required.")
        supplied = credentials(credentials_file)
        with session(supplied["username"], supplied["password"], PRINCIPALS) as caller:
            actor = caller.username
            required = "requester" if command == "request" else "approver"
            if policy["roles"].get(actor) != required:
                raise FixtureError("Authenticated role cannot perform this operation.")
            if command == "request" and (resource != policy["resource"] or type(ttl) is not int
                                          or not 1 <= ttl <= policy["max_ttl"]):
                raise FixtureError("Resource or TTL is outside protected policy.")
            # Authentication and role checks precede *any* product state mutation.
            db = open_db(local)
            try:
                with session(SERVICE, values["SERVICE_PASSWORD"], {SERVICE}) as service:
                    if command == "startup":
                        killed = startup_cleanup(db, service, local, actor)
                        return {"ready": True, "observed_sessions_terminated": killed}
                    if not is_ready(local):
                        startup_cleanup(db, service, local, actor)
                        raise FixtureError("Startup or restored state was cleaned; submit a new request.")
                    if command in {"approve", "deny", "revoke"}:
                        row = row_for(db, request_id)
                        allowed_states = ({"approved", "revoking", "revoked"} if command == "revoke"
                                          else {"pending"})
                        if row["state"] not in allowed_states:
                            raise FixtureError("Decision replay or invalid request state.")
                        if command == "approve" and (actor == row["requester"]
                                or row["resource"] != policy["resource"]
                                or not 1 <= row["ttl"] <= policy["max_ttl"]):
                            raise FixtureError("Stored request is outside approval policy.")
                    # Persist a closed gate across every mutation, including uncertain HTTP failures.
                    seal(local, False)
                    result = reconcile_rows(db, service, actor)
                    if command == "request":
                        request_id = uuid.uuid4().hex
                        with db:
                            db.execute("INSERT INTO requests(id,requester,resource,ttl,state,created_at) VALUES(?,?,?,?,'pending',?)",
                                       (request_id, actor, resource, ttl, time.time()))
                            audit(db, request_id, actor, "requested")
                    elif command in {"approve", "deny", "revoke"}:
                        row = row_for(db, request_id)
                        if command == "approve":
                            if row["resource"] != policy["resource"] or not 1 <= row["ttl"] <= policy["max_ttl"]:
                                raise FixtureError("Stored request is outside protected policy.")
                            approve_row(db, service, row, actor, values, local)
                        elif command == "deny":
                            if row["state"] != "pending":
                                raise FixtureError("Decision replay or invalid request state.")
                            with db:
                                db.execute("UPDATE requests SET state='denied' WHERE id=?", (request_id,))
                                audit(db, request_id, actor, "denied")
                        else:
                            if row["state"] not in {"approved", "revoking", "revoked"}:
                                raise FixtureError("Request is not revocable.")
                            result["observed_sessions_terminated"] += revoke_row(db, service, row, actor)
                    seal(local, True)
                    if request_id:
                        return dict(row_for(db, request_id))
                    return result
            finally:
                db.close()


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("request", "approve", "deny", "revoke", "reconcile", "startup", "status"):
        child = sub.add_parser(command)
        if command != "status":
            child.add_argument("--credentials-file", required=True, type=Path)
        if command == "request":
            child.add_argument("--resource", required=True, choices=["windows-rdp"])
            child.add_argument("--ttl", required=True, type=int)
        if command in {"approve", "deny", "revoke"}:
            child.add_argument("--request-id", required=True)
        if command == "reconcile":
            child.add_argument("--watch", action="store_true", help="Cleanup on startup, then reconcile until interrupted")
            child.add_argument("--interval", type=int, default=2, choices=range(1, 61), metavar="1..60")
    args = vars(parser.parse_args(argv))
    watch, interval = args.pop("watch", False), args.pop("interval", 2)
    try:
        if watch:
            execute("startup", args["credentials_file"])
            while True:
                print(json.dumps(execute(**args), sort_keys=True), flush=True)
                time.sleep(interval)
        else:
            print(json.dumps(execute(**args), sort_keys=True))
    except FixtureError as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        print("Error: invalid or inaccessible fixture state; details withheld.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
