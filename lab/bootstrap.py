#!/usr/bin/env python3
"""Prepare and provision the local Guacamole SSH laboratory (stdlib only)."""

import argparse
import base64
import binascii
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "lab" / ".local"
BASE_URL = "http://127.0.0.1:8080/guacamole/"
DATA_SOURCE = "postgresql"
RECORDING_ROOT = "/var/lib/guacamole/recordings"
CONNECTION_NAME = "PAM lab SSH"
ENV_DEFAULTS = {
    "POSTGRES_DB": "guacamole",
    "POSTGRES_USER": "guacamole",
    "SSH_USERNAME": "pam-lab",
    "GUAC_ADMIN_USERNAME": "guacadmin",
    "GUAC_USERNAME": "pam-user",
    "GUAC_LIMITED_USERNAME": "pam-denied",
}
PASSWORD_KEYS = (
    "POSTGRES_PASSWORD", "SSH_PASSWORD", "GUAC_ADMIN_PASSWORD",
    "GUAC_PASSWORD", "GUAC_LIMITED_PASSWORD",
)
ENV_KEYS = (
    "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD",
    "SSH_USERNAME", "SSH_PASSWORD", "GUAC_ADMIN_USERNAME",
    "GUAC_ADMIN_PASSWORD", "GUAC_USERNAME", "GUAC_PASSWORD",
    "GUAC_LIMITED_USERNAME", "GUAC_LIMITED_PASSWORD",
)


class LabError(Exception):
    """An operator-safe error; never include response bodies or credentials."""


class APIError(LabError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Guacamole API returned HTTP {status}; no response body displayed.")


def read_env(path):
    """Parse the exact plain-key environment contract without shell evaluation."""
    values = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if (not separator or key not in ENV_KEYS or key in values
                    or not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
                raise LabError("Malformed credential file; preserve it and repair manually.")
            values[key] = value
    except (OSError, UnicodeError):
        raise LabError("Cannot read credential file; run prepare first.") from None
    if set(values) != set(ENV_KEYS):
        raise LabError("Incomplete credential file; refusing to replace existing credentials.")
    for key, expected in ENV_DEFAULTS.items():
        if key.startswith("POSTGRES_"):
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", values[key]):
                raise LabError("Invalid database label in credential file.")
        elif values[key] != expected:
            raise LabError("Unexpected fixed user name in credential file.")
    if any(len(values[key]) < 32 for key in PASSWORD_KEYS):
        raise LabError("Credential file contains a password shorter than 32 characters.")
    if len({values[key] for key in PASSWORD_KEYS}) != len(PASSWORD_KEYS):
        raise LabError("Credential file must contain distinct generated passwords.")
    return values


def check_private_file(path, mode=0o600):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise LabError("Local state must be regular files owned by the current operator.")
    if stat.S_IMODE(info.st_mode) != mode:
        raise LabError(f"Local state file requires mode {mode:04o}; correct permissions first.")


@contextlib.contextmanager
def local_lock(create=False):
    if create:
        LOCAL.mkdir(mode=0o700, exist_ok=True)
    if LOCAL.is_symlink() or not LOCAL.is_dir():
        raise LabError("Missing or unsafe lab/.local directory; run prepare first.")
    info = LOCAL.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise LabError("lab/.local must be owned by the operator with mode 0700.")
    # Lock the directory itself: no extra lock file and no concurrent rotation.
    fd = os.open(LOCAL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LabError("Another bootstrap command is already running.") from None
        yield
    finally:
        os.close(fd)


def atomic_write(path, contents, mode=0o600):
    """Runtime state only: private sibling, fsync, then atomic replacement."""
    fd, name = tempfile.mkstemp(prefix=".bootstrap-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), mode)
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def docker(args, timeout=30):
    # Shell exports cannot silently override the stored Compose credentials.
    env = {key: value for key, value in os.environ.items() if key not in ENV_KEYS}
    try:
        result = subprocess.run(["docker", *args], cwd=ROOT, env=env,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise LabError("Docker command unavailable or timed out; no state reset was performed.") from None
    if result.returncode:
        raise LabError("Docker command failed; output withheld to protect credentials.")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeError:
        raise LabError("Docker returned invalid text.") from None


def compose(*args, timeout=30):
    # Inherit COMPOSE_PROJECT_NAME; never supply a fixed project/container name.
    return docker(["compose", "--env-file", "lab/.local/.env", *args], timeout)


def prepare():
    with local_lock(create=True):
        env_path = LOCAL / ".env"
        if env_path.exists() or env_path.is_symlink():
            check_private_file(env_path)
            read_env(env_path)
        else:
            if any(LOCAL.iterdir()):
                raise LabError("Local state exists without credentials; restore its original .env.")
            values = dict(ENV_DEFAULTS)
            values.update({key: secrets.token_urlsafe(32) for key in PASSWORD_KEYS})
            atomic_write(env_path, "".join(f"{key}={values[key]}\n" for key in ENV_KEYS))
        schema = LOCAL / "initdb.sql"
        if schema.exists() or schema.is_symlink():
            check_private_file(schema, mode=0o644)
            sql = schema.read_text(encoding="utf-8")
        else:
            sql = docker(["run", "--rm", "guacamole/guacamole:1.6.0",
                          "/opt/guacamole/bin/initdb.sh", "--postgresql"], timeout=180)
            validate_schema(sql)
            # The official PostgreSQL entrypoint reads SQL as its postgres user.
            # No generated credentials are included in the official schema.
            atomic_write(schema, sql, mode=0o644)
        validate_schema(sql)
    print("Prepared private credentials and official schema. Start Compose, then run provision.")


def validate_schema(sql):
    if "CREATE TABLE guacamole_user" not in sql or "guacamole_connection" not in sql:
        raise LabError("Official schema is empty or invalid; preparation is not complete.")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LabError("Refusing HTTP redirect from the loopback gateway.")


class GuacamoleAPI:
    def __init__(self):
        self.token = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, body=None, form=False):
        # Restrict before attaching the token, even if a caller supplies a bad path.
        if not path.startswith("api/") or any(char in path for char in "?#\\"):
            raise LabError("Invalid local API path.")
        url = BASE_URL + path
        if self.token:
            url += "?" + urllib.parse.urlencode({"token": self.token})
        headers = {}
        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise APIError(status) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise LabError("Loopback gateway request failed or timed out.") from None
        try:
            return json.loads(raw) if raw else None
        except (ValueError, UnicodeError):
            raise LabError("Gateway returned invalid JSON; response withheld.") from None

    def login(self, username, password):
        self.token = None
        result = self.request("POST", "api/tokens",
                              {"username": username, "password": password}, form=True)
        if (not isinstance(result, dict) or not result.get("authToken")
                or DATA_SOURCE not in result.get("availableDataSources", [])):
            raise LabError("Gateway did not return a PostgreSQL authentication session.")
        self.token = result["authToken"]

    def logout(self):
        if self.token:
            try:
                self.request("DELETE", "api/tokens/" + quote(self.token))
            finally:
                self.token = None


def quote(value):
    return urllib.parse.quote(str(value), safe="")


def admin_login(api, values):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            api.login(values["GUAC_ADMIN_USERNAME"], values["GUAC_ADMIN_PASSWORD"])
            return
        except APIError as exc:
            if exc.status in (400, 403):
                # Only use the shipped password for the first rotation.
                api.login(values["GUAC_ADMIN_USERNAME"], "guacadmin")
                api.request("PUT", "api/session/data/postgresql/users/guacadmin/password",
                            {"oldPassword": "guacadmin",
                             "newPassword": values["GUAC_ADMIN_PASSWORD"]})
                api.logout()
                api.login(values["GUAC_ADMIN_USERNAME"], values["GUAC_ADMIN_PASSWORD"])
                return
            if exc.status not in (404, 500, 502, 503, 504):
                raise
        except LabError:
            pass  # Startup transport failure; bounded retry, never print response data.
        time.sleep(2)
    raise LabError("Gateway readiness timed out after 120 seconds; provisioning is incomplete.")


def known_host(public_key):
    parts = public_key.strip().split()
    if len(public_key.strip().splitlines()) != 1 or len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise LabError("Target did not return a single Ed25519 public key.")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error):
        raise LabError("Invalid target host key encoding.") from None
    if raw[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" or len(raw) != 51:
        raise LabError("Invalid target Ed25519 host key.")
    return "ssh-target ssh-ed25519 " + parts[1]


def pointer(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def provision_users(api, values, prefix):
    users = api.request("GET", prefix + "users")
    for username_key, password_key in (("GUAC_USERNAME", "GUAC_PASSWORD"),
                                       ("GUAC_LIMITED_USERNAME", "GUAC_LIMITED_PASSWORD")):
        username = values[username_key]
        user = {"username": username, "password": values[password_key], "attributes": {}}
        path = prefix + "users/" + quote(username)
        if username in users:
            api.request("PUT", path, user)
        else:
            api.request("POST", prefix + "users", user)
        # These dedicated lab accounts must not inherit permission via groups.
        groups = api.request("GET", path + "/userGroups")
        if groups:
            api.request("PATCH", path + "/userGroups",
                        [{"op": "remove", "path": "/", "value": group} for group in groups])


def set_permissions(api, prefix, username, connection_id=None):
    path = prefix + "users/" + quote(username) + "/permissions"
    permissions = api.request("GET", path)
    changes = []
    for category, grants in permissions.items():
        if isinstance(grants, dict):
            for identifier, rights in grants.items():
                # Leave a user's own profile rights intact.
                if category == "userPermissions" and identifier == username:
                    continue
                changes.extend({"op": "remove", "path": f"/{category}/{pointer(identifier)}",
                                "value": right} for right in rights
                               if not (category == "connectionPermissions"
                                       and identifier == connection_id and right == "READ"))
        elif isinstance(grants, list):
            changes.extend({"op": "remove", "path": "/" + category, "value": right}
                           for right in grants)
    if (connection_id is not None
            and "READ" not in permissions.get("connectionPermissions", {}).get(connection_id, [])):
        changes.append({"op": "add", "path": "/connectionPermissions/" + pointer(connection_id),
                        "value": "READ"})
    if changes:
        api.request("PATCH", path, changes)


def provision():
    with local_lock():
        check_private_file(LOCAL / ".env")
        values = read_env(LOCAL / ".env")
        state_path = LOCAL / "state.json"
        previous = None
        if state_path.exists() or state_path.is_symlink():
            check_private_file(state_path)
            previous = json.loads(state_path.read_text(encoding="utf-8"))
            if not isinstance(previous, dict) or not isinstance(previous.get("host_key"), str):
                raise LabError("Invalid existing state; restore it before provisioning.")
        api = GuacamoleAPI()
        try:
            # Remove the shipped password before any target/user configuration.
            admin_login(api, values)
            host_key = known_host(compose("exec", "-T", "ssh-target", "cat",
                                          "/etc/ssh/ssh_host_ed25519_key.pub"))
            if previous and previous["host_key"] != host_key:
                raise LabError("SSH host key changed; refusing to silently replace the existing pin.")
            prefix = "api/session/data/postgresql/"
            connections = api.request("GET", prefix + "connections")
            matches = [str(identifier) for identifier, value in connections.items()
                       if value.get("name") == CONNECTION_NAME]
            if len(matches) > 1:
                raise LabError("Duplicate lab connection names; resolve manually before provisioning.")
            connection = {
                "parentIdentifier": "ROOT", "name": CONNECTION_NAME, "protocol": "ssh",
                "parameters": {
                    "hostname": "ssh-target", "port": "22", "host-key": host_key,
                    "username": values["SSH_USERNAME"], "password": values["SSH_PASSWORD"],
                    "recording-path": "${HISTORY_PATH}/${HISTORY_UUID}",
                    "create-recording-path": "true", "recording-name": "recording",
                },
                "attributes": {},
            }
            if matches:
                connection_id = matches[0]
                connection["identifier"] = connection_id
                api.request("PUT", prefix + "connections/" + quote(connection_id), connection)
            else:
                created = api.request("POST", prefix + "connections", connection)
                connection_id = str(created["identifier"])
            provision_users(api, values, prefix)
            set_permissions(api, prefix, values["GUAC_USERNAME"], connection_id)
            set_permissions(api, prefix, values["GUAC_LIMITED_USERNAME"])
            effective = api.request("GET", prefix + "users/" + quote(values["GUAC_LIMITED_USERNAME"])
                                    + "/effectivePermissions")
            if effective.get("connectionPermissions") or effective.get("systemPermissions"):
                raise LabError("Limited account still has effective access; provisioning failed.")
            state = {"connection_id": connection_id, "data_source": DATA_SOURCE,
                     "base_url": BASE_URL, "host_key": host_key, "recording_root": RECORDING_ROOT}
            atomic_write(state_path, json.dumps(state, indent=2) + "\n")
        finally:
            # Best effort token invalidation; do not conceal the original safe error.
            with contextlib.suppress(LabError):
                api.logout()
    print("Provisioned native users and pinned SSH connection. Metadata: lab/.local/state.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "provision"))
    args = parser.parse_args(argv)
    try:
        {"prepare": prepare, "provision": provision}[args.command]()
    except LabError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print("Error: invalid or inaccessible local/API state; details withheld to protect credentials.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
