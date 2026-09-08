#!/usr/bin/env python3
"""Prepare (trusted-operator Docker) then provision the isolated Guacamole RDP fixture."""

import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time

# Importing this executable must not create an undeclared __pycache__ artifact.
sys.dont_write_bytecode = True
try:
    from . import pam_rdp as pam
except ImportError:
    import pam_rdp as pam

LOCAL = pam.LOCAL


def docker(args, timeout=180):
    """Trusted-operator, captured Docker execution; never return diagnostics in exceptions."""
    try:
        result = subprocess.run(["docker", *args], capture_output=True,
                                timeout=timeout, check=False)
        if result.returncode:
            raise pam.FixtureError("Docker preparation failed; diagnostic output withheld.")
        return result.stdout.decode("utf-8")
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise pam.FixtureError("Docker unavailable, timed out, or returned invalid output.") from None


def image_record(tag):
    record = json.loads(docker(["image", "inspect", tag]))[0]
    repository = tag.split(":")[0]
    digests = [d for d in record.get("RepoDigests", [])
               if re.fullmatch(re.escape(repository) + r"@sha256:[a-f0-9]{64}", d)]
    if not digests or not re.fullmatch(r"sha256:[a-f0-9]{64}", record.get("Id", "")):
        raise pam.FixtureError("Pulled image has no verifiable repository digest.")
    return {"tag": tag, "digest": digests[0], "image_id": record["Id"]}


def validate_schema(sql):
    if "CREATE TABLE guacamole_user" not in sql or "CREATE TABLE guacamole_connection" not in sql:
        raise pam.FixtureError("Official PostgreSQL schema is invalid.")


def prepare_trust_layout(local=LOCAL):
    """Create empty readonly-mount inputs; preserve any enrolled pin."""
    if os.geteuid() != 1000:
        raise pam.FixtureError("Trust preparation requires fixture operator UID 1000.")
    trust = local / "windows-trust"
    for path in (trust, trust / "certs", trust / "server"):
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise pam.FixtureError("Unsafe private trust directory.")
    store = trust / "known_hosts2"
    if store.exists() or store.is_symlink():
        pam.private_file(store)
    else:
        pam.atomic_write(store, "")
    return trust


def prepare(local=LOCAL):
    """Trusted operator. Generate private runtime inputs and schema; never start Compose."""
    if os.geteuid() != 1000:
        raise pam.FixtureError("Preparation requires fixture operator UID 1000.")
    with pam.local_lock(local, create=True) as local:
        env_path, bom_path = local / "private.env", local / "bom.json"
        if env_path.exists() or env_path.is_symlink():
            values = pam.read_env(local)
            if not bom_path.exists():
                raise pam.FixtureError("Existing credentials lack their BOM; restore original preparation state.")
            bom = pam.read_json(bom_path)
        else:
            # A failed first preparation may leave only a BOM. Never rotate existing user files.
            if any(p.name != "bom.json" for p in local.iterdir()):
                raise pam.FixtureError("State exists without private.env; restore original credentials.")
            images = []
            for tag in ("guacamole/guacamole:1.6.0", "guacamole/guacd:1.6.0", "postgres:16"):
                docker(["pull", tag], timeout=300)
                images.append(image_record(tag))
            pg = images[-1]
            version = docker(["run", "--rm", "--network", "none", pg["digest"], "postgres", "--version"]).strip()
            if not re.fullmatch(r"postgres \(PostgreSQL\) 16\.\d+(?: [A-Za-z0-9 .()+~:/_-]+)?", version):
                raise pam.FixtureError("Unexpected PostgreSQL version from pulled image.")
            bom = {"images": images, "postgres_version": version,
                   "api_preparation": "pending", "rdp": "pending"}
            pam.atomic_write(bom_path, json.dumps(bom, indent=2) + "\n")
            values = {key: secrets.token_urlsafe(32) for key in pam.SECRET_KEYS}
            values.update({"POSTGRES_IMAGE": "postgres:16@" + pg["digest"].split("@", 1)[1],
                           "COMPOSE_PROJECT_NAME": "pam_restart02_rdp_api"})
            pam.atomic_write(env_path, "".join(k + "=" + values[k] + "\n" for k in sorted(values)))
        if (not isinstance(bom, dict) or not isinstance(bom.get("images"), list)
                or len(bom["images"]) != 3
                or bom["images"][-1].get("digest") != values["POSTGRES_IMAGE"].replace(":16@", "@")):
            raise pam.FixtureError("Private BOM and pinned PostgreSQL image disagree.")
        schema = local / "initdb.sql"
        if schema.exists() or schema.is_symlink():
            pam.private_file(schema, 0o644)
            validate_schema(schema.read_text(encoding="utf-8"))
        else:
            sql = docker(["run", "--rm", "--network", "none", "guacamole/guacamole:1.6.0",
                          "/opt/guacamole/bin/initdb.sh", "--postgresql"])
            validate_schema(sql)
            # SQL contains the public shipped Guacamole bootstrap account, no generated secrets.
            # The postgres container must be able to read this bind-mounted file.
            pam.atomic_write(schema, sql, 0o644)
        policy_path = local / "policy.json"
        if policy_path.exists() or policy_path.is_symlink():
            pam.read_policy(local)
        else:
            pam.atomic_write(policy_path, json.dumps(pam.DEFAULT_POLICY, indent=2) + "\n")
        for username in pam.PRINCIPALS:
            path = local / (username + ".json")
            expected = {"username": username, "password": values[username.upper() + "_PASSWORD"]}
            if path.exists() or path.is_symlink():
                if pam.credentials(path) != expected:
                    raise pam.FixtureError("Existing caller credential file differs from private.env.")
            else:
                pam.atomic_write(path, json.dumps(expected) + "\n")
        prepare_trust_layout(local)
    return {"prepared": True, "next": "Start the documented isolated Compose project, then provision."}


def admin_login(api, values):
    deadline = time.monotonic() + 120
    while True:
        try:
            api.login("guacadmin", values["ADMIN_PASSWORD"], {"guacadmin"})
            return
        except pam.APIError as exc:
            if exc.status in (400, 403):
                # Only provision uses the public shipped credential, solely to rotate it.
                api.login("guacadmin", "guacadmin", {"guacadmin"})
                try:
                    api.request("PUT", pam.PREFIX + "users/guacadmin/password",
                                {"oldPassword": "guacadmin", "newPassword": values["ADMIN_PASSWORD"]})
                except pam.FixtureError:
                    # Rotation may have succeeded before a lost reply; login is the proof.
                    pass
                api.logout()
                api.login("guacadmin", values["ADMIN_PASSWORD"], {"guacadmin"})
                return
            if exc.status not in (404, 500, 502, 503, 504):
                raise
        except pam.FixtureError:
            pass
        if time.monotonic() >= deadline:
            raise pam.FixtureError("Gateway readiness timed out; provisioning incomplete.")
        time.sleep(2)


def reset_permissions(api, username, administer=False):
    path = pam.PREFIX + "users/" + pam.quote(username)
    groups = api.request("GET", path + "/userGroups")
    if not isinstance(groups, list):
        raise pam.FixtureError("Invalid native group membership response.")
    if groups:
        api.request("PATCH", path + "/userGroups", [{"op": "remove", "path": "/", "value": g} for g in groups])
    permissions = api.request("GET", path + "/permissions")
    if not isinstance(permissions, dict):
        raise pam.FixtureError("Invalid native user permission response.")
    changes = []
    for category, grants in permissions.items():
        if isinstance(grants, dict):
            for identifier, rights in grants.items():
                if category == "userPermissions" and identifier == username:
                    continue
                changes.extend({"op": "remove", "path": "/" + category + "/" + pam.pointer(identifier),
                                "value": right} for right in rights)
        elif isinstance(grants, list):
            changes.extend({"op": "remove", "path": "/" + category, "value": right} for right in grants
                           if not (administer and category == "systemPermissions" and right == "ADMINISTER"))
        else:
            raise pam.FixtureError("Invalid permission category.")
    if administer and "ADMINISTER" not in permissions.get("systemPermissions", []):
        changes.append({"op": "add", "path": "/systemPermissions", "value": "ADMINISTER"})
    if changes:
        api.request("PATCH", path + "/permissions", changes)
    effective = api.request("GET", path + "/effectivePermissions")
    if not isinstance(effective, dict):
        raise pam.FixtureError("Invalid effective permission response.")
    if administer:
        if "ADMINISTER" not in effective.get("systemPermissions", []):
            raise pam.FixtureError("Service ADMINISTER privilege was not verified.")
    else:
        for category, grants in effective.items():
            if category == "userPermissions" and isinstance(grants, dict):
                grants = {i: r for i, r in grants.items() if i != username}
            if grants:
                raise pam.FixtureError("Fixture user retains unexpected effective privilege.")


def provision(local=LOCAL):
    """Native API only. Rotate admin, provision dedicated users, run startup cleanup."""
    with pam.local_lock(local) as local:
        values = pam.read_env(local)
        pam.read_policy(local)
        api = pam.GuacamoleAPI()
        db = None
        try:
            admin_login(api, values)
            db = pam.open_db(local)
            pam.seal(local, False)
            users = pam.get_map(api, "users")
            for username, key in [(pam.SERVICE, "SERVICE_PASSWORD"),
                                  *[(u, u.upper() + "_PASSWORD") for u in pam.PRINCIPALS]]:
                user = {"username": username, "password": values[key], "attributes": {}}
                if username in users:
                    api.request("PUT", pam.PREFIX + "users/" + pam.quote(username), user)
                else:
                    try:
                        api.request("POST", pam.PREFIX + "users", user)
                    except pam.FixtureError:
                        if username not in pam.get_map(api, "users"):
                            raise
            # Cleanup must precede privilege reset; never strand active grants.
            pam.startup_cleanup(db, api, local, "guacadmin")
            pam.seal(local, False)
            for username in [pam.SERVICE, *pam.PRINCIPALS]:
                reset_permissions(api, username, administer=username == pam.SERVICE)
            for username, key in [(pam.SERVICE, "SERVICE_PASSWORD"),
                                  *[(u, u.upper() + "_PASSWORD") for u in pam.PRINCIPALS]]:
                with pam.session(username, values[key], {username}) as user_api:
                    if username != pam.SERVICE:
                        visible = pam.connections(user_api)
                        if visible:
                            raise pam.FixtureError("Unapproved user sees native connections.")
            with db:
                pam.audit(db, None, "guacadmin", "provisioned")
            pam.seal(local, True)
        finally:
            api.logout()
            if db is not None:
                db.close()
    return {"provisioned": True, "authentication": "native PostgreSQL", "rdp": "pending"}


def main(argv=None):
    parser = pam.SafeArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "provision"))
    args = parser.parse_args(argv)
    try:
        print(json.dumps({"prepare": prepare, "provision": provision}[args.command](), sort_keys=True))
    except pam.FixtureError as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, IndexError, pam.sqlite3.Error):
        print("Error: invalid or inaccessible preparation state; details withheld.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
