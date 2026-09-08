# Local SSH gateway laboratory

This slice provides native Guacamole login and an isolated SSH target with session
recording. It is a local laboratory, not a production access service. The existing
workflow prototype remains separate.

## Quickstart

Use Linux, Python 3.11+ and Docker Engine with the Docker Compose v2 plugin. Run
these commands from the product root on a trusted machine. Image pulls and the
Debian package build require internet access. The `control` and `target` networks
are internal; only Guacamole joins the non-internal `frontend` bridge for host
ingress. Keep port 8080 available. Do not export credential variables in your
shell: Compose shell variables take precedence over `--env-file`.

```sh
python3 lab/bootstrap.py prepare
docker compose --env-file lab/.local/.env up -d --build
python3 lab/bootstrap.py provision
```

Run provision promptly after startup: the official database initially contains
the default administrator login. Provision first tries the stored administrator
password, and on the first run rotates the shipped password through the native
password API before setting up users or connections. If any command fails, stop
and resolve it; a successful prepare does not mean the stack is running.

Open <http://127.0.0.1:8080/guacamole/> locally. Retrieve the generated password
from `lab/.local/.env` using a private local editor; do not paste the file into
logs, tickets, or chat. Log in as `pam-user` using `GUAC_PASSWORD`, then open
**PAM lab SSH**. `pam-denied` uses `GUAC_LIMITED_PASSWORD` and has no connection
permission. `guacadmin` uses `GUAC_ADMIN_PASSWORD` for native administration.
The target's ordinary Linux account is `pam-lab`; no external SSH service is used.

The `.env` has plain `KEY=value` lines and exactly these keys:

```text
POSTGRES_DB
POSTGRES_USER
POSTGRES_PASSWORD
SSH_USERNAME
SSH_PASSWORD
GUAC_ADMIN_USERNAME
GUAC_ADMIN_PASSWORD
GUAC_USERNAME
GUAC_PASSWORD
GUAC_LIMITED_USERNAME
GUAC_LIMITED_PASSWORD
```

Secrets come from Python's `secrets` module and are distinct, URL-safe values.
The containing directory has mode 0700, and `.env` and `state.json` have mode
0600. The official schema is stored as `lab/.local/initdb.sql`, mode 0644 so the
PostgreSQL container can read its single read-only file mount; it contains no
generated passwords. All these files are ignored by Git. The build context is
`docs/`, which excludes generated lab secrets; the SSH Dockerfile needs no COPY.
Docker administrators can inspect container environment variables and database
contents. This is not a secrets vault.

Prepare preserves valid credentials and SQL on rerun. Malformed or partial
credentials fail without replacement. A failed schema generation returns nonzero;
rerun prepare after fixing Docker. Provision reuses the named connection and
dedicated accounts, reapplies their intended permissions, and never resets the
database. Changes to a previously recorded SSH host key fail closed. Restore the
original host-key volume instead of casually accepting a new identity.

## Verification

```sh
python3 -B -m unittest -q
python3 tests/integration_gateway.py --static
```

The integration script is a separately supplied test artifact. Static checks
must pass but cannot establish that Docker, SSH, or recording works. On a trusted
Docker host, after startup and provision, run the live check from the product root:

```sh
python3 tests/integration_gateway.py --live
```

The live gate must reject a wrong password and the limited account's connection
attempt, send a unique marker command through an authenticated native Guacamole
HTTP tunnel, read back that marker through read-only Docker exec, close the
session, and validate a nonempty protocol recording. Failure or unavailable
Docker must be a nonzero result, never a skipped success. For acceptance, run this
on a separate copy so generated state does not alter the candidate source.
No live Docker success is claimed by offline development checks.

## Recordings and persistence

Disconnect the session before inspecting its recording. As administrator, use
Guacamole's connection history to play it back. Files are also available under
`/var/lib/guacamole/recordings/<history-uuid>/recording` in the recording volume:

```sh
docker compose --env-file lab/.local/.env exec -T guacd sh -c 'find /var/lib/guacamole/recordings -type f -name recording -exec wc -c {} \;'
docker compose --env-file lab/.local/.env exec -T ssh-target cat /etc/ssh/ssh_host_ed25519_key.pub
```

File sizes alone do not prove valid recordings; the live test must parse actual
Guacamole instructions. Avoid displaying recording contents in shared terminals:
they contain session data. Web access to the shared recording volume is read-only.
Compose preserves the official 1.6.0 images' native users: guacd UID/GID 1000:1000
and web UID/GID 1001:1001. The isolated init helper sets the recording root to
owner 1000:1001 and mode 2750; session directories inherit the web-readable group
through the setgid bit, without granting world access.

Stop while retaining the database, SSH host keys, and recordings:

```sh
docker compose --env-file lab/.local/.env down
```

Restart with the same credentials and the same `COMPOSE_PROJECT_NAME`, if set:

```sh
docker compose --env-file lab/.local/.env up -d --build
python3 lab/bootstrap.py provision
```

Do not remove `.local` while retaining volumes. Back up it and the named volumes
together. **Destructive reset**, only when deliberately discarding the entire lab:

```sh
docker compose --env-file lab/.local/.env down --volumes
rm -rf -- lab/.local
```

This deletes credentials, database, host keys, and recordings. The next prepare
creates a new identity. Ordinary stop/restart never uses `--volumes`.

## Boundaries

The sole published port is `127.0.0.1:8080:8080`. PostgreSQL joins only `control`;
guacd joins `control` and `target`; SSH joins only `target`; Guacamole joins
`control` and `frontend`. The `control` and `target` networks remain internal.
Only Guacamole joins `frontend`, a locally managed bridge with `internal: false`
needed for host ingress: Docker 29.6 startup with an internal-only web network
refused loopback connections despite a healthy container. No network is external.
There are no published PostgreSQL, guacd, or SSH ports, host namespaces,
privileged containers, or Docker socket mounts.

This is **native Guacamole login + isolated SSH proof only**. Authentik SSO/MFA,
workflow JIT/grant expiry/revoke integration, Vault, session retention/WORM, real
servers, and production hardening remain unimplemented. HTTP and password SSH
are for this local lab. Other users of the same host can reach its loopback port.
See [gateway design and sources](../docs/gateway.md).
