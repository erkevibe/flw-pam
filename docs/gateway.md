# Guacamole SSH laboratory

The runnable slice connects a native Guacamole user to one isolated Debian SSH
target. The workflow prototype and its tests are unchanged and have no gateway
integration. This is native Guacamole login + isolated SSH proof only.

## Start and verify

Run from the product root on a trusted Linux Docker host with Python 3.11+ and
Compose v2. Initial image pulls and package installation require internet access.

```sh
python3 lab/bootstrap.py prepare
docker compose --env-file lab/.local/.env up -d --build
python3 lab/bootstrap.py provision
python3 -B -m unittest -q
python3 tests/integration_gateway.py --static
python3 tests/integration_gateway.py --live
```

Provision must follow startup promptly to replace the shipped administrator
password. Open <http://127.0.0.1:8080/guacamole/> and log in as `pam-user` with the
generated `GUAC_PASSWORD` from `lab/.local/.env`. Inspect that file privately,
without printing or sharing its contents. `pam-denied` has its own password and
no connection access. `guacadmin` uses the generated administrator password.
These are native database accounts, not SSO identities.

The separate integration test artifact owns the static and live test commands.
Offline development cannot run Docker and does not demonstrate live success.
Acceptance requires an actual successful live gate on a separate runtime copy:
denied bad credentials, denied limited-user access, an authenticated HTTP tunnel
carrying the shell command, independently read-back target marker, session close,
and parsed real protocol recording. Static results do not replace that gate.

## Runtime design

| Service | Image | Network | Persistent storage |
| --- | --- | --- | --- |
| guacamole | guacamole/guacamole:1.6.0 | control, frontend | recordings, read-only |
| guacd | guacamole/guacd:1.6.0 | control, target | recordings, read/write |
| postgres | postgres:16 | control | postgres-data |
| ssh-target | debian:bookworm-slim + openssh-server | target | ssh-host-keys at /etc/ssh |
| recording-init | debian:bookworm-slim | none | sets recording root permissions |

There are exactly three locally managed networks: `control` and `target` have
`internal: true`; `frontend` has `internal: false` and only Guacamole joins it.
The frontend bridge provides host ingress: Docker 29.6 startup with an
internal-only web network refused loopback connections despite a healthy
container. PostgreSQL remains on control only, guacd on control and target, and
SSH on target only. No network uses `external: true`. Only
`127.0.0.1:8080:8080` is published; PostgreSQL, guacd, and SSH publish no ports.
Compose does not fix a project or container name; retain the caller's `COMPOSE_PROJECT_NAME`
across all commands. There is no Docker socket, privileged mode, or host namespace.
Healthchecks and bootstrap readiness retries are bounded. PostgreSQL must become
healthy before the web service starts. PostgreSQL receives the official schema
through one read-only `001-initdb.sql` mount, applied only on first database init.

Prepare invokes the official schema generator exactly:

```sh
docker run --rm guacamole/guacamole:1.6.0 /opt/guacamole/bin/initdb.sh --postgresql
```

Its output is captured into `lab/.local/initdb.sql`; errors cannot become a
successful prepare. The schema has mode 0644 for the container's database user.
Generated passwords are absent from it. Credentials use atomic writes, mode
0600, and a mode-0700 containing directory. Reruns validate and preserve `.env`;
missing credentials alongside existing local state fail. Keep the original
`.env` with persistent volumes: losing it is not a request to rotate the database.

Provision uses only loopback REST, bypasses HTTP proxies, and rejects redirects
before credentials or tokens can be forwarded. Errors omit server bodies and
Docker output. It first authenticates with the saved administrator password;
only an authentication rejection permits trying the shipped initial password.
Initial rotation uses the dedicated `/users/guacadmin/password` endpoint. The
two lab users are reconciled by name, group memberships and unrelated access
removed, and only `pam-user` receives READ on the single named lab connection.
Tokens are invalidated on exit where the server remains reachable.

Target startup sets the generated password without printing it, disables root
SSH login and forwarding, and runs sshd in the foreground. Ed25519 host keys
persist at `/etc/ssh/ssh_host_ed25519_key` and `.pub`. Provision reads the public
key with `docker compose --env-file lab/.local/.env exec -T ssh-target cat
/etc/ssh/ssh_host_ed25519_key.pub`. The connection's `host-key` contains one entry
of the form `ssh-target ssh-ed25519 <base64-public-key>`. Existing recorded pins
are never silently changed.

`lab/.local/state.json` has mode 0600 and contains only `connection_id` (string),
`data_source` (`postgresql`), `base_url` (the loopback URL), `host_key` (the full
known_hosts entry), and `recording_root` (`/var/lib/guacamole/recordings`). No
passwords or tokens are included. This is the live verifier's discovery interface.

## Recordings and lifecycle

The connection uses `recording-path=${HISTORY_PATH}/${HISTORY_UUID}`,
`create-recording-path=true`, and `recording-name=recording`. The web recording
extension is enabled and searches `/var/lib/guacamole/recordings`. Guacd writes
the shared volume and the web container mounts it read-only.

Compose preserves the pinned images' native users: guacd runs as UID/GID
1000:1000 and the web service as UID/GID 1001:1001. These identities were verified
by running `id` in the official 1.6.0 images. The isolated init helper sets the
recording root to owner 1000:1001, mode 2750, without world access. The setgid bit
makes session directories inherit group 1001 so the web service can read them.
Actual session recording and playback still require the live gate.

Disconnect before playback in Guacamole's administrator connection history.
To inspect sizes without dumping session contents:

```sh
docker compose --env-file lab/.local/.env exec -T guacd sh -c 'find /var/lib/guacamole/recordings -type f -name recording -exec wc -c {} \;'
docker compose --env-file lab/.local/.env down
docker compose --env-file lab/.local/.env up -d --build
python3 lab/bootstrap.py provision
```

`down` retains all named volumes. Preserve `.local` and the same project name.
For an intentional **destructive reset only**, use `down --volumes`, then remove
`lab/.local`; this discards the database, recordings, host identity and credentials.
See the [operator guide](../lab/README.md) for the exact reset commands.

## Unimplemented scope

Authentik SSO/MFA, workflow JIT/grant expiry/revoke integration, Vault, session
retention/WORM, real servers, and production hardening remain unimplemented.
Database owners and Docker administrators can inspect or alter credentials and
recordings. Loopback HTTP is accessible to local host users. Neither immutable
audit nor production security is claimed.

## Official references

- [Guacamole 1.6 Docker configuration](https://guacamole.apache.org/doc/1.6.0/gug/guacamole-docker.html)
- [SSH known_hosts verification](https://guacamole.apache.org/doc/1.6.0/gug/configuring-guacamole.html#ssh-host-verification)
- [Recording paths, numeric IDs and directory permissions](https://guacamole.apache.org/doc/1.6.0/gug/recording-playback.html)
- [Native user password REST implementation](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole/src/main/java/org/apache/guacamole/rest/user/UserResource.java)
- [Web image source](https://github.com/apache/guacamole-client/blob/1.6.0/Dockerfile) and [guacd image source](https://github.com/apache/guacamole-server/blob/1.6.0/Dockerfile)
