#!/usr/bin/env python3
"""Independent, stdlib-only acceptance checks for the local gateway contract.

--static is offline: a deliberately limited Compose YAML reader, source checks,
and prepare CLI tests with Docker schema generation explicitly mocked in /tmp.
It cannot establish Docker readiness. --live requires an already provisioned
stack and makes a real native HTTP tunnel; nothing is skipped when unavailable.
Only JSON summaries go to stdout. Server bodies and subprocess diagnostics are
never echoed because they can contain passwords or authentication tokens.

Protocol references (Apache Guacamole 1.6.0):
https://github.com/apache/guacamole-client/blob/1.6.0/guacamole-common-js/src/main/webapp/modules/Tunnel.js
https://github.com/apache/guacamole-client/blob/1.6.0/guacamole-common-js/src/main/webapp/modules/Client.js
https://guacamole.apache.org/doc/1.6.0/gug/configuring-guacamole.html#ssh-host-verification
"""

import argparse
import ast
import base64
import codecs
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8080/guacamole/"
RECORDING_ROOT = "/var/lib/guacamole/recordings"
ENV_KEYS = {
    "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "SSH_USERNAME",
    "SSH_PASSWORD", "GUAC_ADMIN_USERNAME", "GUAC_ADMIN_PASSWORD",
    "GUAC_USERNAME", "GUAC_PASSWORD", "GUAC_LIMITED_USERNAME", "GUAC_LIMITED_PASSWORD",
}
NAMES = {"SSH_USERNAME": "pam-lab", "GUAC_ADMIN_USERNAME": "guacadmin",
         "GUAC_USERNAME": "pam-user", "GUAC_LIMITED_USERNAME": "pam-denied"}
FILES = ("compose.yaml", "lab/Dockerfile.ssh", "lab/bootstrap.py",
         "lab/README.md", ".gitignore", "docs/gateway.md")
DEADLINE = 0.0


class Failure(Exception):
    """A diagnostic known not to contain credentials or response bodies."""


def require(condition, message):
    if not condition:
        raise Failure(message)


def budget(maximum=10):
    left = DEADLINE - time.monotonic() if DEADLINE else maximum
    require(left > 0, "overall acceptance deadline exceeded")
    return max(0.01, min(maximum, left))


def instruction(*parts):
    return ",".join(f"{len(str(p))}.{p}" for p in parts) + ";"


class Protocol:
    """Incremental character-length parser, including HTTP's empty terminator."""

    def __init__(self):
        self.buffer = ""
        self.parts = []

    def feed(self, text):
        self.buffer += text
        result = []
        while self.buffer:
            dot = self.buffer.find(".")
            if dot < 0:
                require(len(self.buffer) <= 8 and self.buffer.isascii()
                        and self.buffer.isdigit(), "invalid protocol length")
                break
            length = self.buffer[:dot]
            require(0 < len(length) <= 8 and length.isascii() and length.isdigit(),
                    "invalid protocol length")
            end = dot + 1 + int(length)
            require(int(length) <= 16 * 1024 * 1024, "oversized protocol element")
            if len(self.buffer) <= end:
                break
            require(self.buffer[end] in ",;", "invalid protocol separator")
            self.parts.append(self.buffer[dot + 1:end])
            require(len(self.parts) <= 64, "too many protocol elements")
            done = self.buffer[end] == ";"
            self.buffer = self.buffer[end + 1:]
            if done:
                result.append(self.parts)
                self.parts = []
        return result

    def finish(self):
        require(not self.buffer and not self.parts, "truncated protocol stream")


def parse_env(text):
    values = {}
    for line in text.splitlines():
        require(bool(re.fullmatch(r"[A-Z_]+=[A-Za-z0-9_-]+", line)),
                "environment must contain plain URL-safe KEY=value lines")
        key, value = line.split("=", 1)
        require(key not in values, "duplicate environment key")
        values[key] = value
    require(set(values) == ENV_KEYS, "environment keys differ from contract")
    require(all(values[k] == v for k, v in NAMES.items()), "incorrect native user names")
    passwords = [v for k, v in values.items() if k.endswith("PASSWORD")]
    require(all(len(v) >= 24 for v in passwords), "generated passwords lack sufficient length")
    require(len(set(passwords)) == len(passwords), "generated passwords must be independent")
    return values


def host_key(value):
    require(isinstance(value, str) and "\n" not in value and "\r" not in value,
            "host-key must be a single known_hosts entry")
    parts = value.split()
    require(len(parts) == 3 and parts[:2] == ["ssh-target", "ssh-ed25519"],
            "host-key must include ssh-target and ssh-ed25519")
    try:
        blob = base64.b64decode(parts[2], validate=True)
    except ValueError:
        raise Failure("invalid host-key encoding") from None
    require(len(blob) == 51 and blob[:19] == b"\0\0\0\x0bssh-ed25519\0\0\0\x20",
            "invalid Ed25519 host-key structure")
    return " ".join(parts)


def split_flow(text):
    """Split a small YAML flow collection without splitting quoted strings."""
    result, start, depth, quote, escaped = [], 0, 0, None, False
    for index, char in enumerate(text):
        if quote:
            if char == quote and not escaped:
                quote = None
            escaped = char == "\\" and not escaped
        elif char in "\"'":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    require(quote is None and depth == 0, "unsupported or malformed YAML flow value")
    result.append(text[start:].strip())
    return result if text.strip() else []


def scalar(text):
    text = text.strip()
    if text.startswith('"'):
        return json.loads(text)
    if text.startswith("'"):
        require(text.endswith("'"), "unterminated YAML quote")
        return text[1:-1].replace("''", "'")
    if text.startswith("["):
        require(text.endswith("]"), "unterminated YAML list")
        return [scalar(v) for v in split_flow(text[1:-1])]
    if text.startswith("{"):
        require(text.endswith("}"), "unterminated YAML map")
        result = {}
        for pair in split_flow(text[1:-1]):
            key, sep, value = pair.partition(":")
            require(sep and key.strip() not in result, "invalid YAML flow mapping")
            result[str(scalar(key))] = scalar(value)
        return result
    require(not text.startswith(("&", "*", "!")), "YAML anchors, aliases and tags unsupported offline")
    if text.lower() in ("true", "false"):
        return text.lower() == "true"
    if text in ("", "null", "~"):
        return None
    return text


def compose_yaml(text):
    """Contract-specific block/flow YAML subset; unsupported syntax fails closed.

    This is NOT a complete Compose validator. Live mode also checks Docker's
    fully resolved JSON configuration. No Docker or YAML dependency is used here.
    """
    lines = []
    for raw in text.splitlines():
        require("\t" not in raw[:len(raw) - len(raw.lstrip())], "YAML indentation contains tabs")
        # Strip comments only outside quotes, retaining shell/block content.
        quote = None
        for i, char in enumerate(raw):
            if char in "\"'" and (i == 0 or raw[i - 1] != "\\"):
                quote = None if quote == char else (char if quote is None else quote)
            if char == "#" and quote is None and (i == 0 or raw[i - 1].isspace()):
                raw = raw[:i]
                break
        if raw.strip() and raw.strip() != "---":
            lines.append((len(raw) - len(raw.lstrip()), raw.strip()))

    def block(index, indent):
        is_list = lines[index][1].startswith("- ")
        out = [] if is_list else {}
        while index < len(lines) and lines[index][0] == indent:
            item = lines[index][1]
            index += 1
            if is_list:
                require(item.startswith("- "), "mixed YAML mapping and list")
                item = item[2:].strip()
            match = re.match(r"^([A-Za-z0-9_.-]+):(?:\s+(.*)|$)", item)
            if match:
                key, value = match.group(1), match.group(2) or ""
                require(key != "<<", "YAML merge unsupported offline")
                target = {} if is_list else out
                require(key not in target, "duplicate YAML key")
                if value in ("|", ">", "|-", ">-", "|+", ">+"):
                    chunks = []
                    while index < len(lines) and lines[index][0] > indent:
                        chunks.append(lines[index][1])
                        index += 1
                    target[key] = ("\n" if value.startswith("|") else " ").join(chunks)
                elif not value and index < len(lines) and lines[index][0] > indent:
                    target[key], index = block(index, lines[index][0])
                else:
                    target[key] = scalar(value)
                if is_list:
                    if index < len(lines) and lines[index][0] > indent:
                        rest, index = block(index, lines[index][0])
                        require(isinstance(rest, dict) and not set(rest) & set(target),
                                "invalid YAML list mapping")
                        target.update(rest)
                    out.append(target)
            else:
                require(is_list, "unsupported YAML mapping syntax")
                out.append(scalar(item))
        return out, index

    require(lines and lines[0][0] == 0, "empty or indented Compose document")
    result, end = block(0, 0)
    require(end == len(lines) and isinstance(result, dict), "unsupported YAML structure")
    return result


def environment(service):
    env = service.get("environment", {})
    if isinstance(env, list):
        mapped = {}
        for entry in env:
            key, sep, value = entry.partition("=")
            require(sep and key not in mapped, "invalid Compose environment list")
            mapped[key] = value
        env = mapped
    require(isinstance(env, dict), "Compose environment must be explicit")
    return {k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in env.items()}


def mounts(service):
    result = {}
    for entry in service.get("volumes", []):
        if isinstance(entry, str):
            bits = entry.split(":")
            require(2 <= len(bits) <= 3, "volume must have explicit source and target")
            source, target = bits[:2]
            kind = "bind" if source.startswith((".", "/", "~")) else "volume"
            readonly = len(bits) == 3 and "ro" in bits[2].split(",")
        else:
            source, target = entry.get("source"), entry.get("target")
            kind, readonly = entry.get("type"), entry.get("read_only", False)
        require(source and target and target not in result, "invalid or duplicate volume target")
        require("docker.sock" not in source and target != "/var/run/docker.sock",
                "Docker socket mount forbidden")
        result[target] = (source, kind, bool(readonly))
    return result


def check_compose(config, resolved=False):
    services = config.get("services", {})
    required = {"guacamole", "guacd", "postgres", "ssh-target"}
    require(required <= set(services), "required service missing")
    extra = set(services) - required
    require(len(extra) <= 1, "only one optional initialization service is permitted")
    networks = config.get("networks", {})
    require(set(networks) == {"control", "target", "frontend"},
            "network allowlist must be control, target and frontend")
    for name, internal in {"control": True, "target": True, "frontend": False}.items():
        network = networks[name]
        # Resolved Compose JSON may omit the default internal:false value.
        require(isinstance(network, dict)
                and network.get("internal", False if resolved else None) is internal
                and not network.get("external"),
                "network must be locally owned with internal:%s: %s" % (str(internal).lower(), name))
    if not resolved:
        require("name" not in config, "Compose must respect caller project name")
    expected = {"guacamole": {"control", "frontend"}, "postgres": {"control"},
                "guacd": {"control", "target"}, "ssh-target": {"target"}}
    images = {"guacamole": "guacamole/guacamole:1.6.0",
              "guacd": "guacamole/guacd:1.6.0", "postgres": "postgres:16"}
    volumes = config.get("volumes", {})
    for name, service in services.items():
        require(isinstance(service, dict), "invalid Compose service")
        for forbidden in ("container_name", "pid", "ipc", "volumes_from",
                          "devices", "external_links", "extra_hosts", "extends", "provider"):
            require(forbidden not in service, "forbidden Compose setting: " + forbidden)
        if "network_mode" in service:
            require(name in extra and service["network_mode"] == "none"
                    and "networks" not in service,
                    "network_mode permits only none on the isolated init helper")
        require(not service.get("privileged") and not service.get("cap_add"),
                "privilege escalation settings forbidden")
        require(not service.get("profiles"), "required stack must not depend on profiles")
        attached = service.get("networks", {})
        require(isinstance(attached, (list, dict)), "explicit service networks required")
        if name in expected:
            require(set(attached) == expected[name], "network membership incorrect: " + name)
        else:
            require(set(attached) <= {"control", "target"}, "init network outside allowlist")
        if name in images:
            require(service.get("image") == images[name], "missing exact image pin: " + name)
            require("build" not in service, "official service image must not be replaced by build")
        if name in ("guacd", "guacamole"):
            require("user" not in service, "preserve native image user: " + name)
        ports = service.get("ports", [])
        if name == "guacamole":
            require(len(ports) == 1, "web must publish exactly one port")
            port = ports[0]
            if isinstance(port, str):
                require(port in ("127.0.0.1:8080:8080", "127.0.0.1:8080:8080/tcp"),
                        "web binding must be loopback port 8080 only")
            else:
                require(port.get("host_ip") == "127.0.0.1"
                        and str(port.get("published")) == "8080"
                        and str(port.get("target")) == "8080"
                        and port.get("protocol", "tcp") == "tcp",
                        "web binding must be loopback port 8080 only")
        else:
            require(not ports, "non-web service publishes host ports")
        for source, kind, _ in mounts(service).values():
            if kind == "bind":
                normalized = source.replace("\\", "/")
                require(("lab/.local/" in normalized or normalized.endswith("lab/.local"))
                        and ".." not in Path(source).parts,
                        "bind mounts must stay inside generated lab/.local state")
            else:
                require(kind == "volume" and source in volumes, "persistent volume must be named")
        for key, value in environment(service).items():
            if "PASSWORD" in key and not resolved:
                require(bool(re.fullmatch(r"\$\{[A-Z_]+(?::\?[^}]*)?\}", value)),
                        "Compose password must come from generated environment")
    web = environment(services["guacamole"])
    for key, value in {"GUACD_HOSTNAME": "guacd", "POSTGRESQL_HOSTNAME": "postgres",
                       "POSTGRESQL_PORT": "5432", "RECORDING_ENABLED": "true",
                       "RECORDING_SEARCH_PATH": RECORDING_ROOT}.items():
        require(web.get(key) == value, "missing Guacamole environment setting: " + key)
    for key in ("POSTGRESQL_DATABASE", "POSTGRESQL_USERNAME", "POSTGRESQL_PASSWORD"):
        require(web.get(key) not in (None, "", "None"), "missing PostgreSQL web configuration")
    require("build" in services["ssh-target"], "SSH target must be locally built")
    pg = services["postgres"]
    health = pg.get("healthcheck", {})
    require(health.get("test") and not health.get("disable") and health.get("retries"),
            "PostgreSQL needs a bounded healthcheck")
    deps = services["guacamole"].get("depends_on", {})
    require(isinstance(deps, dict) and isinstance(deps.get("postgres"), dict)
            and deps["postgres"].get("condition") == "service_healthy",
            "Guacamole must wait for PostgreSQL health")
    pm, gm, wm, sm = (mounts(services[n]) for n in ("postgres", "guacd", "guacamole", "ssh-target"))
    require("/var/lib/postgresql/data" in pm and pm["/var/lib/postgresql/data"][1:] == ("volume", False),
            "PostgreSQL data must persist in a writable named volume")
    init = [(target, spec) for target, spec in pm.items() if target.startswith("/docker-entrypoint-initdb.d/")]
    require(len(init) == 1 and init[0][0].endswith(".sql")
            and init[0][1][0].endswith("lab/.local/initdb.sql") and init[0][1][2],
            "official initdb.sql must be mounted alone and read-only")
    require("/docker-entrypoint-initdb.d" not in pm, "initdb directory must not mix secrets and SQL")
    require(RECORDING_ROOT in gm and RECORDING_ROOT in wm,
            "recording root must be mounted in both Guacamole services")
    require(gm[RECORDING_ROOT][1:] == ("volume", False)
            and wm[RECORDING_ROOT][1:] == ("volume", True)
            and gm[RECORDING_ROOT][0] == wm[RECORDING_ROOT][0],
            "recording volume must be shared, guacd writable and web read-only")
    require(any((target == "/etc/ssh" or target == "/etc/ssh/ssh_host_ed25519_key")
                and spec[1:] == ("volume", False) for target, spec in sm.items()),
            "SSH host key at /etc/ssh must persist in a named volume")
    require(all(not (v or {}).get("external") and not (v or {}).get("driver_opts")
                for v in volumes.values()), "external or host-backed volume driver settings forbidden")


def helper_checks():
    sample = instruction("name", "a,.;é中") + instruction("sync", "123") + "0.;"
    parser, got = Protocol(), []
    for char in sample:
        got.extend(parser.feed(char))
    parser.finish()
    require(got == [["name", "a,.;é中"], ["sync", "123"], [""]], "protocol roundtrip failed")
    for invalid in ("x.a;", "1.ax", "2.a;", "1.a,", "999999999.a;"):
        try:
            parser = Protocol()
            parser.feed(invalid)
            parser.finish()
        except Failure:
            continue
        raise Failure("malformed protocol accepted")
    env = {k: secrets.token_urlsafe(24) for k in ENV_KEYS}
    env.update(NAMES)
    valid = "\n".join(k + "=" + v for k, v in env.items()) + "\n"
    require(parse_env(valid) == env, "environment roundtrip failed")
    for bad in (valid + "SSH_USERNAME=other\n", valid.replace("SSH_USERNAME=", "#SSH_USERNAME="),
                valid.replace("GUAC_PASSWORD=", "MISSING_PASSWORD="), ""):
        try:
            parse_env(bad)
        except Failure:
            continue
        raise Failure("malformed environment accepted")
    key = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(32)).decode()
    require(host_key("ssh-target " + key).startswith("ssh-target "), "host-key parser failed")
    for bad in (key, "other " + key, "ssh-target " + key + "\n"):
        try:
            host_key(bad)
        except Failure:
            continue
        raise Failure("invalid host-key accepted")
    parsed = compose_yaml('services:\n  x:\n    networks: [control, target]\n    environment:\n      X: "a#b"\n    volumes:\n      - type: volume\n        source: data\n        target: /data\nnetworks: {control: {internal: true}}\n')
    require(parsed["services"]["x"]["networks"] == ["control", "target"]
            and parsed["services"]["x"]["environment"]["X"] == "a#b"
            and mounts(parsed["services"]["x"])["/data"] == ("data", "volume", False),
            "Compose subset parser failed")


def source_checks(sources):
    tree = ast.parse(sources["lab/bootstrap.py"], filename="lab/bootstrap.py")
    compile(tree, "lab/bootstrap.py", "exec")
    compile(Path(__file__).read_text(), str(__file__), "exec")
    imports = {n.names[0].name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
    imports |= {n.module.split(".")[0] for n in ast.walk(tree)
                if isinstance(n, ast.ImportFrom) and n.module}
    require(imports <= sys.stdlib_module_names, "bootstrap must use Python standard library only")
    require("secrets" in imports, "bootstrap must use the secrets module")
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    literals = "\n".join(strings)
    for value in ("prepare", "provision", "host-key", "recording-path", "create-recording-path",
                  "recording-name", "${HISTORY_PATH}/${HISTORY_UUID}", "recording",
                  "connection_id", "data_source", "base_url", "host_key", "recording_root",
                  "--env-file", "--postgresql", "guacamole/guacamole:1.6.0"):
        require(value in literals, "bootstrap missing contract literal: " + value)
    require("/opt/guacamole/bin/initdb.sh" in literals, "bootstrap must use official schema generator")
    require(all(k in literals for k in ENV_KEYS), "bootstrap missing required generated environment key")
    require(not re.search(r"\b(?:DROP\s+(?:DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b", literals, re.I),
            "bootstrap must not reset an existing database")
    # Membership checks for table-name markers validate output, not invent DDL.
    schema_markers = {id(n.left) for n in ast.walk(tree) if isinstance(n, ast.Compare)
                      and len(n.ops) == 1 and isinstance(n.ops[0], (ast.In, ast.NotIn))
                      and isinstance(n.left, ast.Constant) and isinstance(n.left.value, str)
                      and re.fullmatch(r"CREATE TABLE [a-z_]+", n.left.value)}
    schema_literals = "\n".join(n.value for n in ast.walk(tree)
                               if isinstance(n, ast.Constant) and isinstance(n.value, str)
                               and id(n) not in schema_markers)
    require(not re.search(r"\bCREATE\s+TABLE\b", schema_literals, re.I),
            "bootstrap must not invent Guacamole schema")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if name in ("print", "debug", "info", "warning", "error", "exception"):
                rendered = " ".join(ast.unparse(a) for a in node.args)
                # Static direct-leak guard; prepare is also exercised with real generated secrets.
                require(not re.search(r"\b(?:password|authToken|auth_token|token|environ)\b", rendered)
                        or all(isinstance(a, ast.Constant) for a in node.args),
                        "bootstrap may print sensitive runtime data")
    dockerfile = sources["lab/Dockerfile.ssh"]
    require(re.search(r"(?im)^FROM\s+debian:bookworm-slim\s*$", dockerfile), "SSH base image pin missing")
    require("openssh-server" in dockerfile, "SSH image must install openssh-server")
    require(re.search(r"PermitRootLogin\s+no", dockerfile), "root SSH login must be disabled")
    require(re.search(r"PasswordAuthentication\s+yes", dockerfile), "local lab SSH password auth missing")
    require("sshd" in dockerfile and re.search(r"(?:\s|[\"'])-D(?:\s|[\"'])", dockerfile),
            "SSH daemon must run in foreground")
    joined = "\n".join(sources.values())
    require(not re.search(r"chmod\s+(?:-[A-Za-z]+\s+)*0?777\b", joined)
            and not re.search(r"0o777\b", sources["lab/bootstrap.py"]), "world-writable permissions forbidden")
    require("2750" in joined and "1001" in joined and "1000" in joined,
            "recording owner/group/mode guidance missing")
    require(not re.search(r"(?:StrictHostKeyChecking\s*[= ]\s*no|ignore-host-key\s*[=:]\s*true)", joined, re.I),
            "SSH host-key verification bypass forbidden")
    require(any(line.strip().rstrip("/") in ("lab/.local", "/lab/.local", ".local", "**/.local")
                for line in sources[".gitignore"].splitlines()), "generated lab/.local must be gitignored")
    for name, content in sources.items():
        require("PRIVATE KEY-----" not in content, "private key in product source: " + name)
        require(not re.search(r"(?im)^\s*(?:" + "|".join(k for k in ENV_KEYS if k.endswith("PASSWORD"))
                              + r")\s*=\s*[A-Za-z0-9_-]{16,}\s*$", content),
                "literal generated credential in product source: " + name)


def prepare_checks(sources):
    """Black-box prepare behavior with an explicitly offline schema-generation stub.

    All files and subprocess capture live in TemporaryDirectory outside source.
    No bootstrap helper names are assumed. The stub only accepts the documented
    official image/initdb command, and can inject a schema-generator failure.
    """
    with tempfile.TemporaryDirectory(prefix="gateway-static-", dir="/tmp") as directory:
        root = Path(directory)
        for name, content in sources.items():
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)
        binary = root / "bin"
        binary.mkdir()
        docker = binary / "docker"
        docker.write_text("#!" + sys.executable + "\n" + '''import os, sys
from pathlib import Path
args = sys.argv[1:]
valid = (args[:2] == ["run", "--rm"] and args[-3:] ==
    ["guacamole/guacamole:1.6.0", "/opt/guacamole/bin/initdb.sh", "--postgresql"])
if not valid:
    sys.exit(91)
with open(os.environ["QA_SCHEMA_CALLS"], "a") as calls:
    calls.write("official-schema-command\\n")
if os.environ.get("QA_SCHEMA_FAIL") == "1":
    sys.exit(92)
sys.stdout.write("-- Offline unit-test schema substitute; never live evidence.\\n"
                 "-- CREATE TABLE guacamole_user; guacamole_connection\\nSELECT 1;\\n")
''')
        docker.chmod(0o700)
        runner = root / "offline_runner.py"
        runner.write_text('''import runpy, socket, sys
def offline(*args, **kwargs):
    raise RuntimeError("network forbidden during offline prepare test")
socket.socket.connect = offline
socket.create_connection = offline
sys.argv = ["lab/bootstrap.py", "prepare"]
runpy.run_path("lab/bootstrap.py", run_name="__main__")
''')
        env = {k: v for k, v in os.environ.items() if k not in ENV_KEYS}
        env.update(PATH=str(binary) + os.pathsep + os.environ.get("PATH", ""),
                   PYTHONDONTWRITEBYTECODE="1", QA_SCHEMA_CALLS=str(root / "calls"))
        captures = []

        def run(success=True):
            result = subprocess.run([sys.executable, "-B", str(runner)], cwd=root, env=env,
                                    capture_output=True, timeout=budget(20))
            captures.append(result.stdout + result.stderr)
            require((result.returncode == 0) == success,
                    "offline prepare " + ("failed with schema stub" if success else "accepted invalid/failing state"))

        run()
        local = root / "lab/.local"
        require(local.is_dir() and stat.S_IMODE(local.stat().st_mode) == 0o700, "prepare state directory mode must be 0700")
        path = local / ".env"
        require(path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o600, "prepare environment mode must be 0600")
        original = path.read_bytes()
        values = parse_env(original.decode())
        require((local / "initdb.sql").is_file() and (root / "calls").is_file(), "prepare did not invoke official schema command")
        schema = (local / "initdb.sql").read_bytes()
        require(b"SELECT 1;" in schema, "prepare ignored schema generator output")
        run()
        require(path.read_bytes() == original and (local / "initdb.sql").read_bytes() == schema,
                "prepare rerun rotated credentials or replaced existing SQL")
        for malformed in (b"POSTGRES_DB=partial\n", original + b"SSH_USERNAME=duplicate\n"):
            path.write_bytes(malformed)
            run(False)
            require(path.read_bytes() == malformed, "prepare silently rewrote malformed credentials")
        for password in (v.encode() for k, v in values.items() if k.endswith("PASSWORD")):
            require(all(password not in capture for capture in captures), "prepare leaked a generated password")
        # Fresh state exercises real error propagation, independently of idempotency.
        shutil.rmtree(local)
        env["QA_SCHEMA_FAIL"] = "1"
        run(False)
        require(not (local / "initdb.sql").exists() or not (local / "initdb.sql").stat().st_size,
                "failed schema generation left apparently valid SQL")


def static_checks():
    helper_checks()
    missing = [name for name in FILES if not (ROOT / name).is_file()]
    require(not missing, "required implementation files missing: " + ", ".join(missing))
    sources = {name: (ROOT / name).read_text() for name in FILES}
    check_compose(compose_yaml(sources["compose.yaml"]))
    source_checks(sources)
    prepare_checks(sources)
    return {"mode": "static", "passed": True,
            "checks": ["protocol_and_validation_helpers", "compose_isolation_and_pins",
                       "bootstrap_and_ssh_source", "offline_prepare_behavior"],
            "live_verified": False, "compose_parser": "contract-specific YAML subset"}


def docker(*args, allow_failure=False):
    result = subprocess.run(["docker", "compose", "--env-file", "lab/.local/.env", *args],
                            cwd=ROOT, capture_output=True, timeout=budget(15))
    require(allow_failure or result.returncode == 0, "Docker read-only evidence command failed")
    return result


class HTTP:
    """Fixed loopback origin, no proxy use, redirects or URL supplied by metadata."""

    def __init__(self):
        self.cookies = {}

    def open(self, method, path, body=None, headers=None):
        require(path.startswith(("api/", "tunnel?")) and not any(c in path for c in "\r\n"),
                "HTTP path outside gateway interface")
        headers = dict(headers or {})
        if self.cookies:
            headers["Cookie"] = "; ".join(k + "=" + v for k, v in self.cookies.items())
        conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=budget(10))
        try:
            conn.request(method, "/guacamole/" + path, body=body, headers=headers)
            response = conn.getresponse()
        except Exception:
            conn.close()
            raise
        from http.cookies import SimpleCookie
        for key, value in response.getheaders():
            if key.lower() == "set-cookie":
                cookie = SimpleCookie()
                cookie.load(value)
                self.cookies.update({k: v.value for k, v in cookie.items()})
        return conn, response

    def request(self, method, path, form=None, token=None, body=None, headers=None):
        headers = dict(headers or {})
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token:
            path += ("&" if "?" in path else "?") + urllib.parse.urlencode({"token": token})
        conn, response = self.open(method, path, body, headers)
        try:
            data = response.read(4 * 1024 * 1024 + 1)
            require(len(data) <= 4 * 1024 * 1024, "HTTP response exceeded size bound")
            return response.status, dict((k.lower(), v) for k, v in response.getheaders()), data
        finally:
            response.close()
            conn.close()

    def api(self, path, token):
        status, _, body = self.request("GET", "api/session/data/postgresql/" + path, token=token)
        require(status == 200, "Guacamole REST evidence request failed (HTTP %d)" % status)
        return json.loads(body)

    def login(self, username, password, denied=False):
        status, _, body = self.request("POST", "api/tokens", form={"username": username, "password": password})
        if denied:
            require(status in (401, 403), "invalid credentials were not explicitly denied")
            return None
        require(status == 200, "native authentication failed (HTTP %d)" % status)
        result = json.loads(body)
        require(isinstance(result.get("authToken"), str) and result["authToken"]
                and result.get("dataSource") == "postgresql", "invalid native authentication response")
        return result["authToken"]


class Tunnel:
    def __init__(self, http, token, connection_id):
        self.http, self.token, self.connection_id = http, token, connection_id
        self.uuid = self.session_token = None
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.ended = threading.Event()
        self.closing = False
        self.error = None
        self.syncs = set()
        self.opcodes = set()
        self.count = 0
        self.reader = None

    def connect(self, denied=False):
        status, headers, body = self.http.request("POST", "tunnel?connect", form={
            "token": self.token, "GUAC_DATA_SOURCE": "postgresql", "GUAC_ID": self.connection_id,
            "GUAC_TYPE": "c", "GUAC_WIDTH": "1024", "GUAC_HEIGHT": "768", "GUAC_DPI": "96",
            "GUAC_TIMEZONE": "UTC", "GUAC_AUDIO": "", "GUAC_VIDEO": "",
            "GUAC_IMAGE": "image/png", "GUAC_CLIENT_NAME": "gateway-acceptance",
        })
        if status == 200:
            try:
                self.uuid = str(uuid.UUID(body.decode().strip()))
            except (ValueError, UnicodeError):
                raise Failure("native tunnel returned an invalid UUID") from None
            self.session_token = headers.get("guacamole-tunnel-token")
            require(bool(self.session_token), "native tunnel response lacks tunnel token")
        if denied:
            if status == 200:
                self.close()
            require(status in (403, 404), "limited user was not explicitly denied a native tunnel")
            return
        require(status == 200, "native HTTP tunnel connect failed (HTTP %d)" % status)
        self.reader = threading.Thread(target=self.read_loop, name="guacamole-reader", daemon=True)
        self.reader.start()

    def write(self, text):
        with self.lock:
            status, _, _ = self.http.request("POST", "tunnel?write:" + self.uuid,
                body=text.encode(), headers={"Content-Type": "application/octet-stream",
                                            "Guacamole-Tunnel-Token": self.session_token})
        require(status == 200, "native tunnel write failed (HTTP %d)" % status)

    def read_loop(self):
        try:
            counter = 0
            while not self.ended.is_set():
                conn, response = self.http.open("GET", "tunnel?read:" + self.uuid + ":" + str(counter),
                    headers={"Guacamole-Tunnel-Token": self.session_token})
                counter += 1
                try:
                    if response.status == 404 and self.closing:
                        break
                    require(response.status == 200, "native tunnel read failed (HTTP %d)" % response.status)
                    decoder, parser = codecs.getincrementaldecoder("utf-8")(), Protocol()
                    terminated = False
                    while not terminated:
                        budget()
                        chunk = response.read1(65536)
                        text = decoder.decode(chunk, final=not chunk)
                        for parts in parser.feed(text):
                            opcode = parts[0]
                            if opcode == "":
                                require(parts == [""], "invalid HTTP tunnel stream terminator")
                                terminated = True
                                continue
                            self.count += 1
                            self.opcodes.add(opcode)
                            if opcode == "sync":
                                require(len(parts) >= 2 and parts[1].isdigit(), "invalid tunnel sync")
                                self.syncs.add(parts[1])
                                if not self.closing:
                                    self.write(instruction("sync", parts[1]))
                                self.ready.set()
                            elif opcode == "error":
                                raise Failure("guacd reported a protocol error")
                            elif opcode == "disconnect":
                                self.ended.set()
                        if not chunk:
                            terminated = True
                        if self.ended.is_set():
                            break
                    parser.finish()
                finally:
                    response.close()
                    conn.close()
        except Exception as exc:
            if not self.closing:
                self.error = exc if isinstance(exc, Failure) else Failure("native tunnel reader failed: " + type(exc).__name__)
        finally:
            self.ended.set()
            self.ready.set()

    def healthy(self):
        if self.error:
            raise self.error
        require(not self.ended.is_set(), "native tunnel ended before SSH proof")

    def type_command(self, command):
        require(command.endswith("\n") and all(32 <= ord(c) < 127 or c == "\n" for c in command),
                "unsafe marker command encoding")
        self.healthy()
        self.write("".join(instruction("key", 65293 if c == "\n" else ord(c), down)
                           for c in command for down in (1, 0)))

    def close(self):
        if not self.uuid or self.closing:
            return
        self.closing = True
        try:
            if not self.ended.is_set():
                self.write(instruction("disconnect"))
        finally:
            if self.reader:
                self.reader.join(timeout=budget(12))
                require(not self.reader.is_alive(), "native tunnel did not close within deadline")


def recording_paths():
    result = docker("exec", "-T", "guacd", "find", RECORDING_ROOT, "-type", "f", "-name", "recording", "-print")
    paths = result.stdout.decode().splitlines()
    require(all(re.fullmatch(re.escape(RECORDING_ROOT) + r"/[A-Za-z0-9_-]+/recording", p) for p in paths),
            "recording path does not follow session directory contract")
    return set(paths)


def verify_recording(path, syncs):
    size = docker("exec", "-T", "guacd", "stat", "-c", "%s", path).stdout.strip()
    require(size.isdigit() and 0 < int(size) <= 32 * 1024 * 1024, "recording empty or exceeds evidence bound")
    data = docker("exec", "-T", "guacd", "cat", path).stdout
    require(len(data) == int(size), "recording changed after session close")
    parser = Protocol()
    instructions = parser.feed(data.decode("utf-8"))
    parser.finish()
    recorded_syncs = {p[1] for p in instructions if p[0] == "sync" and len(p) >= 2}
    opcodes = {p[0] for p in instructions}
    require(len(instructions) >= 10 and "size" in opcodes
            and bool(opcodes & {"img", "png", "copy", "cfill", "rect"})
            and len(recorded_syncs & syncs) >= 2 and "error" not in opcodes,
            "recording lacks real display instructions and matching session syncs")
    return {"bytes": len(data), "instructions": len(instructions),
            "matching_syncs": len(recorded_syncs & syncs), "sha256": hashlib.sha256(data).hexdigest()}


def live_checks():
    local = ROOT / "lab/.local"
    require(local.is_dir(), "live state missing; run prepare/start/provision first")
    require(stat.S_IMODE(local.stat().st_mode) == 0o700, "live state directory mode must be 0700")
    for name in (".env", "state.json"):
        require((local / name).is_file() and not (local / name).is_symlink()
                and stat.S_IMODE((local / name).stat().st_mode) == 0o600,
                "live credential/metadata files must be regular mode 0600")
    env = parse_env((local / ".env").read_text())
    state_text = (local / "state.json").read_text()
    state = json.loads(state_text)
    require(state.get("base_url") == BASE_URL and state.get("data_source") == "postgresql"
            and state.get("recording_root") == RECORDING_ROOT, "provision metadata does not match interface")
    cid = state.get("connection_id")
    require(isinstance(cid, str) and bool(re.fullmatch(r"[0-9]+", cid)), "invalid provisioned connection identifier")
    pinned = host_key(state.get("host_key"))
    require(not any(v in state_text for k, v in env.items() if k.endswith("PASSWORD"))
            and not re.search(r'"[^"\n]*(?:password|token)[^"\n]*"\s*:', state_text, re.I),
            "state metadata contains credentials")
    config = json.loads(docker("config", "--format", "json").stdout)
    check_compose(config, resolved=True)
    public = docker("exec", "-T", "ssh-target", "cat", "/etc/ssh/ssh_host_ed25519_key.pub").stdout.decode().split()
    require(len(public) >= 2 and pinned == "ssh-target " + " ".join(public[:2]),
            "provisioned host-key does not match persistent target key")
    permissions = docker("exec", "-T", "guacd", "stat", "-c", "%u:%g:%a", RECORDING_ROOT).stdout.strip()
    require(permissions == b"1000:1001:2750", "recording root must have owner 1000, group 1001, mode 2750")
    admin, user, limited = HTTP(), HTTP(), HTTP()
    tokens = []
    tunnel = None
    try:
        user.login(env["GUAC_USERNAME"], secrets.token_urlsafe(32), denied=True)
        admin.login("guacadmin", "guacadmin", denied=True)
        at = admin.login(env["GUAC_ADMIN_USERNAME"], env["GUAC_ADMIN_PASSWORD"])
        tokens.append((admin, at))
        ut = user.login(env["GUAC_USERNAME"], env["GUAC_PASSWORD"])
        tokens.append((user, ut))
        lt = limited.login(env["GUAC_LIMITED_USERNAME"], env["GUAC_LIMITED_PASSWORD"])
        tokens.append((limited, lt))
        connections = admin.api("connections", at)
        require(isinstance(connections, dict) and set(connections) == {cid}
                and connections[cid].get("protocol") == "ssh" and connections[cid].get("name"),
                "expected exactly one named native SSH connection")
        params = admin.api("connections/" + cid + "/parameters", at)
        expected = {"hostname": "ssh-target", "port": "22", "username": env["SSH_USERNAME"],
                    "password": env["SSH_PASSWORD"], "host-key": pinned,
                    "recording-path": "${HISTORY_PATH}/${HISTORY_UUID}",
                    "create-recording-path": "true", "recording-name": "recording"}
        require(all(params.get(k) == v for k, v in expected.items()), "provisioned SSH/recording parameters differ from contract")
        require(cid in user.api("connections", ut), "ordinary user cannot read provisioned connection")
        require(cid not in limited.api("connections", lt), "limited user can enumerate provisioned connection")
        status, _, _ = limited.request("GET", "api/session/data/postgresql/connections/" + cid, token=lt)
        require(status in (403, 404), "limited user can read connection directly")
        Tunnel(limited, lt, cid).connect(denied=True)
        before = recording_paths()
        tunnel = Tunnel(user, ut, cid)
        tunnel.connect()
        require(tunnel.ready.wait(timeout=budget(30)), "native tunnel never received a sync instruction")
        tunnel.healthy()
        marker = "pam-gateway-" + secrets.token_hex(16)
        value = "gateway-proof-" + secrets.token_hex(24)
        # This is the sole marker creation path. Docker exec below is cat only.
        tunnel.type_command("printf '%s\\n' '" + value + "' > /tmp/" + marker + "\n")
        until = time.monotonic() + budget(35)
        while True:
            tunnel.healthy()
            result = docker("exec", "-T", "ssh-target", "cat", "/tmp/" + marker, allow_failure=True)
            if result.returncode == 0:
                require(result.stdout == (value + "\n").encode(), "SSH marker content mismatch")
                break
            require(time.monotonic() < until, "tunnel command did not create target marker before deadline")
            time.sleep(min(0.5, budget()))
        until = time.monotonic() + budget(10)
        while len(tunnel.syncs) < 2:
            tunnel.healthy()
            require(time.monotonic() < until, "too few session sync instructions for recording correlation")
            time.sleep(min(0.1, budget()))
        tunnel.close()
        require(tunnel.error is None, "native tunnel failed before close")
        until = time.monotonic() + budget(20)
        evidence = None
        while evidence is None:
            for path in sorted(recording_paths() - before):
                try:
                    evidence = verify_recording(path, tunnel.syncs)
                    break
                except Failure:
                    pass  # A partially flushed recording is retried, never accepted.
            require(evidence is not None or time.monotonic() < until,
                    "no new valid protocol recording correlated to this tunnel session")
            if evidence is None:
                time.sleep(min(0.5, budget()))
        return {"mode": "live", "passed": True, "checks": ["resolved_compose_isolation",
                "persistent_host_key_pin", "recording_permissions", "wrong_password_denied",
                "default_admin_password_denied", "limited_user_denied", "native_http_tunnel",
                "tunnel_created_ssh_marker", "session_protocol_recording"],
                "connection_id": cid, "tunnel_instructions": tunnel.count,
                "marker": "/tmp/" + marker, "recording": evidence}
    finally:
        try:
            if tunnel:
                tunnel.close()
        finally:
            for http, token in reversed(tokens):
                # Invalidate only the authentication sessions created by this test.
                http.request("DELETE", "api/tokens/" + urllib.parse.quote(token, safe=""))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--static", action="store_true", help="offline configuration and helper checks; never a live success")
    mode.add_argument("--live", action="store_true", help="real provisioned Docker stack and authenticated native HTTP tunnel (180s bound)")
    args = parser.parse_args()
    global DEADLINE
    DEADLINE = time.monotonic() + (180 if args.live else 120)
    selected = "live" if args.live else "static"

    def timeout(_signum, _frame):
        raise Failure("overall acceptance deadline exceeded")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(180 if args.live else 120)
    try:
        result = live_checks() if args.live else static_checks()
    except Exception as exc:
        # Never stringify arbitrary exceptions: URLs, env and response bodies may be secret.
        message = str(exc) if isinstance(exc, Failure) else "acceptance operation failed: " + type(exc).__name__
        print(json.dumps({"mode": selected, "passed": False, "error": message}, sort_keys=True))
        return 1
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
