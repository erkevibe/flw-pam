#!/usr/bin/env python3
"""Explicit operator TLS-only pin installation; never sends Windows credentials."""
import hashlib
import json
import socket
import ssl
import sys

sys.dont_write_bytecode = True
try:
    from . import pam_rdp as pam, bootstrap
except ImportError:
    import pam_rdp as pam
    import bootstrap


def receive(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise pam.FixtureError("TLS discovery failed; details withheld.")
        data += chunk
    return data


def observe_certificate(target):
    # Existing experiment's X.224 negotiation; TLS discovery only, no CredSSP.
    with socket.create_connection((target["hostname"], target["port"]), timeout=10) as raw:
        raw.sendall(bytes.fromhex("030000130ee000000000000100080003000000"))
        header = receive(raw, 4)
        size = int.from_bytes(header[2:], "big")
        if header[:2] != b"\x03\x00" or not 12 <= size <= 4096:
            raise pam.FixtureError("TLS discovery failed; details withheld.")
        reply = receive(raw, size - 4)[-8:]
        if reply[0] != 2 or int.from_bytes(reply[4:], "little") not in (1, 2, 8):
            raise pam.FixtureError("TLS discovery failed; details withheld.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Discovery; exact stored pin checked before installation.
        with context.wrap_socket(raw, server_hostname=target["hostname"]) as tls:
            return tls.getpeercert(binary_form=True)


def install(local=pam.LOCAL, *, accept_first_observed_lab_pin=False):
    if not accept_first_observed_lab_pin:
        raise pam.FixtureError("Explicit first-observed lab pin acknowledgement required.")
    with pam.local_lock(local) as local:
        target = pam.windows_target(local, require_store=False)
        if target is None:
            raise pam.FixtureError("Private Windows configuration required.")
        der = observe_certificate(target)
        fingerprint = hashlib.sha256(der).hexdigest()
        if "sha256:" + fingerprint != target["cert_fingerprint"].lower():
            raise pam.FixtureError("Observed certificate differs; trust and configuration preserved.")
        trust = bootstrap.prepare_trust_layout(local)
        # Store contains public certificate/endpoint metadata but remains private.
        digest = ":".join(fingerprint[i:i + 2] for i in range(0, 64, 2))
        entry = f"{target['hostname']} {target['port']} {digest} bGFiLXBpbg== bGFiLXBpbg==\n"
        pam.atomic_write(trust / "certificate.pem", ssl.DER_cert_to_PEM_cert(der))
        pam.atomic_write(trust / "known_hosts2", entry)
        return {"trust_installed": True, "stored_pin_matched": True,
                "credentials_transmitted": False, "independent_identity_verified": False}


def main(argv=None):
    parser = pam.SafeArgumentParser(description=__doc__)
    parser.add_argument("--accept-first-observed-lab-pin", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(install(accept_first_observed_lab_pin=args.accept_first_observed_lab_pin)))
        return 0
    except Exception:
        print(json.dumps({"trust_installed": False, "error": "Trust initialization failed; details withheld"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
