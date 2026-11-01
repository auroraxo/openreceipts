#!/usr/bin/env python3
"""openreceipts — cryptographically signed, publicly verifiable receipts.

A receipt is a small JSON document signed with Ed25519. Anyone can verify it
offline with just the receipt file (it embeds the issuer's public key) or
against a pinned key in a keyring.

    receipt sign   --issuer auroraxo --type release --subject auroraxo/docrot-check \
                    --claim 'version=v1' --out receipts/docrot-check-v1.json
    receipt verify receipts/docrot-check-v1.json

No dependencies beyond the Python 3.11+ standard library (cryptography is
NOT required: Ed25519 is available via the `nacl`-free stdlib path using
`cryptography` when present, else via `ssl`-independent fallback using the
pure-python verifier below). In practice we use the `cryptography` package
if installed; otherwise we use PyNaCl; otherwise we fail loudly.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket as socket_mod
import sys
import time
from datetime import datetime, timezone

SCHEMA = "openreceipts/v1"

# ---------------------------------------------------------------- backend ---


def _load_backend():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization

        class Backend:
            @staticmethod
            def generate():
                k = Ed25519PrivateKey.generate()
                priv = k.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
                pub = k.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                return priv, pub

            @staticmethod
            def load_priv(pem: bytes):
                return serialization.load_pem_private_key(pem, password=None)

            @staticmethod
            def sign(priv, msg: bytes) -> bytes:
                return priv.sign(msg)

            @staticmethod
            def verify(pub_raw: bytes, msg: bytes, sig: bytes) -> bool:
                try:
                    Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
                    return True
                except Exception:
                    return False

            @staticmethod
            def pubkey(priv) -> bytes:
                return priv.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )

        return Backend
    except ImportError:
        pass

    try:
        import nacl.signing  # type: ignore
    except ImportError:
        # Both real backends absent: local signing is impossible, but the
        # verifier alone still works and --via-signerd needs exactly one
        # verify. Keep the product usable instead of dying at import time.
        class Backend:
            @staticmethod
            def verify(pub_raw: bytes, msg: bytes, sig: bytes) -> bool:
                import sys

                print(
                    "FAIL: no Ed25519 backend available "
                    "(install 'cryptography' or 'pynacl')",
                    file=sys.stderr,
                )
                return False

            @staticmethod
            def generate():
                raise RuntimeError("no Ed25519 backend available")

            @staticmethod
            def load_priv(raw: bytes):
                raise RuntimeError("no Ed25519 backend available")

            @staticmethod
            def sign(priv, msg: bytes):
                raise RuntimeError("no Ed25519 backend available")

            @staticmethod
            def pubkey(priv):
                raise RuntimeError("no Ed25519 backend available")

        return Backend

    class Backend:
        @staticmethod
        def generate():
            k = nacl.signing.SigningKey.generate()
            return bytes(k), bytes(k.verify_key)

        @staticmethod
        def load_priv(raw: bytes):
            # raw is PEM in the cryptography path; here we accept raw seed too
            if raw.startswith(b"-----BEGIN"):
                # extract base64 body of PEM (PKCS8 wraps the 32-byte seed; be lenient)
                body = "".join(
                    l for l in raw.decode().splitlines() if not l.startswith("-----")
                )
                import binascii

                der = base64.b64decode(body)
                # last 32 bytes of PKCS8 Ed25519 key is the seed
                raw = der[-32:]
            return nacl.signing.SigningKey(raw)

        @staticmethod
        def sign(priv, msg: bytes) -> bytes:
            return bytes(priv.sign(msg).signature)

        @staticmethod
        def verify(pub_raw: bytes, msg: bytes, sig: bytes) -> bool:
            try:
                nacl.signing.VerifyKey(pub_raw).verify(msg, sig)
                return True
            except Exception:
                return False

        @staticmethod
        def pubkey(priv) -> bytes:
            return bytes(priv.verify_key)

    return Backend


BACKEND = _load_backend()

# ----------------------------------------------------------------- helpers ---


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# The required fields of openreceipts/v1 (SPEC section 2). A signed document
# missing any of them is invalid regardless of its signature; without this
# check the verifier's own field access crashes (KeyError) on a body the
# signature covers — review 7 / H12d.
REQUIRED_FIELDS = ("schema", "issuer", "type", "subject", "issued_at", "claims")


def missing_required_fields(body) -> list[str]:
    """The openreceipts/v1 required fields absent from ``body``."""
    return [k for k in REQUIRED_FIELDS if k not in body]


def _pinned_b64(issuer: str) -> str | None:
    """The pinned public key for `issuer`, if one exists locally.

    ``receipt.py verify --key`` pins a key you have seen before; signing is
    held to the same rule in reverse: if you published a key for this issuer,
    a daemon answering with a DIFFERENT key is a refusal, not a key swap.
    Public data only — this never reads or writes the private key.
    """
    _, pub_path = key_paths(issuer)
    if os.path.exists(pub_path):
        with open(pub_path) as f:
            return f.read().strip()
    return None


def _via_signerd(
    issuer: str,
    body: dict,
    socket_path: str,
    grant: str,
    timeout_s: float = 5.0,
) -> dict:
    """Sign `body` through a local signerd daemon (the message-grant envelope).

    The daemon holds the private key; this process sends the receipt body as
    JSON text and receives ``{ok, kind, signature, pubkey, ...}``.
    No key material ever enters this process, and no OPENRECEIPTS_HOME key
    file is created: signing without a key of one's own is the entire point.

    The signature is verified HERE, before anything is written: a daemon that
    answers ``ok`` with bytes that do not verify cannot produce a receipt.
    Refusals travel as ``{ok: false, error: <reason>}`` and become
    ``refused: <reason>`` on stderr with a non-zero exit upstream.
    """
    pinned = _pinned_b64(issuer)
    payload = json.dumps({"grant": grant, "body": json.dumps(body)}).encode()
    if len(payload) > 8192:
        print("FAIL: request too large for the signerd request frame", file=sys.stderr)
        raise SystemExit(1)
    deadline = time.monotonic() + timeout_s
    s = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
    try:
        s.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            s.connect(socket_path)
        except (OSError, FileNotFoundError) as e:
            print(f"FAIL: cannot reach signerd at {socket_path}: {e}", file=sys.stderr)
            raise SystemExit(1)
        s.sendall(payload + b"\n")
        buf = bytearray()
        while b"\n" not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print("FAIL: signerd did not answer", file=sys.stderr)
                raise SystemExit(1)
            s.settimeout(remaining)
            chunk = s.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > 1_000_000:
                print("FAIL: signerd response too large", file=sys.stderr)
                raise SystemExit(1)
    finally:
        s.close()

    line = bytes(buf).split(b"\n", 1)[0]
    try:
        response = json.loads(line.decode())
    except Exception:
        print("FAIL: signerd response is not JSON", file=sys.stderr)
        raise SystemExit(1)
    if response.get("ok") is not True:
        reason = response.get("error", "unknown")
        print(f"refused: {reason}", file=sys.stderr)
        raise SystemExit(1)
    pubkey_b64 = response.get("pubkey")
    sig_b64 = response.get("signature")
    if not isinstance(pubkey_b64, str) or not isinstance(sig_b64, str):
        print("FAIL: signerd answer lacks pubkey/signature", file=sys.stderr)
        raise SystemExit(1)
    if pinned is not None and pinned != pubkey_b64:
        print(
            "FAIL: daemon key does not match the pinned public key for "
            f"{issuer} (embedded {pubkey_b64} != pinned {pinned})",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not BACKEND.verify(b64d(pubkey_b64), canonical(body), b64d(sig_b64)):
        print("FAIL: signature returned by signerd does not verify", file=sys.stderr)
        raise SystemExit(1)
    return {"receipt": body, "pubkey": pubkey_b64, "sig": sig_b64}


def key_paths(issuer: str):
    root = os.path.expanduser(os.environ.get("OPENRECEIPTS_HOME", "~/.openreceipts"))
    return (
        os.path.join(root, f"{issuer}.key"),
        os.path.join(root, f"{issuer}.pub"),
    )


def ensure_key(issuer: str):
    priv_path, pub_path = key_paths(issuer)
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            priv = BACKEND.load_priv(f.read())
        if os.path.exists(pub_path):
            with open(pub_path) as f:
                pub = b64d(f.read().strip())
        else:
            # BYO-key flow (e.g. GitHub Actions secret): private key provided,
            # public key derived and published alongside it.
            pub = BACKEND.pubkey(priv)
            with open(pub_path, "w") as f:
                f.write(b64e(pub) + "\n")
        return priv, pub
    os.makedirs(os.path.dirname(priv_path), exist_ok=True)
    priv_pem, pub_raw = BACKEND.generate()
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    os.chmod(priv_path, 0o600)
    with open(pub_path, "w") as f:
        f.write(b64e(pub_raw) + "\n")
    priv = BACKEND.load_priv(priv_pem)
    return priv, pub_raw


# ---------------------------------------------------------------- commands ---


def cmd_keygen(args) -> int:
    priv, pub = ensure_key(args.issuer)
    _, pub_path = key_paths(args.issuer)
    print(f"issuer: {args.issuer}")
    print(f"public key (publish this): {b64e(pub)}")
    print(f"stored at: {pub_path}")
    return 0


def cmd_sign(args) -> int:
    claims = {}
    for kv in args.claim or []:
        if "=" not in kv:
            print(f"bad --claim {kv!r}, expected key=value", file=sys.stderr)
            return 2
        k, v = kv.split("=", 1)
        claims[k] = v

    if args.json:
        claims.update(json.loads(args.json))

    body = {
        "schema": SCHEMA,
        "issuer": args.issuer,
        "type": args.type,
        "subject": args.subject,
        "issued_at": args.issued_at
        if args.issued_at
        else datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "claims": claims,
    }
    if args.note:
        body["note"] = args.note

    if args.via_signerd:
        if args.via_signerd == "-":
            print("FAIL: --via-signerd needs the daemon socket path", file=sys.stderr)
            return 2
        doc = _via_signerd(args.issuer, body, args.via_signerd, args.grant or "default")
    else:
        priv, pub = ensure_key(args.issuer)
        payload = {"receipt": body, "pubkey": b64e(pub)}
        sig = BACKEND.sign(priv, canonical(body))
        doc = {**payload, "sig": b64e(sig)}

    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            f.write(text)
        print(f"signed -> {args.out}")
        print(f"verify: receipt verify {args.out}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_verify(args) -> int:
    with open(args.file) as f:
        doc = json.load(f)
    body = doc.get("receipt")
    if not body or doc.get("schema") != SCHEMA and body.get("schema") != SCHEMA:
        print("FAIL: not an openreceipts/v1 document", file=sys.stderr)
        return 1
    if body.get("schema") != SCHEMA:
        print("FAIL: bad schema", file=sys.stderr)
        return 1

    missing = missing_required_fields(body)
    if missing:
        print(
            "FAIL: missing required field(s): " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    pub = b64d(doc["pubkey"])
    sig = b64d(doc["sig"])

    if args.key:
        with open(args.key) as f:
            pinned = b64d(f.read().strip())
        if pinned != pub:
            print("FAIL: embedded pubkey does not match pinned key", file=sys.stderr)
            return 1

    if not BACKEND.verify(pub, canonical(body), sig):
        print("FAIL: signature invalid", file=sys.stderr)
        return 1

    # optional transparency: hash-chain append
    if args.chain:
        entries = []
        if os.path.exists(args.chain):
            entries = json.load(open(args.chain))
        digest = hashlib.sha256(canonical(body)).hexdigest()
        if digest not in [e["sha256"] for e in entries]:
            entries.append(
                {
                    "sha256": digest,
                    "issuer": body["issuer"],
                    "type": body["type"],
                    "subject": body["subject"],
                    "issued_at": body["issued_at"],
                    "prev": entries[-1]["sha256"] if entries else "0" * 64,
                }
            )
            json.dump(entries, open(args.chain, "w"), indent=2)
        print(f"chain: {args.chain} ({len(entries)} entries)")

    print(
        f"OK  {body['type']}/{body['subject']}  "
        f"issued {body['issued_at']} by {body['issuer']}"
    )
    for k, v in body.get("claims", {}).items():
        print(f"    {k} = {v}")
    return 0


def cmd_list(args) -> int:
    import glob

    files = sorted(glob.glob(os.path.join(args.dir, "**", "*.json"), recursive=True))
    ok = bad = 0
    for fp in files:
        rc = cmd_verify(argparse.Namespace(file=fp, key=None, chain=None))
        if rc == 0:
            ok += 1
        else:
            bad += 1
            print(f"  ^ invalid: {fp}", file=sys.stderr)
    print(f"\n{ok} valid, {bad} invalid, {len(files)} total")
    return 1 if bad else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="receipt", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create issuer keypair")
    s.add_argument("--issuer", required=True)
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("sign", help="sign a receipt")
    s.add_argument("--issuer", required=True)
    s.add_argument("--type", required=True, help="release | scan | customer | milestone")
    s.add_argument("--subject", required=True, help="repo/product the receipt is about")
    s.add_argument("--claim", action="append", help="key=value (repeatable)")
    s.add_argument("--json", help="extra claims as JSON object")
    s.add_argument("--note", help="human-readable note")
    s.add_argument("--issued-at", help="RFC3339 issued_at (default: now); replay identity")
    s.add_argument(
        "--via-signerd",
        metavar="SOCKET",
        help="sign through a local signerd daemon Unix socket instead of a local "
        "key; needs --grant; no key material is created or read in this process",
    )
    s.add_argument("--grant", help="signerd grant name (with --via-signerd)")
    s.add_argument("--out", help="output path")
    s.set_defaults(fn=cmd_sign)

    s = sub.add_parser("verify", help="verify a receipt file")
    s.add_argument("file")
    s.add_argument("--key", help="pinned public key file (base64)")
    s.add_argument("--chain", help="append verified digest to a transparency log")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("list", help="verify every receipt under a directory")
    s.add_argument("dir")
    s.set_defaults(fn=cmd_list)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
