#!/usr/bin/env python3
"""openreceipts feed aggregator.

Walks one or more directories of receipts/*.json, verifies each one against a
pinned key, and emits a single feed JSON suitable for serving on a domain:

    receipt feed receipts/  --key keys/auroraxo.pub \
        --out feed.json \
        --meta '{"issuer":"auroraxo","name":"Aurora public receipts","url":"https://codebyaurora.com/receipts"}'

The output is sorted newest-first and includes a `verified` field per entry so
clients can render a "verified by openreceipts" badge without re-verifying.

No network. No external dependencies.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any

# Re-use the verification path from receipt.py
import receipt as r


def collect(directory: str) -> list[str]:
    return sorted(glob.glob(os.path.join(directory, "**", "*.json"), recursive=True))


def verify_all(files: list[str], pinned: str | None) -> tuple[list[dict], int]:
    ok: list[dict] = []
    bad = 0
    for fp in files:
        try:
            with open(fp) as f:
                doc = json.load(f)
            body = doc.get("receipt")
            if not body or body.get("schema") != r.SCHEMA:
                bad += 1
                continue
            pub = r.b64d(doc["pubkey"])
            sig = r.b64d(doc["sig"])
            if pinned and pub != r.b64d(pinned):
                bad += 1
                continue
            if not r.BACKEND.verify(pub, r.canonical(body), sig):
                bad += 1
                continue
            digest = __import__("hashlib").sha256(r.canonical(body)).hexdigest()
            ok.append(
                {
                    "file": os.path.relpath(fp),
                    "sha256": digest,
                    "receipt": body,
                    "pubkey": doc["pubkey"],
                    "sig": doc["sig"],
                    "verified": True,
                }
            )
        except Exception as e:
            print(f"WARN {fp}: {e}", file=sys.stderr)
            bad += 1
    ok.sort(key=lambda e: e["receipt"].get("issued_at", ""), reverse=True)
    return ok, bad


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="receipt-feed", description=__doc__)
    p.add_argument("dirs", nargs="+")
    p.add_argument("--key", help="pinned public key file (base64)")
    p.add_argument("--out", help="output path (default: stdout)")
    p.add_argument("--meta", help="JSON object with feed-level metadata")
    args = p.parse_args(argv)

    pinned = None
    if args.key:
        with open(args.key) as f:
            pinned = f.read().strip()

    files: list[str] = []
    for d in args.dirs:
        files.extend(collect(d))

    entries, bad = verify_all(files, pinned)
    if bad:
        print(f"WARN: {bad} invalid receipts skipped", file=sys.stderr)

    feed: dict[str, Any] = {
        "schema": "openreceipts-feed/v1",
        "count": len(entries),
        "entries": entries,
    }
    if args.meta:
        feed["meta"] = json.loads(args.meta)
    if pinned:
        feed["pinned_pubkey"] = pinned

    text = json.dumps(feed, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"feed -> {args.out}  ({len(entries)} entries)")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
