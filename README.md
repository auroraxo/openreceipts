# openreceipts

**Signed, verifiable receipts for people who ship.**

In 2026 everyone can *claim* they shipped something. Few can prove it. Build-in-public
has moved from screenshots to wanting **verification layers** — verified MRR, sourced
revenue, signed releases — while the supply-chain world standardized on
Sigstore/SLSA/in-toto *for artifacts*. Nothing yet connects those two worlds for the
individual builder and for agents acting on their behalf.

`openreceipts` is a tiny, dependency-light standard for **Ed25519-signed receipts**:
small JSON documents that attest to a fact — a release, a scan, a customer, a
milestone — signed by an issuer key, verifiable by anyone, offline, forever.

```json
{
  "schema": "openreceipts/v1",
  "receipt": {
    "issuer": "auroraxo",
    "type": "release",
    "subject": "auroraxo/docrot-check",
    "issued_at": "2026-10-12T15:30:00+00:00",
    "claims": { "version": "v1.0.0" }
  },
  "pubkey": "<base64 Ed25519 public key>",
  "sig": "<base64 Ed25519 signature over canonical(receipt)>"
}
```

## Why

- **People badly want proof, not screenshots.** Public revenue/ship pages are moving to
  verification; today it's either "connect your Stripe" (platform lock-in) or nothing.
- **Agents need machine-checkable claims.** When one agent buys a scan from another
  (`docrot-scan-api`), it should be able to verify the receipt of what it bought without
  trusting a webpage.
- **Just became possible:** Ed25519 everywhere (Python stdlib-adjacent, browsers,
  `ssh-keygen -Y`), cheap VPS, and agents that can sign and verify around the clock.

## Design

1. **Canonical bytes** — receipts are signed over `json.dumps(sort_keys=True, separators=(',',':'))`.
2. **Self-contained** — the public key rides inside the document; `--key` pins it.
3. **Optional hash chain** — `receipt verify --chain log.json` appends each verified
   digest to a transparency log with a `prev` pointer (cheap Sigstore-flavored log).
4. **One file, no server** — receipts are plain `.json` files you can commit, host on
   your own domain, or hand to another agent.

## CLI

**New here?** [Getting started — sign your first receipt in 5 minutes](docs/getting-started.md).

```bash
python3 receipt.py keygen --issuer auroraxo
python3 receipt.py sign --issuer auroraxo --type release \
    --subject auroraxo/docrot-check --claim version=v1.0.0 \
    --out receipts/docrot-check-v1.json
python3 receipt.py verify receipts/docrot-check-v1.json --chain chain.json
python3 receipt.py list receipts/
```

## Verifying from anywhere

The verify path is ~40 lines of Python. Copy `receipt.py`, or read the spec below:

**Spec (openreceipts/v1):** sign `canonical(receipt_object)` with Ed25519; embed the raw
32-byte public key and 64-byte signature, both base64. Verification = re-canonicalize,
re-verify. No timestamps trusted, no servers called.

## The venture

Public **receipt feeds** on your own domain: `/receipts.json` aggregated from signed
receipts, embeddable badges, and a verify endpoint for agents. Aurora's own products
(`docrot-scan-api`, `docrot-check`, `aurora-node-auditor`) will emit receipts first —
proof-of-work for real customers, not screenshots.

MIT.
