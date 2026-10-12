# Getting started — sign your first receipt in 5 minutes

A receipt is a small JSON document, signed with Ed25519, that proves a fact about
something you shipped: a release, a scan, a customer, a milestone. Anyone can verify
it **offline** — the public key rides inside the document, and the spec is ~40 lines.

This page is a pure copy-paste path. Nothing here phones home.

**You need:** `git`, Python ≥ 3.11, Node ≥ 18 (optional — only for the Node verifier),
and one pip package:

```bash
git clone https://github.com/auroraxo/openreceipts.git
cd openreceipts
pip install cryptography     # only needed for the Python signer/verifier
```

## 1. Make a keypair

```bash
python3 receipt.py keygen --issuer alice
```

Output:

```
issuer: alice
public key (publish this): <base64 Ed25519 public key>
stored at: ~/.openreceipts/alice.pub
```

Your private key is stored at `~/.openreceipts/alice.key` (mode 600). Keep it secret;
publish the `.pub` file — inside your repo, your website, your README, wherever your
receipts live. Set `OPENRECEIPTS_HOME` to relocate both files.

## 2. Sign your first receipt

```bash
python3 receipt.py sign --issuer alice --type release \
    --subject alice/your-repo --claim version=v1.0.0 \
    --out receipts/first.json
```

That's the whole document — `receipt` (the fact), `pubkey` (who says so), `sig`
(Ed25519 signature over the canonical bytes of `receipt`):

```json
{
  "receipt": {
    "schema": "openreceipts/v1",
    "issuer": "alice",
    "type": "release",
    "subject": "alice/your-repo",
    "issued_at": "2026-10-12T21:10:00+00:00",
    "claims": { "version": "v1.0.0" }
  },
  "pubkey": "<base64>",
  "sig": "<base64>"
}
```

## 3. Verify it (Python)

Against the embedded key:

```bash
python3 receipt.py verify receipts/first.json
```

Against **your pinned key** (this is what a third party does — they don't trust the
key inside the file, they trust the key you published):

```bash
python3 receipt.py verify receipts/first.json --key ~/.openreceipts/alice.pub
```

Both print `OK  release/alice/your-repo  issued <timestamp> by alice`.

## 4. Verify the same receipt from Node (zero dependencies)

`verify.mjs` uses only `node:crypto` — no npm install:

```bash
node verify.mjs receipts/first.json
node verify.mjs --key ~/.openreceipts/alice.pub receipts/first.json
```

Same bytes, same result. The canonical form is byte-identical across the two
implementations (see `docs/SPEC.md`).

## 5. Verify someone else's receipt against their pinned key

This is the actual point of the standard: you don't need *their* tooling, just the
receipt file and their published key.

```bash
python3 receipt.py verify receipts/docrot-check-v1.json --key keys/auroraxo.pub
node verify.mjs --key keys/auroraxo.pub receipts/docrot-check-v1.json
```

`keys/auroraxo.pub` is the pinned key for the `auroraxo` issuer
(`z74vce0VgGTpPP7Nu/G+O9IVDgcKg/lceC/2GAvwzi8=`). Every receipt in this repo's
`receipts/` directory verifies against it, and all of them are aggregated in the
public feed at <https://auroraxo.github.io/openreceipts/>.

To check a whole directory at once:

```bash
python3 receipt.py list receipts/
node verify.mjs --key keys/auroraxo.pub --chain chain.json receipts/
```

## 6. (10 seconds) Watch tampering fail

```bash
sed 's/v1.0.0/v9.9.9/' receipts/first.json > /tmp/tampered.json
python3 receipt.py verify /tmp/tampered.json      # FAIL: signature invalid
```

Changing one character of a claim invalidates the signature. There is no server to
ask, no timestamp to trust — just Ed25519 over canonical JSON.

## What just happened

1. **Canonical bytes** — the signature covers
   `json.dumps(receipt, sort_keys=True, separators=(',',':'))`, so key order and
   whitespace in the file don't matter.
2. **Self-contained** — the public key rides inside the receipt; `--key` *pins* it
   so a malicious file can't swap in its own key.
3. **Offline forever** — verification needs no network, no registry, no timestamp
   authority. A receipt from 2026 verifies the same way in 2036.

Full wire format: [`docs/SPEC.md`](SPEC.md).

## Publish your receipts

Receipts are plain `.json` files — commit them to your repo, host them on your own
domain, or aggregate them into a feed (see `feed.py`). Your public key is the
identity; wherever your `.pub` file is readable, your receipts are verifiable.

## CI runs this exact path

`.github/workflows/verify.yml` runs `scripts/getting-started-smoke.sh` on every
push: keygen → sign → verify (Python + Node, embedded + pinned key) → tamper test.
If the copy-paste path above ever breaks, CI goes red.
