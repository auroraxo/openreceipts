#!/usr/bin/env bash
# End-to-end smoke test of docs/getting-started.md — the copy-paste path a first
# external user follows. CI runs this on every push; keep it in sync with the doc.
set -euo pipefail
cd "$(dirname "$0")/.."

export OPENRECEIPTS_HOME="$(mktemp -d)"
TMP="$(mktemp -d)"
trap 'rm -rf "$OPENRECEIPTS_HOME" "$TMP"' EXIT

echo "== 1. keypair =="
python3 receipt.py keygen --issuer smoke-test

echo "== 2. sign =="
python3 receipt.py sign --issuer smoke-test --type release \
    --subject smoke-test/hello --claim version=v1.0.0 \
    --out "$TMP/first.json"

echo "== 3. verify (Python: embedded key, then pinned own key) =="
python3 receipt.py verify "$TMP/first.json"
python3 receipt.py verify "$TMP/first.json" --key "$OPENRECEIPTS_HOME/smoke-test.pub"

echo "== 4. verify (Node: embedded key, then pinned own key) =="
node verify.mjs "$TMP/first.json"
node verify.mjs --key "$OPENRECEIPTS_HOME/smoke-test.pub" "$TMP/first.json"

echo "== 5. verify seed receipt against pinned auroraxo key (both) =="
python3 receipt.py verify receipts/docrot-check-v1.json --key keys/auroraxo.pub
node verify.mjs --key keys/auroraxo.pub receipts/docrot-check-v1.json

echo "== 6. tampering must fail (both) =="
sed 's/v1.0.0/v9.9.9/' "$TMP/first.json" > "$TMP/tampered.json"
if python3 receipt.py verify "$TMP/tampered.json" 2>/dev/null; then
    echo "FAIL: Python accepted a tampered receipt" >&2
    exit 1
fi
if node verify.mjs "$TMP/tampered.json" 2>/dev/null; then
    echo "FAIL: Node accepted a tampered receipt" >&2
    exit 1
fi

echo "getting-started smoke: all steps OK"
