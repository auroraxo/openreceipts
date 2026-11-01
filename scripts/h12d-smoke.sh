#!/usr/bin/env bash
# H12d smoke: two verifier/feed defects found by signerd review #9, with the
# checks that were RED on 702409a (main before this branch):
#   1. a signed-but-incomplete document must be REFUSED by BOTH verifiers
#      (before: python died with KeyError: 'issued_at', node passed it
#      printing "issued undefined" — two verdicts for one artifact),
#   2. the feed must order by the MOMENT issued_at claims, not by the raw
#      string (before: "2027-01-01T00:00:00+05:30" — an earlier moment,
#      18:30Z on 2026-12-31 — sorted above "2026-12-31T23:00:00Z").
# CI runs this on every push.
set -euo pipefail
cd "$(dirname "$0")/.."

export OPENRECEIPTS_HOME="$(mktemp -d)"
TMP="$(mktemp -d)"
trap 'rm -rf "$OPENRECEIPTS_HOME" "$TMP"' EXIT

echo "== 1. signed body without issued_at: BOTH verifiers refuse cleanly =="
python3 - "$TMP" <<'PY'
import json, os, sys
import receipt as r

tmp = sys.argv[1]
priv_pem, pub = r.BACKEND.generate()
priv = r.BACKEND.load_priv(priv_pem)
body = {"schema": r.SCHEMA, "issuer": "h12d", "type": "release",
        "subject": "h12d/no-issued-at", "claims": {}}
doc = {"receipt": body, "pubkey": r.b64e(pub),
       "sig": r.b64e(r.BACKEND.sign(priv, r.canonical(body)))}
with open(os.path.join(tmp, "no-issued.json"), "w") as f:
    json.dump(doc, f)
print("signed incomplete document:", os.path.join(tmp, "no-issued.json"))
PY

if out=$(python3 receipt.py verify "$TMP/no-issued.json" 2>&1); then
    echo "FAIL: python verifier accepted a document without issued_at" >&2
    exit 1
fi
echo "$out" | grep -q "missing required field" || {
    echo "FAIL: python refusal is not the required-field message (traceback?)" >&2
    echo "$out" >&2
    exit 1
}
echo "python: refused -> $(echo "$out" | head -1)"

if out=$(node verify.mjs "$TMP/no-issued.json" 2>&1); then
    echo "FAIL: node verifier accepted a document without issued_at" >&2
    exit 1
fi
echo "$out" | grep -q "missing required field" || {
    echo "FAIL: node refusal is not the required-field message" >&2
    echo "$out" >&2
    exit 1
}
echo "node:   refused -> $(echo "$out" | head -1)"

echo "== 2. feed orders by moment, not by string spelling =="
python3 receipt.py keygen --issuer h12d >/dev/null
# a: string sorts FIRST ("2027-...") but claims the EARLIER moment
#    (2027-01-01T00:00:00+05:30 == 2026-12-31T18:30:00Z)
# b: claims 4.5h LATER (2026-12-31T23:00:00Z)
python3 receipt.py sign --issuer h12d --type release --subject h12d/a \
    --issued-at "2027-01-01T00:00:00+05:30" --out "$TMP/feed/a.json" >/dev/null
python3 receipt.py sign --issuer h12d --type release --subject h12d/b \
    --issued-at "2026-12-31T23:00:00Z" --out "$TMP/feed/b.json" >/dev/null
python3 feed.py "$TMP/feed" --key "$OPENRECEIPTS_HOME/h12d.pub" --out "$TMP/feed.json"
first=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['entries'][0]['receipt']['subject'])" "$TMP/feed.json")
if [ "$first" != "h12d/b" ]; then
    echo "FAIL: feed's newest-first entry is '$first', expected 'h12d/b' (later moment)" >&2
    exit 1
fi
echo "feed: newest-by-moment first -> $first"

echo "h12d smoke: all checks OK"
