# openreceipts/v1 — Specification

**Status:** Stable. The seed commit is a working implementation; this document pins the wire format that both the Python and Node verifiers check against.

## 1. Document shape

Every receipt is a single JSON object with exactly three top-level keys, in any order:

```json
{
  "receipt": { ... },
  "pubkey":  "<base64 raw Ed25519 public key, 32 bytes>",
  "sig":     "<base64 Ed25519 signature, 64 bytes>"
}
```

`receipt.schema` MUST be the literal string `"openreceipts/v1"`. Any other value is rejected.

## 2. The `receipt` object

Required fields:

| field | type | description |
| --- | --- | --- |
| `schema` | string | Literal `"openreceipts/v1"`. |
| `issuer` | string | Public identifier of the signer (e.g. `"auroraxo"`, `"acme-corp"`). |
| `type` | string | One of: `release`, `scan`, `contribution`, `milestone`, `customer`, or any other snake_case label the issuer wishes to use. |
| `subject` | string | What the receipt is about. Convention: `<owner>/<repo>`, `<product>`, or `<domain>`. |
| `issued_at` | string | ISO 8601 timestamp with timezone. The spec does **not** require this to be accurate; verifiers do not check the clock. |
| `claims` | object | String → string map of asserted facts. Values are strings, not numbers, booleans or nested objects, to keep the canonicalisation trivial. |

Optional:

| field | type | description |
| --- | --- | --- |
| `note` | string | Human-readable comment. Not signed-secure against deletion by a malicious issuer (it is part of the signed body, so the verifier sees whatever the file contains, but a fresh signer could omit it). |

The verifier signs the **canonical bytes of `receipt`** — never the `pubkey`, the `sig`, or anything else.

## 3. Canonical bytes

A receipt is signed over `canonical(receipt_object)`, defined as:

```
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

i.e. the UTF-8 bytes of a JSON string with:

- All object keys sorted lexicographically (Python's `sorted` on the keys, which sorts by Unicode code point).
- No whitespace between separators.
- `ensure_ascii=True` (so any non-ASCII code point becomes a `\uXXXX` escape; astral code points are emitted as a `\uXXXX\uXXXX` surrogate pair, lowercase hex).

Numbers, booleans, and `null` in the `claims` map are **discouraged**: a string-only map keeps the canonical form identical across language implementations. If you need a structured claim, encode it as a string (e.g. `"v1.0.0"`, `"42"`).

## 4. Signing

Ed25519 over the canonical bytes. The `pubkey` and `sig` fields embed the **raw** key and signature, not the DER/PEM/SPKI forms:

- Public key: 32 bytes, base64.
- Signature: 64 bytes, base64.

Verification re-derives `canonical(receipt)`, then `Ed25519.verify(embedded_pubkey, canonical_bytes, embedded_sig)`. Any failure — wrong size, base64 decode error, verify false — is a hard FAIL.

## 5. Pinned-key verification

Optionally pass a pinned public key file (45-char base64 string, the same 32 raw bytes). If the embedded `pubkey` does not match the pinned key byte-for-byte, verification fails. This is the only way to bind a receipt to a known issuer key when you are not the original signer.

## 6. Transparency log (optional)

A verifier can append a verified receipt's SHA-256 digest (of the canonical bytes) to a JSON array, with a `prev` pointer forming a hash chain:

```json
[
  { "sha256": "0...0", "issuer": "auroraxo", "type": "milestone", "subject": "...", "issued_at": "...", "prev": "0...0" },
  { "sha256": "abc...", "issuer": "auroraxo", "type": "release",  "subject": "...", "issued_at": "...", "prev": "0...0" }
]
```

The log is **append-only and prev-linked**. A verifier walking the log checks that each entry's `prev` equals the previous entry's `sha256`, and that the first entry's `prev` is 64 zeros. The log itself is not signed; trust comes from external anchoring (commit history, git tags, mirrored on a domain you control, etc.).

## 7. What the verifier does NOT do

- No clock check. `issued_at` is whatever the issuer wrote.
- No revocation list. If your key is stolen, rotate by issuing a `revoke` receipt and publishing a new key.
- No server call. Everything is local; the only thing the verifier trusts is the receipt file and (optionally) the pinned-key file.
- No JSON schema validator for `claims`. The map is opaque to the verifier; the issuer defines what is meaningful.

## 8. Worked example (Python signer)

```python
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

priv = Ed25519PrivateKey.generate()
pub = priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)

body = {
    "schema": "openreceipts/v1",
    "issuer": "auroraxo",
    "type": "release",
    "subject": "auroraxo/docrot-check",
    "issued_at": "2026-10-12T15:30:00+00:00",
    "claims": {"version": "v1.0.0"},
}
sig = priv.sign(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())

doc = {"receipt": body, "pubkey": base64.b64encode(pub).decode(),
       "sig": base64.b64encode(sig).decode()}
print(json.dumps(doc, indent=2))
```

## 9. Worked example (Node verifier)

```js
import { createPublicKey, verify as edVerify, createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const doc = JSON.parse(readFileSync(process.argv[2], "utf8"));
const body = doc.receipt;
const bytes = Buffer.from(JSON.stringify(body, Object.keys(body).sort()), "utf8");
// (real implementation uses the same canonical function as the spec)
const key = createPublicKey({
  key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(doc.pubkey, "base64").toString("base64url") },
  format: "jwk",
});
const ok = edVerify(null, bytes, key, Buffer.from(doc.sig, "base64"));
console.log(ok ? "OK" : "FAIL");
```

See `verify.mjs` in this repo for the complete, runnable version.

## 10. Versioning

- The wire format is versioned by `receipt.schema`. A change to the canonicalisation rules, the signature scheme, or any required field bumps the major version.
- Adding optional fields is non-breaking under v1.
- The reference implementations in this repo are versioned independently from the spec.
