#!/usr/bin/env node
// openreceipts/v1 verifier — Node.js, zero dependencies (node:crypto only).
//
//   node verify.mjs [--key keys/auroraxo.pub] [--chain chain.json] <receipt.json | receipts-dir>...
//
// Verification = re-canonicalize the receipt object, re-verify the Ed25519
// signature over those bytes with the embedded (or pinned) public key.
// No timestamps are trusted and no servers are called.

import { createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const SCHEMA = "openreceipts/v1";

// Python-compatible JSON: json.dumps(obj, sort_keys=True, separators=(",", ":"))
// with ensure_ascii semantics (anything outside 0x20..0x7e becomes \uXXXX,
// astral code points as surrogate pairs, lowercase hex).
function pyEsc(str) {
  let out = "";
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp > 0x7e) {
      if (cp > 0xffff) {
        const v = cp - 0x10000;
        out += "\\u" + (0xd800 + (v >> 10)).toString(16).padStart(4, "0");
        out += "\\u" + (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, "0");
      } else {
        out += "\\u" + cp.toString(16).padStart(4, "0");
      }
    } else out += ch;
  }
  return out;
}

// Key order: Unicode code points (JS default UTF-16 order is identical for
// every key set the spec allows: ASCII identifiers).
function canonical(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    return (
      "{" +
      Object.keys(v)
        .sort()
        .map((k) => pyEsc(JSON.stringify(k)) + ":" + canonical(v[k]))
        .join(",") +
      "}"
    );
  }
  if (typeof v === "string") return pyEsc(JSON.stringify(v));
  return JSON.stringify(v); // numbers/bools are discouraged by the spec
}

function pubkeyObject(b64) {
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) throw new Error("pubkey is not 32 raw bytes");
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

function collectFiles(paths) {
  const out = [];
  for (const p of paths) {
    if (statSync(p).isDirectory()) {
      for (const name of readdirSync(p)) {
        const full = join(p, name);
        if (statSync(full).isDirectory()) out.push(...collectFiles([full]));
        else if (name.endsWith(".json")) out.push(full);
      }
    } else out.push(p);
  }
  return out;
}

function verifyOne(file, pinned) {
  const doc = JSON.parse(readFileSync(file, "utf8"));
  const body = doc.receipt;
  if (!body || body.schema !== SCHEMA)
    throw new Error("not an openreceipts/v1 document");
  if (typeof doc.pubkey !== "string" || typeof doc.sig !== "string")
    throw new Error("missing pubkey/sig");

  if (pinned && doc.pubkey !== pinned)
    throw new Error("embedded pubkey does not match pinned key");

  const sig = Buffer.from(doc.sig, "base64");
  if (sig.length !== 64) throw new Error("signature is not 64 bytes");

  const key = pubkeyObject(doc.pubkey);
  if (!edVerify(null, Buffer.from(canonical(body), "utf8"), key, sig))
    throw new Error("signature invalid");

  const digest = require_hash(body); // sha256 of canonical bytes
  return { body, digest };
}

// sha256 via node:crypto (kept separate so canonical bytes are hashed exactly
// once and the same helper is reusable by the chain check).
import { createHash } from "node:crypto";
function require_hash(body) {
  return createHash("sha256").update(canonical(body), "utf8").digest("hex");
}

function checkChain(entries) {
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const prevExpected = i === 0 ? "0".repeat(64) : entries[i - 1].sha256;
    if (e.prev !== prevExpected)
      throw new Error(`chain link broken at entry ${i}`);
    if (!/^[0-9a-f]{64}$/.test(e.sha256))
      throw new Error(`bad digest at entry ${i}`);
  }
}

// ------------------------------------------------------------------- main ---

const args = process.argv.slice(2);
let pinned = null;
let chainPath = null;
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--key") pinned = readFileSync(args[++i], "utf8").trim();
  else if (args[i] === "--chain") chainPath = args[++i];
  else files.push(args[i]);
}
if (files.length === 0) {
  console.error(
    "usage: node verify.mjs [--key pinned.pub] [--chain chain.json] <receipt.json | dir>..."
  );
  process.exit(2);
}

let chain = null;
if (chainPath) {
  chain = JSON.parse(readFileSync(chainPath, "utf8"));
  checkChain(chain);
}

let ok = 0,
  bad = 0;
for (const file of collectFiles(files)) {
  try {
    const { body, digest } = verifyOne(file, pinned);
    if (chain && !chain.some((e) => e.sha256 === digest))
      throw new Error("digest not found in chain");
    console.log(
      `OK  ${body.type}/${body.subject}  issued ${body.issued_at} by ${body.issuer}`
    );
    for (const [k, v] of Object.entries(body.claims ?? {}))
      console.log(`    ${k} = ${v}`);
    ok++;
  } catch (err) {
    console.error(`FAIL ${file}: ${err.message}`);
    bad++;
  }
}
console.log(`\n${ok} valid, ${bad} invalid, ${ok + bad} total`);
process.exit(bad ? 1 : 0);
