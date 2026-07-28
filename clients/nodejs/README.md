# kivi Node.js SDK (G3.6)

The untrusting client, TypeScript on `@grpc/grpc-js` (pure JS, no native
bindings). Compiled to plain CommonJS — runs on `node`, no `ts-node` needed.
Runtime dependencies: `@grpc/grpc-js` + `@grpc/proto-loader` only; Ed25519 and
SHA-256 verification use Node's built-in `node:crypto` (a raw Ed25519 public
key is wrapped in its fixed 12-byte SPKI DER prefix — no extra crypto package).

```ts
import { KiviClient } from "kivi";

const c = new KiviClient("localhost:4741", { token: process.env.KIVI_TOKEN });

const r = await c.append("property", { subject: "dog", attribute: "sound", value: "bark" });
const a = await c.table("dog", "sound");        // TracedAnswer{valueJson, trace, scope}
const old = await c.table("dog", "sound", 41);  // time travel: the answer AT record 41
const receipts = await c.why(a.trace);          // the actual ledger records, as JSON text

for await (const rec of c.replay(0, false)) {   // hash+chain+seal verified CLIENT-SIDE
  JSON.parse(rec);
}

const sess = await c.login("alice", "pw");      // kivi-user identity: role-scoped session token
const c2 = c.withBearer(sess.token);            // same connection, another identity (per-call bearer)
const hits = await c.similar("noise complaints", 5); // traced semantic search (no+score+record)
const head = await c.head();                    // cheap orientation — no audit runs
```

- Honest refusals throw typed errors (`NotFoundError`, `PreconditionFailedError`,
  `UnauthenticatedError`, …) — a missing cell never resolves to a fabricated
  `null`.
- A lying server or wire throws `VerificationError` (see the conformance
  tamper traps S6/S7). Verification splices the canonical wire bytes (the
  server's output is already sorted-key, compact JSON) rather than
  re-serializing — the same byte-fidelity technique the JVM and Rust SDKs use.
- **int64 fidelity (conformance S2):** `TracedAnswer.valueJson` is the RAW
  JSON text, not parsed — `JSON.parse` would silently round an integer
  beyond 2^53 to the nearest double, exactly the failure this avoids (the
  same choice the Kotlin and .NET SDKs make). Call `.value()` for the
  common case, or parse `valueJson` yourself with a BigInt-aware parser when
  an exact int64 matters.
- Loads `../../api/kivi.proto` at runtime via `@grpc/proto-loader` (no
  codegen step) — nothing hand-written follows the wire format; `findProto()`
  walks up from the compiled file so it works regardless of the output layout.

Build: `npm install && npm run build` (from `clients/nodejs/`). Conformance:
`clients/conformance/run.sh` → `CONFORMANCE PASS 14/14`.
