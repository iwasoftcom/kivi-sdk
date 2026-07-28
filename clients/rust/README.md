# kivi Rust SDK (G3.5)

The untrusting client, Rust edition: async-first (tokio), typed errors, and
client-side verification ON by default. Runtime dependencies: `tonic` +
`prost` (gRPC), `sha2` + `ed25519-dalek` (verify-only — no keys are ever
generated or used for signing here), `serde_json`.

```rust
use kivi::Client;
use serde_json::json;

let c = Client::connect("localhost:4741", std::env::var("KIVI_TOKEN").unwrap_or_default()).await?;

let r = c.append("property",
    &json!({"subject": "dog", "attribute": "sound", "value": "bark"})).await?;
let a = c.table("dog", "sound").await?;      // TracedAnswer{value, trace, scope} — trace mandatory
let old = c.table_at("dog", "sound", Some(41)).await?;  // time travel: the answer AT record 41
let receipts = c.why(&a.trace).await?;       // the actual ledger records

use tokio_stream::StreamExt;
let mut stream = c.replay(0, false).await?;  // hash+chain+seal verified CLIENT-SIDE
while let Some(rec) = stream.next().await { let rec = rec?; }

let sess = c.login("alice", "pw").await?;       // kivi-user identity: role-scoped session token
let c2 = c.with_bearer(sess.token);             // same channel, another identity (per-call bearer)
let hits = c.similar("noise complaints", 5).await?;  // traced semantic search (no+score+record)
let head = c.head().await?;                     // cheap orientation — no audit runs
```

- Honest refusals map to the typed `KiviError` enum (`NotFound`,
  `PreconditionFailed`, `Unauthenticated`, …) — a missing cell is never a
  fabricated `None`.
- A lying server or wire returns `KiviError::Verification` (see the
  conformance tamper traps S6/S7). Verification splices the canonical wire
  bytes (server output is already sorted-key, compact JSON) rather than
  re-serializing — the same byte-fidelity technique the JVM SDK uses.
- int64 values round-trip exactly: `serde_json::Value`'s default `Number`
  holds any i64/u64 precisely (no float detour) — see conformance S2.
- Codegen at build time from the single contract `../../api/kivi.proto`
  (via `tonic-build`, which needs `protoc` on `PATH` or `PROTOC` set) —
  nothing hand-written follows the wire format.

Build: `cargo build` (from `clients/rust/`). Conformance:
`clients/conformance/run.sh` → `CONFORMANCE PASS 14/14`.
