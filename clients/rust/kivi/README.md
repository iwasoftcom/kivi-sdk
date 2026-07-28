# kivi (Rust SDK)

The untrusting client for [kivi](https://iwasoft.com) — an event-ledger database
in which only events are durable, representations are compiled, and no answer
comes without a trace.

```toml
[dependencies]
kivi = "1.1"
```

```rust
let c = kivi::Client::connect("localhost:4741", "token").await?;
c.append("property", &serde_json::json!({"subject":"dog","attribute":"sound","value":"woof"})).await?;
let a = c.table("dog", "sound").await?;   // { value, trace, scope } — cite the trace
```

Client-side verification is on by default: replayed records are re-hashed, the
chain and numbering are checked, and seals are Ed25519-verified — a lying server
is caught. Building requires `protoc` on PATH (the wire contract is compiled from
the bundled `proto/kivi.proto`).

MIT licensed. The kivi server and core are a separate, proprietary product.
