# Iwasoft.Kivi (.NET SDK)

The untrusting client for [kivi](https://iwasoft.com) — an event-ledger database
in which only events are durable, representations are compiled, and no answer
comes without a trace.

```csharp
using var c = new KiviClient("localhost:4741", token);
c.Append("property", new { subject = "dog", attribute = "sound", value = "woof" });
var a = c.Table("dog", "sound");   // value + trace + scope — cite the trace
```

Client-side verification is on by default: replayed records are re-hashed, the
chain and numbering checked, and seals Ed25519-verified — a lying server is
caught. MIT licensed; the kivi server and core are a separate, proprietary product.
