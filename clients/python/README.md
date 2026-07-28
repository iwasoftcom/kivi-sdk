# kivi Python SDK (G3.1)

The untrusting client: K2 ergonomics + K3 client-side verification, sync and
async. Runtime dependency: `grpcio` only (the Ed25519 verifier and canonical
hashing are self-contained, verify-only).

```python
from kivi import KiviClient

c = KiviClient("localhost:4741", token="...")          # verify=True by default
r = c.append("property", {"subject": "dog", "attribute": "sound", "value": "bark"})
a = c.table("dog", "sound")     # TracedAnswer(value, trace, scope) — trace mandatory
old = c.table("dog", "sound", as_of=41)   # time travel: the answer AT record 41
receipts = c.why(a.trace)       # the actual ledger records
for rec in c.replay():          # hash+chain+seal verified CLIENT-SIDE
    ...

sess = c.login("alice", "pw")   # kivi-user identity: role-scoped session token
c2 = c.with_bearer(sess.token)  # same channel, another identity (per-call bearer)
hits = c.similar("noise complaints", k=5)  # traced semantic search (no+score+record)
head_no, head_hash = c.head()   # cheap orientation — no audit runs
```

Async (`grpc.aio`):

```python
from kivi.aio import AsyncKiviClient

async with AsyncKiviClient("localhost:4741", token="...") as c:
    a = await c.table("dog", "sound")
    async for rec in c.replay():
        ...
```

- Honest refusals raise native exceptions (`NotFound`, `PreconditionFailed`,
  `Unauthenticated`, …) — a missing cell is never a fabricated `None`.
- A lying server or wire raises `VerificationError` (see the conformance
  tamper traps S6/S7).
- int64 values round-trip exactly — bodies travel as JSON strings (S2).
- Regenerate stubs after a proto change:
  `.venv/bin/python -m grpc_tools.protoc -I api --python_out=clients/python/kivi --grpc_python_out=clients/python/kivi api/kivi.proto`
  (then fix the relative import in `kivi_pb2_grpc.py`).

Conformance: `clients/conformance/run.sh` → `CONFORMANCE PASS 10/10`.
