#!/usr/bin/env python3
"""kivi Python SDK conformance runner (G3.0 scenarios S1–S10 + the parity
scenarios S12–S14: identity/login, semantic similar, head + as-of).

    conformance_runner.py <clean> <tamper_record> <tamper_seal> <token> <auth>

auth serves a seeded kivi user conf-writer/conf-pass-123 (writer).
Exits 0 and prints `CONFORMANCE PASS n/n` only when every scenario holds.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dataclasses import dataclass

from kivi import (KiviClient, TracedAnswer, NotFound, Unauthenticated,
                  PreconditionFailed, VerificationError, body_as)
from kivi.aio import AsyncKiviClient

PASS = 0
TOTAL = 0


def step(name):
    def deco(fn):
        def run(*a):
            global PASS, TOTAL
            TOTAL += 1
            try:
                fn(*a)
                PASS += 1
                print(f"  {name}: ok")
            except Exception as e:  # noqa: BLE001 — the exam reports, honestly
                print(f"  {name}: FAIL — {type(e).__name__}: {e}")
        return run
    return deco


BIG = 9007199254740993  # 2**53 + 1 — dies in any double conversion


@step("S1 receipt")
def s1(c):
    r = c.append("property", {"subject": "dog", "attribute": "sound", "value": "bark"})
    assert r.no == 0 and len(r.hash) == 64, r
    r2 = c.append("property", {"subject": "dog", "attribute": "sound", "value": "woof"})
    assert r2.no == 1 and r2.offset > r.offset, r2


@step("S2 int64 fidelity")
def s2(c):
    c.append("property", {"subject": "num", "attribute": "big", "value": BIG})
    a = c.table("num", "big")
    assert a.value == BIG and isinstance(a.value, int), f"int64 mangled: {a.value!r}"


@step("S3 traced answers, honest refusals")
def s3(c):
    a = c.table("dog", "sound")
    assert a.trace and isinstance(a.scope, int) and a.value == "woof", a
    try:
        c.table("ghost", "attr")
        raise AssertionError("missing cell did not raise NotFound")
    except NotFound:
        pass
    try:
        TracedAnswer(value=1, trace=(), scope=1)
        raise AssertionError("a traceless answer was constructable")
    except ValueError:
        pass


@step("S4 why")
def s4(c):
    a = c.table("num", "big")
    recs = c.why(a.trace)
    assert len(recs) == 1 and recs[0]["body"]["value"] == BIG, recs


@step("S5 verified replay (clean)")
def s5(c):
    c.seal()
    want = c.verify_ledger().records
    got = sum(1 for _ in c.replay(verify=True))
    assert got == want, f"replayed {got}, ledger holds {want}"


@step("S6 tamper trap (record)")
def s6(t):
    t.append("note", {"k": "tamper-me"})
    try:
        list(t.replay(verify=True))
        raise AssertionError("a corrupted record sailed through verification")
    except VerificationError:
        pass


@step("S7 tamper trap (seal)")
def s7(s):
    s.append("note", {"k": 1})
    s.seal()
    try:
        list(s.replay(verify=True))
        raise AssertionError("a forged seal sailed through verification")
    except VerificationError:
        pass


@step("S8 auth")
def s8(clean_addr, token):
    try:
        KiviClient(clean_addr).verify_ledger()
        raise AssertionError("tokenless call was accepted")
    except Unauthenticated:
        pass
    try:
        KiviClient(clean_addr, token="wrong").verify_ledger()
        raise AssertionError("wrong token was accepted")
    except Unauthenticated:
        pass
    assert KiviClient(clean_addr, token=token).verify_ledger().records >= 0


@step("S9 erase flow")
def s9(c):
    r = c.append_private("note", {"v": "top-secret"})
    rec = c.get_record(r.no, unseal=True)
    assert rec["body"]["v"] == "top-secret", rec
    c.erase(r.no, "conformance")
    try:
        c.erase(r.no, "again")
        raise AssertionError("second erase did not fail")
    except PreconditionFailed:
        pass
    rec2 = c.get_record(r.no, unseal=True)
    assert "top-secret" not in str(rec2) and rec2["body"].get("kivi.sealed") is True, rec2


@step("S10 async parity")
def s10(clean_addr, token):
    async def go():
        async with AsyncKiviClient(clean_addr, token=token) as ac:
            await ac.append("property",
                            {"subject": "anum", "attribute": "big", "value": BIG})
            a = await ac.table("anum", "big")
            assert a.value == BIG and isinstance(a.value, int), a
            n = 0
            async for _ in ac.replay(verify=True):
                n += 1
            assert n == (await ac.verify_ledger()).records
    asyncio.run(go())


@step("S12 identity (login + per-call bearer)")
def s12(auth_addr):
    u = KiviClient(auth_addr)
    try:
        u.login("conf-writer", "wrong-pass")
        raise AssertionError("wrong password was accepted")
    except Unauthenticated:
        pass
    sess = u.login("conf-writer", "conf-pass-123")
    assert sess.role == "writer" and sess.token, sess
    u.append("note", {"who": "conf-writer"})  # the session identity can write
    bare = KiviClient(auth_addr)
    try:
        bare.verify_ledger()
        raise AssertionError("anonymous call was accepted")
    except Unauthenticated:
        pass
    # per-call bearer: the same channel, another identity — stateless frontends
    view = bare.with_bearer(sess.token)
    assert view.verify_ledger().records >= 0
    view.close()  # closing a view must NOT cut the shared wire…
    assert bare.with_bearer(sess.token).verify_ledger().records >= 0  # …proof


@step("S13 similar (traced semantic search)")
def s13(auth_addr, token):
    u = KiviClient(auth_addr, token=token)
    r = u.append("note", {"text": "the zebra escaped the painting exhibition"})
    u.append("note", {"text": "database replication lag is boring"})
    a = u.similar("zebra exhibition painting", k=3)
    assert a.hits and a.hits[0].no == r.no, a.hits
    assert a.model and a.scope >= r.no and a.hits[0].record is not None, a


@step("S14 head + as-of (time travel)")
def s14(c):
    head_no, head_hash = c.head()
    assert head_no == c.verify_ledger().records - 1 and len(head_hash) == 64
    # record 0 was dog.sound=bark, later overwritten by woof (S1): as of
    # record 0 the ledger honestly answers the OLD value, traced to record 0
    a = c.table("dog", "sound", as_of=0)
    assert a.value == "bark" and a.scope == 0 and a.trace == (0,), a
    assert c.table("dog", "sound").value == "woof"


@step("S16 paged view reads (keyset + snapshot pinning)")
def s16(c):
    for s in ("pgA", "pgB", "pgC"):
        c.append("property", {"subject": s, "attribute": "a", "value": s})
    p1 = c.view_page("table", after_key="pg", limit=2)
    assert [e.key for e in p1.entries] == ["pgA", "pgB"], p1
    assert p1.next_key == "pgB" and len(p1.hash) == 64, p1
    # a write lands BETWEEN pages — the pinned walk must not see it
    c.append("property", {"subject": "pgD", "attribute": "a", "value": 4})
    p2 = c.view_page("table", after_key=p1.next_key, limit=10, as_of=p1.scope)
    assert [e.key for e in p2.entries] == ["pgC"] and p2.next_key == "", p2
    assert p2.hash == p1.hash and p2.scope == p1.scope, "pinned page drifted"
    # an unpinned page tells today's truth
    now = c.view_page("table", after_key="pg", limit=10)
    assert len(now.entries) == 4 and now.hash != p1.hash, now


@step("S17 Subscribe (type-filtered feed)")
def s17(c):
    c.append("sub-other", {"i": 1})
    c.append("sub-wanted", {"i": 2})
    got = list(c.subscribe(start=0, types=["sub-wanted"]))
    assert len(got) == 1 and got[0]["type"] == "sub-wanted", got


@step("S18 QuerySubject (whole-row read)")
def s18(c):
    c.append("property", {"subject": "subj-whole", "attribute": "a", "value": 1})
    c.append("property", {"subject": "subj-whole", "attribute": "b", "value": 2})
    a = c.subject("subj-whole")
    assert a.value == {"a": 1, "b": 2} and len(a.trace) == 2, a


@dataclass
class _Size:
    w: int
    h: int


@dataclass
class _Widget:
    name: str
    weight_g: int  # int64 fidelity through the typed path
    size: _Size


@step("S20 typed entity round-trip (entity in, entity out)")
def s20(c):
    r = c.append("widget", _Widget(name="cog", weight_g=BIG, size=_Size(w=3, h=4)))
    out = c.get_record_as(_Widget, r.no)
    assert out.name == "cog" and out.weight_g == BIG, out
    assert out.size == _Size(w=3, h=4), out
    # body_as works on a fetched record too
    rec = c.get_record(r.no)
    assert body_as(_Widget, rec).weight_g == BIG


@step("S21 graph traversal (traced neighbors / reachable / shortest path)")
def s21(c):
    # directed chain gN1 —owns→ gN2 —owns→ gN3 out of `relation` events
    e1 = c.append("relation", {"source": "gN1", "relation": "owns", "target": "gN2"})
    e2 = c.append("relation", {"source": "gN2", "relation": "owns", "target": "gN3"})
    # neighbors: gN1 has exactly one outgoing edge, to gN2, set by e1
    edges, _ = c.graph_neighbors("gN1")
    assert len(edges) == 1 and edges[0].target == "gN2" \
        and edges[0].relation == "owns" and edges[0].no == e1.no, edges
    # reachable: gN3 at depth 2 with traced edge path [e1, e2]
    reached, _ = c.graph_reachable("gN1", depth=3)
    gn3 = next((n for n in reached if n.node == "gN3"), None)
    assert gn3 is not None and gn3.depth == 2 \
        and list(gn3.trace) == [e1.no, e2.no], reached
    # shortest path: two hops, each naming its edge record number
    hops, found, _ = c.graph_path("gN1", "gN3")
    assert found and len(hops) == 2, (found, hops)
    assert hops[0].frm == "gN1" and hops[0].to == "gN2" and hops[0].no == e1.no
    assert hops[1].frm == "gN2" and hops[1].to == "gN3" and hops[1].no == e2.no
    # as-of e1: gN2→gN3 did not exist yet, so gN3 is unreachable
    early, _ = c.graph_reachable("gN1", depth=3, as_of=e1.no)
    assert all(n.node != "gN3" for n in early), early


def main():
    if len(sys.argv) != 6:
        print(__doc__)
        return 2
    clean_addr, tr_addr, ts_addr, token, auth_addr = sys.argv[1:6]
    print("kivi Python SDK conformance:")
    c = KiviClient(clean_addr, token=token)
    s1(c)
    s2(c)
    s3(c)
    s4(c)
    s5(c)
    s6(KiviClient(tr_addr))
    s7(KiviClient(ts_addr))
    s8(clean_addr, token)
    s9(c)
    s10(clean_addr, token)
    s12(auth_addr)
    s13(auth_addr, token)
    s14(c)
    s16(c)
    s17(c)
    s18(c)
    s20(c)
    s21(c)
    print(f"CONFORMANCE {'PASS' if PASS == TOTAL else 'FAIL'} {PASS}/{TOTAL}")
    return 0 if PASS == TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
