// kivi Node.js SDK conformance runner (G3.0 scenarios S1-S10, the parity
// scenarios S12-S14: identity/login, semantic similar, head + as-of, and
// S16: paged view reads). Usage:
//
//   node dist/conformance/runner.js <clean> <tamper-record> <tamper-seal> <token> <auth>
//
// auth serves a seeded kivi user conf-writer/conf-pass-123 (writer) — its
// record 0 is that kivi.user event.

import {
  KiviClient,
  TracedAnswer,
  NotFoundError,
  UnauthenticatedError,
  PreconditionFailedError,
  VerificationError,
  parseJson,
  bodyAs,
} from "../src/index";

interface Size { w: number; h: number; }
interface Widget { name: string; weight_g: bigint; size: Size; }

// 2^53+1 as a BigInt LITERAL — a `number` literal of the same digits would
// already round to 2^53 the moment V8 parses this source file (verified:
// `9007199254740993` as a plain number literal prints "9007199254740992"),
// which would make S2 compare an already-corrupted value against itself and
// pass without ever exercising the real boundary. BigInt literals have no
// such limit, so this is the one true representation of the test value.
const BIG = 9007199254740993n;

let pass = 0;
let total = 0;

async function step(name: string, fn: () => Promise<void>): Promise<void> {
  total++;
  try {
    await fn();
    pass++;
    console.log(`  ${name}: ok`);
  } catch (e: any) {
    console.log(`  ${name}: FAIL — ${e?.constructor?.name ?? "Error"}: ${e?.message ?? e}`);
  }
}

/** JSON.stringify tolerant of bigint — for DIAGNOSTIC messages only (never
 * for data on the wire, where stringifyBody's exact-integer handling in
 * client.ts is what matters). */
function diag(v: unknown): string {
  return JSON.stringify(v, (_k, val) => (typeof val === "bigint" ? `${val}n` : val));
}

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length !== 5) {
    console.error("usage: runner <clean> <tamper-record> <tamper-seal> <token> <auth>");
    process.exit(2);
  }
  const [cleanAddr, trAddr, tsAddr, token, authAddr] = args;
  const c = new KiviClient(cleanAddr, { token });
  console.log("kivi Node.js SDK conformance:");

  await step("S1 receipt", async () => {
    const r = await c.append("property", { subject: "dog", attribute: "sound", value: "bark" });
    assert(r.no === 0 && r.hash.length === 64, JSON.stringify(r));
    const r2 = await c.append("property", { subject: "dog", attribute: "sound", value: "woof" });
    assert(r2.no === 1 && r2.offset > r.offset, JSON.stringify(r2));
  });

  await step("S2 int64 fidelity", async () => {
    await c.append("property", { subject: "num", attribute: "big", value: BIG });
    const a = await c.table("num", "big");
    // exact fidelity is checked on the RAW text — JSON.parse would round
    // 2^53+1 to a different double, which is exactly what this guards against
    assert(a.valueJson === String(BIG), `int64 mangled: ${a.valueJson}`);
  });

  await step("S3 traced answers, honest refusals", async () => {
    const a = await c.table("dog", "sound");
    assert(a.trace.length > 0 && a.scope > 0 && a.valueJson === '"woof"', JSON.stringify(a));
    try {
      await c.table("ghost", "attr");
      throw new Error("missing cell did not raise NotFoundError");
    } catch (e) {
      assert(e instanceof NotFoundError, `wrong error type: ${e}`);
    }
    try {
      new TracedAnswer("1", [], 1);
      throw new Error("a traceless answer was constructable");
    } catch (e) {
      assert(e instanceof VerificationError, `wrong error type: ${e}`);
    }
  });

  await step("S4 why", async () => {
    const a = await c.table("num", "big");
    const recs = await c.why(a.trace);
    assert(recs.length === 1, JSON.stringify(recs));
    assert(recs[0].includes(`"value":${BIG}`), recs[0]);
  });

  await step("S5 verified replay (clean)", async () => {
    await c.seal();
    const rep = await c.verifyLedger();
    let n = 0;
    for await (const _ of c.replay(0, false)) n++;
    assert(n === rep.records, `replayed ${n}, ledger holds ${rep.records}`);
  });

  await step("S6 tamper trap (record)", async () => {
    const t = new KiviClient(trAddr, {});
    await t.append("note", { k: "tamper-me" });
    let caught = false;
    try {
      for await (const _ of t.replay(0, false)) {
        /* drain */
      }
    } catch (e) {
      caught = e instanceof VerificationError;
    }
    t.close();
    assert(caught, "a corrupted record sailed through verification");
  });

  await step("S7 tamper trap (seal)", async () => {
    const s = new KiviClient(tsAddr, {});
    await s.append("note", { k: 1 });
    await s.seal();
    let caught = false;
    try {
      for await (const _ of s.replay(0, false)) {
        /* drain */
      }
    } catch (e) {
      caught = e instanceof VerificationError;
    }
    s.close();
    assert(caught, "a forged seal sailed through verification");
  });

  await step("S8 auth", async () => {
    const bare = new KiviClient(cleanAddr, {});
    try {
      await bare.verifyLedger();
      throw new Error("tokenless call was accepted");
    } catch (e) {
      assert(e instanceof UnauthenticatedError, `${e}`);
    }
    const wrong = new KiviClient(cleanAddr, { token: "wrong" });
    try {
      await wrong.verifyLedger();
      throw new Error("wrong token was accepted");
    } catch (e) {
      assert(e instanceof UnauthenticatedError, `${e}`);
    }
    bare.close();
    wrong.close();
    await c.verifyLedger();
  });

  await step("S9 erase flow", async () => {
    const r = await c.appendPrivate("note", { v: "top-secret" });
    const rec = JSON.parse(await c.getRecord(r.no, true));
    assert(rec.body.v === "top-secret", JSON.stringify(rec));
    await c.erase(r.no, "conformance");
    try {
      await c.erase(r.no, "again");
      throw new Error("second erase did not fail");
    } catch (e) {
      assert(e instanceof PreconditionFailedError, `${e}`);
    }
    const rec2 = JSON.parse(await c.getRecord(r.no, true));
    assert(
      !JSON.stringify(rec2).includes("top-secret") && rec2.body["kivi.sealed"] === true,
      JSON.stringify(rec2),
    );
  });

  await step("S10 concurrency parity (Node's async)", async () => {
    await Promise.all(
      Array.from({ length: 8 }, (_, g) => c.append("metric", { series: "conc", value: g })),
    );
    const rep = await c.verifyLedger();
    assert(rep.ok, JSON.stringify(rep));
  });

  await step("S12 identity (login + per-call bearer)", async () => {
    const u = new KiviClient(authAddr, {});
    try {
      await u.login("conf-writer", "wrong-pass");
      throw new Error("wrong password was accepted");
    } catch (e) {
      assert(e instanceof UnauthenticatedError, `${e}`);
    }
    const sess = await u.login("conf-writer", "conf-pass-123");
    assert(sess.role === "writer" && !!sess.token, JSON.stringify(sess));
    await u.append("note", { who: "conf-writer" });
    const bare = new KiviClient(authAddr, {});
    try {
      await bare.verifyLedger();
      throw new Error("anonymous call was accepted");
    } catch (e) {
      assert(e instanceof UnauthenticatedError, `${e}`);
    }
    const view = bare.withBearer(sess.token);
    const rep = await view.verifyLedger();
    assert(rep.records >= 0, JSON.stringify(rep));
    view.close(); // closing a view must NOT cut the shared connection…
    const rep2 = await bare.withBearer(sess.token).verifyLedger(); // …proof
    assert(rep2.records >= 0, JSON.stringify(rep2));
    u.close();
    bare.close();
  });

  await step("S13 similar (traced semantic search)", async () => {
    const u = new KiviClient(authAddr, { token });
    const r = await u.append("note", { text: "the zebra escaped the painting exhibition" });
    await u.append("note", { text: "database replication lag is boring" });
    const a = await u.similar("zebra exhibition painting", 3);
    assert(a.hits.length > 0 && a.hits[0].no === r.no, JSON.stringify(a.hits));
    assert(!!a.model && a.scope >= r.no && !!a.hits[0].recordJson, JSON.stringify(a));
    u.close();
  });

  await step("S14 head + as-of (time travel)", async () => {
    const rep = await c.verifyLedger();
    const head = await c.head();
    assert(head.no === rep.records - 1 && head.hash.length === 64, JSON.stringify(head));
    // record 0 was dog.sound=bark, overwritten later by woof (S1)
    const a = await c.table("dog", "sound", 0);
    assert(
      a.valueJson === '"bark"' && a.scope === 0 && a.trace.length === 1 && a.trace[0] === 0,
      JSON.stringify(a),
    );
    const now = await c.table("dog", "sound");
    assert(now.valueJson === '"woof"', "time travel changed the present");
  });

  await step("S16 paged view reads (keyset + snapshot pinning)", async () => {
    for (const s of ["pgA", "pgB", "pgC"]) {
      await c.append("property", { subject: s, attribute: "a", value: s });
    }
    const p1 = await c.viewPage("table", "pg", 2);
    assert(
      p1.entries.length === 2 &&
        p1.entries[0].key === "pgA" &&
        p1.entries[1].key === "pgB" &&
        p1.nextKey === "pgB" &&
        p1.hash.length === 64,
      JSON.stringify(p1),
    );
    // a write lands BETWEEN pages — the pinned walk must not see it
    await c.append("property", { subject: "pgD", attribute: "a", value: 4 });
    const p2 = await c.viewPage("table", p1.nextKey, 10, p1.scope);
    assert(
      p2.entries.length === 1 &&
        p2.entries[0].key === "pgC" &&
        p2.nextKey === "" &&
        p2.hash === p1.hash &&
        p2.scope === p1.scope,
      `pinned page drifted: ${JSON.stringify(p2)}`,
    );
    const now = await c.viewPage("table", "pg", 10);
    assert(now.entries.length === 4 && now.hash !== p1.hash, JSON.stringify(now));
  });

  await step("S17 Subscribe (type-filtered feed)", async () => {
    await c.append("sub-other", { i: 1 });
    await c.append("sub-wanted", { i: 2 });
    const got: string[] = [];
    for await (const rec of c.subscribe(0, false, ["sub-wanted"])) got.push(rec);
    assert(
      got.length === 1 && JSON.parse(got[0]).type === "sub-wanted",
      `type filter leaked or missed a record: ${JSON.stringify(got)}`,
    );
  });

  await step("S18 QuerySubject (whole-row read)", async () => {
    await c.append("property", { subject: "subj-whole", attribute: "a", value: 1 });
    await c.append("property", { subject: "subj-whole", attribute: "b", value: 2 });
    const a = await c.subject("subj-whole");
    assert(
      a.valueJson === `{"a":1,"b":2}` && a.trace.length === 2,
      `whole row wrong: ${a.valueJson}`,
    );
  });

  await step("S19 parseJson (dependency-free, int64-safe parse)", async () => {
    const obj = parseJson(
      `{"policy_id":"POL1111","limit":${BIG},"tags":["a","b"],"active":true,"note":null}`,
    ) as Record<string, unknown>;
    assert(obj.policy_id === "POL1111", `string field: ${diag(obj)}`);
    assert(obj.limit === BIG, `int64 fidelity lost: ${obj.limit} (want bigint ${BIG})`);
    assert(typeof obj.limit === "bigint", `limit should be a bigint, got ${typeof obj.limit}`);
    assert(
      Array.isArray(obj.tags) && obj.tags.length === 2 && obj.tags[0] === "a",
      `array: ${diag(obj.tags)}`,
    );
    assert(obj.active === true, `bool: ${obj.active}`);
    assert("note" in obj && obj.note === null, `null: ${diag(obj)}`);
    // a plain small number stays a `number`, not a bigint — ergonomics matter
    assert(typeof (parseJson('{"n":1}') as any).n === "number", "small int should stay a number");

    // round-trip against a REAL record from the server
    await c.append("property", { subject: "json-rt", attribute: "a", value: 42 });
    let recJson = "";
    for await (const rec of c.replay(0, false)) recJson = rec; // last record
    const rec = parseJson(recJson) as Record<string, unknown>;
    assert(
      typeof rec.no === "number" && typeof rec.type === "string" && typeof rec.body === "object",
      `record shape: ${diag(rec)}`,
    );
  });

  await step("S20 typed entity round-trip (entity in, entity out)", async () => {
    const widget: Widget = { name: "cog", weight_g: BIG, size: { w: 3, h: 4 } };
    const r = await c.append("widget", widget);
    const out = await c.getRecordAs<Widget>(r.no);
    assert(out.name === "cog", `name: ${out.name}`);
    assert(out.weight_g === BIG, `int64 fidelity lost: ${out.weight_g} (want ${BIG})`);
    assert(out.size.w === 3 && out.size.h === 4, `nested: ${diag(out.size)}`);
    // bodyAs works on a fetched record too
    const rec = await c.getRecord(r.no);
    assert(bodyAs<Widget>(rec).weight_g === BIG, "bodyAs int64 lost");
  });

  const verdict = pass === total ? "PASS" : "FAIL";
  console.log(`CONFORMANCE ${verdict} ${pass}/${total}`);
  c.close();
  if (pass !== total) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
