// Insurance policy lifecycle — what a policy administration system's audit
// trail looks like when it is built on kivi instead of bolted onto one.
//
// The point this example exists to make: a policy's insured, policyholder,
// asset, coverages and premium are NOT crammed into kivi's built-in
// Table/Graph views — each meaningful business fact (issuance, endorsement,
// a claim, a reserve change) is its OWN richly-shaped event, exactly as it
// would be named in the business ("policy.issued", not a generic
// "changed"). kivi is the event backbone underneath a policy admin system,
// not a replacement for its relational read model — see
// docs/kivi-docs.html's "Worked example" section for the full reasoning.
//
// The scene: a claim happens BEFORE a second vehicle is endorsed onto the
// policy. subject() answers "what do we know about this policy RIGHT NOW"
// (both vehicles); the as-of query answers the question a claims dispute
// actually turns on — "was the second vehicle covered on the day of THIS
// loss?" — and the honest answer is no, because the record proves the
// endorsement came later.
//
//   node dist/examples/insurance.js <addr> [token]

import { KiviClient, parseJson, bodyAs } from "../src/index";

const POLICY_ID = "POL-1001";

// -- the domain, as plain typed interfaces (no untyped objects) --------------

interface Asset { type: string; plate: string; }
interface Coverage { code: string; limit_cents: number; deductible_cents: number; }
interface PolicyIssued {
  policy_id: string; insured: string; policyholder: string; asset: Asset;
  premium_cents: number; effective_date: string; coverages: Coverage[];
}
interface PolicyEndorsed {
  policy_id: string; endorsement_no: number; kind: string; asset: Asset; effective_date: string;
}
interface ClaimReported {
  claim_id: string; policy_id: string; loss_date: string; description: string;
}
interface ClaimReserveChanged { claim_id: string; reserve_cents: number; reason: string; }
interface Property { subject: string; attribute: string; value: unknown; }

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error("usage: insurance <addr> [token]");
    return 2;
  }
  const c = new KiviClient(args[0], { token: args[1] }); // verification ON by default

  console.log("== issue the policy (one vehicle) — a typed event, not a generic row");
  const issued: PolicyIssued = {
    policy_id: POLICY_ID, insured: "jane-doe", policyholder: "jane-doe",
    asset: { type: "vehicle", plate: "1FA-2024" }, premium_cents: 84900, effective_date: "2026-01-01",
    coverages: [
      { code: "LIABILITY", limit_cents: 10_000_000, deductible_cents: 0 },
      { code: "COLLISION", limit_cents: 5_000_000, deductible_cents: 50_000 },
    ],
  };
  await c.append("policy.issued", issued);
  // a thin, deliberate SHADOW as properties on the policy_id subject — not a
  // duplicate of the rich event, just the handful of fields worth an
  // instant, traced whole-row lookup later (subject())
  const status: Property = { subject: POLICY_ID, attribute: "status", value: "active" };
  await c.append("property", status);
  await c.append("property", { subject: POLICY_ID, attribute: "asset_count", value: 1 } as Property);

  console.log("== a claim is reported against the ONE vehicle on record (FNOL)");
  const reported: ClaimReported = {
    claim_id: "CLM-5001", policy_id: POLICY_ID,
    loss_date: "2026-03-10", description: "rear-end collision",
  };
  const claim = await c.append("claim.reported", reported);
  console.log(`   filed as record ${claim.no}`);

  console.log("== an adjuster sets, then revises, the reserve — TWO events, not an overwrite");
  const r1: ClaimReserveChanged = { claim_id: "CLM-5001", reserve_cents: 300_000, reason: "initial estimate" };
  await c.append("claim.reserve_changed", r1);
  const r2: ClaimReserveChanged = {
    claim_id: "CLM-5001", reserve_cents: 450_000, reason: "body shop estimate came in higher" };
  const final = await c.append("claim.reserve_changed", r2);

  console.log("== FIVE DAYS LATER: a second vehicle is endorsed onto the policy");
  const endorsed: PolicyEndorsed = {
    policy_id: POLICY_ID, endorsement_no: 1, kind: "asset_added",
    asset: { type: "vehicle", plate: "9ZR-2021" }, effective_date: "2026-03-15",
  };
  await c.append("policy.endorsed", endorsed);
  await c.append("property", { subject: POLICY_ID, attribute: "asset_count", value: 2 } as Property);

  console.log("\n== subject(): everything we know about the policy RIGHT NOW, one traced call");
  const now = await c.subject(POLICY_ID);
  // parseJson: dependency-free, int64-safe structured access — no need for
  // a library just to read this back
  console.log(
    `   ${JSON.stringify(parseJson(now.valueJson))}  (established by ${now.trace.length} events, ` +
      `scope: records 0..${now.scope})`,
  );

  console.log("\n== the question a claims dispute actually turns on:");
  console.log('   "was the second vehicle covered on the day of the March 10 loss?"');
  const asOfClaim = await c.subject(POLICY_ID, claim.no);
  console.log(
    `   as of record ${claim.no} (the moment the claim was filed): ${JSON.stringify(parseJson(asOfClaim.valueJson))}`,
  );
  console.log("   → asset_count is 1: the endorsement had not happened yet. Not fabricated — proven.");

  console.log("\n== why(): the FINAL reserve receipt, read back AS A TYPED ENTITY (bodyAs)");
  for (const rec of await c.why([final.no])) {
    const e = bodyAs<ClaimReserveChanged>(rec);
    console.log(`   claim ${e.claim_id}: reserve now ${e.reserve_cents} cents (${e.reason})`);
  }

  console.log("\n== subscribe(): a downstream reserve-monitor gets TYPED events, one event type only");
  let n = 0;
  for await (const rec of c.subscribe(0, false, ["claim.reserve_changed"])) {
    n++;
    const e = bodyAs<ClaimReserveChanged>(rec);
    console.log(`   ${e.claim_id} → ${e.reserve_cents} cents (${e.reason})`);
  }
  console.log(
    `   ${n} reserve-change event(s) delivered — policy.issued/endorsed and claim.reported never crossed the wire`,
  );

  console.log("\n== what this demo does NOT show, on purpose");
  console.log('   kivi retention hold --reason "SIU fraud review" <ledger> <period>   # legal hold: CLI-only,');
  console.log("   offline, deliberately never a server RPC — see OPERATIONS.md §2.1/§14 and the docs page.");

  console.log("\nINSURANCE DEMO OK");
  c.close();
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
