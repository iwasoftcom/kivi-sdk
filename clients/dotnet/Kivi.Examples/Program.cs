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
// TYPED events, no raw JSON: each event is a C# record. Append<T> takes it
// directly (System.Text.Json, already in the runtime — no NuGet), and
// BodyAs<T> decodes a record's body back INTO a record — entity in, entity
// out, no ORM. PascalCase properties map to snake_case JSON both ways.
//
// The scene: a claim happens BEFORE a second vehicle is endorsed onto the
// policy. Subject() answers "what do we know about this policy RIGHT NOW"
// (both vehicles); the as-of query answers the question a claims dispute
// actually turns on — "was the second vehicle covered on the day of THIS
// loss?" — and the honest answer is no, because the record proves the
// endorsement came later.
//
//	dotnet run --project clients/dotnet/Kivi.Examples -- <addr> [token]
using Kivi;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: insurance <addr> [token]");
    return 2;
}
const string policyId = "POL-1001";

using var c = new KiviClient(args[0], args.Length > 1 ? args[1] : null); // verification ON by default

static string Show(object? v)
{
    if (v is Dictionary<string, object?> d)
        return "{" + string.Join(", ", d.Select(kv => $"{kv.Key}: {kv.Value}")) + "}";
    return v?.ToString() ?? "null";
}

Console.WriteLine("== issue the policy (one vehicle) — a typed event, not a generic row");
c.Append("policy.issued", new PolicyIssued(policyId, "jane-doe", "jane-doe",
    new Asset("vehicle", "1FA-2024"), 84900, "2026-01-01",
    new[] { new Coverage("LIABILITY", 10_000_000, 0), new Coverage("COLLISION", 5_000_000, 50_000) }));
// a thin, deliberate SHADOW as properties on the policy_id subject — not a
// duplicate of the rich event, just the handful of fields worth an instant,
// traced whole-row lookup later (Subject())
c.Append("property", new Property(policyId, "status", "active"));
c.Append("property", new Property(policyId, "asset_count", 1));

Console.WriteLine("== a claim is reported against the ONE vehicle on record (FNOL)");
var claim = c.Append("claim.reported",
    new ClaimReported("CLM-5001", policyId, "2026-03-10", "rear-end collision"));
Console.WriteLine($"   filed as record {claim.No}");

Console.WriteLine("== an adjuster sets, then revises, the reserve — TWO events, not an overwrite");
c.Append("claim.reserve_changed", new ClaimReserveChanged("CLM-5001", 300_000, "initial estimate"));
var finalReserve = c.Append("claim.reserve_changed",
    new ClaimReserveChanged("CLM-5001", 450_000, "body shop estimate came in higher"));

Console.WriteLine("== FIVE DAYS LATER: a second vehicle is endorsed onto the policy");
c.Append("policy.endorsed",
    new PolicyEndorsed(policyId, 1, "asset_added", new Asset("vehicle", "9ZR-2021"), "2026-03-15"));
c.Append("property", new Property(policyId, "asset_count", 2));

Console.WriteLine("\n== Subject(): everything we know about the policy RIGHT NOW, one traced call");
var now = c.Subject(policyId);
Console.WriteLine($"   {Show(Json.Parse(now.ValueJson))}  (established by {now.Trace.Count} events, " +
    $"scope: records 0..{now.Scope})");

Console.WriteLine("\n== the question a claims dispute actually turns on:");
Console.WriteLine("   \"was the second vehicle covered on the day of the March 10 loss?\"");
var asOfClaim = c.Subject(policyId, claim.No);
Console.WriteLine($"   as of record {claim.No} (the moment the claim was filed): {Show(Json.Parse(asOfClaim.ValueJson))}");
Console.WriteLine("   → asset_count is 1: the endorsement had not happened yet. Not fabricated — proven.");

Console.WriteLine("\n== Why(): the FINAL reserve receipt, read back AS A TYPED ENTITY (BodyAs)");
foreach (var rec in c.Why(new[] { finalReserve.No }))
{
    var e = KiviClient.BodyAs<ClaimReserveChanged>(rec);
    Console.WriteLine($"   claim {e.ClaimId}: reserve now {e.ReserveCents} cents ({e.Reason})");
}

Console.WriteLine("\n== SubscribeAll(): a downstream reserve-monitor gets TYPED events, one event type only");
var fed = c.SubscribeAll(types: new[] { "claim.reserve_changed" });
foreach (var rec in fed)
{
    var e = KiviClient.BodyAs<ClaimReserveChanged>(rec);
    Console.WriteLine($"   {e.ClaimId} → {e.ReserveCents} cents ({e.Reason})");
}
Console.WriteLine($"   {fed.Count} reserve-change event(s) delivered — policy.issued/endorsed and " +
    "claim.reported never crossed the wire");

Console.WriteLine("\n== what this demo does NOT show, on purpose");
Console.WriteLine("   kivi retention hold --reason \"SIU fraud review\" <ledger> <period>   # legal hold: CLI-only,");
Console.WriteLine("   offline, deliberately never a server RPC — see OPERATIONS.md §2.1/§14 and the docs page.");

Console.WriteLine("\nINSURANCE DEMO OK");
return 0;

// -- the domain, as plain typed records (PascalCase ↔ snake_case JSON) -------

record Asset(string Type, string Plate);
record Coverage(string Code, long LimitCents, long DeductibleCents);
record PolicyIssued(string PolicyId, string Insured, string Policyholder, Asset Asset,
    long PremiumCents, string EffectiveDate, Coverage[] Coverages);
record PolicyEndorsed(string PolicyId, int EndorsementNo, string Kind, Asset Asset, string EffectiveDate);
record ClaimReported(string ClaimId, string PolicyId, string LossDate, string Description);
record ClaimReserveChanged(string ClaimId, long ReserveCents, string Reason);
record Property(string Subject, string Attribute, object Value);
