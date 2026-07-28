// Insurance policy lifecycle — the pure-Java client version. Written in
// JAVA on purpose, same discipline as JavaScenario.java: compiling and
// running this file IS the claim that the shapes below work identically
// from plain Java, no coroutines. See InsuranceDemo.kt (Kotlin) for the
// full narrative comment, and docs/kivi-docs.html's "Worked example"
// section for the reasoning behind the design.
//
//	gradle installDist
//	java -cp "build/install/kivi-jvm/lib/*" kivi.examples.InsuranceDemoJava <addr> [token]
package kivi.examples;

import kivi.Json;
import kivi.KiviJavaClient;
import kivi.Receipt;
import kivi.TracedAnswer;

import java.util.Iterator;
import java.util.List;

public final class InsuranceDemoJava {
    private static final String POLICY_ID = "POL-1001";

    // -- the domain, as plain Java records (nested to avoid colliding with the
    //    Kotlin demo's same-named types in this package). kivi.Json maps them
    //    both ways; camelCase components become snake_case JSON keys. No JSON
    //    text, no Jackson — entity in, entity out.
    record Asset(String type, String plate) {}
    record Coverage(String code, long limitCents, long deductibleCents) {}
    record PolicyIssued(String policyId, String insured, String policyholder, Asset asset,
                        long premiumCents, String effectiveDate, List<Coverage> coverages) {}
    record PolicyEndorsed(String policyId, int endorsementNo, String kind, Asset asset,
                          String effectiveDate) {}
    record ClaimReported(String claimId, String policyId, String lossDate, String description) {}
    record ClaimReserveChanged(String claimId, long reserveCents, String reason) {}
    record Property(String subject, String attribute, Object value) {}

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("usage: InsuranceDemoJava <addr> [token]");
            System.exit(2);
        }
        String token = args.length > 1 ? args[1] : null;

        try (KiviJavaClient c = new KiviJavaClient(args[0], token)) {
            System.out.println("== issue the policy (one vehicle) — a typed event, not a generic row");
            c.append("policy.issued", new PolicyIssued(POLICY_ID, "jane-doe", "jane-doe",
                    new Asset("vehicle", "1FA-2024"), 84900, "2026-01-01",
                    List.of(new Coverage("LIABILITY", 10_000_000, 0),
                            new Coverage("COLLISION", 5_000_000, 50_000))));
            // a thin, deliberate SHADOW as properties on the policy_id subject
            // — not a duplicate of the rich event, just the handful of fields
            // worth an instant, traced whole-row lookup later (subject())
            c.append("property", new Property(POLICY_ID, "status", "active"));
            c.append("property", new Property(POLICY_ID, "asset_count", 1));

            System.out.println("== a claim is reported against the ONE vehicle on record (FNOL)");
            Receipt claim = c.append("claim.reported",
                    new ClaimReported("CLM-5001", POLICY_ID, "2026-03-10", "rear-end collision"));
            System.out.println("   filed as record " + claim.getNo());

            System.out.println("== an adjuster sets, then revises, the reserve — TWO events, not an overwrite");
            c.append("claim.reserve_changed", new ClaimReserveChanged("CLM-5001", 300_000, "initial estimate"));
            Receipt finalReserve = c.append("claim.reserve_changed",
                    new ClaimReserveChanged("CLM-5001", 450_000, "body shop estimate came in higher"));

            System.out.println("== FIVE DAYS LATER: a second vehicle is endorsed onto the policy");
            c.append("policy.endorsed", new PolicyEndorsed(POLICY_ID, 1, "asset_added",
                    new Asset("vehicle", "9ZR-2021"), "2026-03-15"));
            c.append("property", new Property(POLICY_ID, "asset_count", 2));

            System.out.println("\n== subject(): everything we know about the policy RIGHT NOW, one traced call");
            TracedAnswer now = c.subject(POLICY_ID);
            System.out.println("   " + Json.parse(now.getValueJson()) + "  (established by "
                    + now.getTrace().size() + " events, scope: records 0.." + now.getScope() + ")");

            System.out.println("\n== the question a claims dispute actually turns on:");
            System.out.println("   \"was the second vehicle covered on the day of the March 10 loss?\"");
            TracedAnswer asOfClaim = c.subject(POLICY_ID, claim.getNo());
            System.out.println("   as of record " + claim.getNo() + " (the moment the claim was filed): "
                    + Json.parse(asOfClaim.getValueJson()));
            System.out.println("   → asset_count is 1: the endorsement had not happened yet. Not fabricated — proven.");

            System.out.println("\n== why(): the FINAL reserve receipt, read back AS A TYPED ENTITY (Json.bodyAs)");
            for (String rec : c.why(List.of(finalReserve.getNo()))) {
                ClaimReserveChanged e = Json.bodyAs(rec, ClaimReserveChanged.class);
                System.out.println("   claim " + e.claimId() + ": reserve now " + e.reserveCents()
                        + " cents (" + e.reason() + ")");
            }

            System.out.println("\n== subscribe(): a downstream reserve-monitor gets TYPED events, one event type only");
            int n = 0;
            Iterator<String> it = c.subscribe(0, false, List.of("claim.reserve_changed"));
            while (it.hasNext()) {
                n++;
                ClaimReserveChanged e = Json.bodyAs(it.next(), ClaimReserveChanged.class);
                System.out.println("   " + e.claimId() + " → " + e.reserveCents() + " cents (" + e.reason() + ")");
            }
            System.out.println("   " + n + " reserve-change event(s) delivered — policy.issued/endorsed and "
                    + "claim.reported never crossed the wire");

            System.out.println("\n== what this demo does NOT show, on purpose");
            System.out.println("   kivi retention hold --reason \"SIU fraud review\" <ledger> <period>   "
                    + "# legal hold: CLI-only,");
            System.out.println("   offline, deliberately never a server RPC — see OPERATIONS.md §2.1/§14 "
                    + "and the docs page.");

            System.out.println("\nINSURANCE DEMO OK");
        }
    }
}
