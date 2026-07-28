// Insurance policy lifecycle — what a policy administration system's audit
// trail looks like when it is built on kivi instead of bolted onto one.
//
// The point this example exists to make: a policy's insured, policyholder,
// asset, coverages and premium are NOT crammed into kivi's built-in
// Table/Graph views — each meaningful business fact (issuance, endorsement,
// a claim, a reserve change) is its OWN richly-shaped event, exactly as it
// would be named in the business ("policy.issued", not a generic "changed").
// kivi is the event backbone underneath a policy admin system, not a
// replacement for its relational read model — see docs/kivi-docs.html's
// "Worked example" section for the full reasoning.
//
// The scene: a claim happens BEFORE a second vehicle is endorsed onto the
// policy. subject() answers "what do we know about this policy RIGHT NOW"
// (both vehicles); the as-of query answers the question a claims dispute
// actually turns on — "was the second vehicle covered on the day of THIS
// loss?" — and the honest answer is no, because the record proves the
// endorsement came later.
//
//	gradle installDist
//	java -cp "build/install/kivi-jvm/lib/*" kivi.examples.InsuranceDemoKt <addr> [token]
package kivi.examples

import kivi.KiviClient
import kotlinx.coroutines.runBlocking

private const val POLICY_ID = "POL-1001"

// -- the domain, as @JvmRecord data classes (each compiles to a real
//    java.lang.Record, so kivi.Json maps it both ways; camelCase properties
//    become snake_case JSON keys automatically). No raw JSON, no Jackson.

@JvmRecord data class Asset(val type: String, val plate: String)
@JvmRecord data class Coverage(val code: String, val limitCents: Long, val deductibleCents: Long)
@JvmRecord data class PolicyIssued(
    val policyId: String, val insured: String, val policyholder: String, val asset: Asset,
    val premiumCents: Long, val effectiveDate: String, val coverages: List<Coverage>,
)
@JvmRecord data class PolicyEndorsed(
    val policyId: String, val endorsementNo: Int, val kind: String,
    val asset: Asset, val effectiveDate: String,
)
@JvmRecord data class ClaimReported(
    val claimId: String, val policyId: String, val lossDate: String, val description: String,
)
@JvmRecord data class ClaimReserveChanged(val claimId: String, val reserveCents: Long, val reason: String)
@JvmRecord data class Property(val subject: String, val attribute: String, val value: Any)

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("usage: InsuranceDemo <addr> [token]")
        kotlin.system.exitProcess(2)
    }
    val token = args.getOrNull(1)
    val c = KiviClient(args[0], token) // verification ON by default

    runBlocking {
        println("== issue the policy (one vehicle) — a typed event, not a generic row")
        c.append("policy.issued", PolicyIssued(
            policyId = POLICY_ID, insured = "jane-doe", policyholder = "jane-doe",
            asset = Asset("vehicle", "1FA-2024"), premiumCents = 84900, effectiveDate = "2026-01-01",
            coverages = listOf(Coverage("LIABILITY", 10_000_000, 0), Coverage("COLLISION", 5_000_000, 50_000)),
        ))
        // a thin, deliberate SHADOW as properties on the policy_id subject —
        // not a duplicate of the rich event, just the handful of fields
        // worth an instant, traced whole-row lookup later (subject())
        c.append("property", Property(POLICY_ID, "status", "active"))
        c.append("property", Property(POLICY_ID, "asset_count", 1))

        println("== a claim is reported against the ONE vehicle on record (FNOL)")
        val claim = c.append("claim.reported",
            ClaimReported("CLM-5001", POLICY_ID, "2026-03-10", "rear-end collision"))
        println("   filed as record ${claim.no}")

        println("== an adjuster sets, then revises, the reserve — TWO events, not an overwrite")
        c.append("claim.reserve_changed", ClaimReserveChanged("CLM-5001", 300_000, "initial estimate"))
        val final = c.append("claim.reserve_changed",
            ClaimReserveChanged("CLM-5001", 450_000, "body shop estimate came in higher"))

        println("== FIVE DAYS LATER: a second vehicle is endorsed onto the policy")
        c.append("policy.endorsed", PolicyEndorsed(
            POLICY_ID, 1, "asset_added", Asset("vehicle", "9ZR-2021"), "2026-03-15"))
        c.append("property", Property(POLICY_ID, "asset_count", 2))

        println("\n== subject(): everything we know about the policy RIGHT NOW, one traced call")
        val now = c.subject(POLICY_ID)
        println("   ${kivi.Json.parse(now.valueJson)}  (established by ${now.trace.size} events, " +
            "scope: records 0..${now.scope})")

        println("\n== the question a claims dispute actually turns on:")
        println("   \"was the second vehicle covered on the day of the March 10 loss?\"")
        val asOfClaim = c.subject(POLICY_ID, asOf = claim.no)
        println("   as of record ${claim.no} (the moment the claim was filed): ${kivi.Json.parse(asOfClaim.valueJson)}")
        println("   → asset_count is 1: the endorsement had not happened yet. Not fabricated — proven.")

        println("\n== why(): the FINAL reserve receipt, read back AS A TYPED ENTITY (Json.bodyAs)")
        for (rec in c.why(listOf(final.no))) {
            val e = kivi.Json.bodyAs(rec, ClaimReserveChanged::class.java)
            println("   claim ${e.claimId}: reserve now ${e.reserveCents} cents (${e.reason})")
        }

        println("\n== subscribe(): a downstream reserve-monitor gets TYPED events, one event type only")
        var n = 0
        c.subscribe(types = listOf("claim.reserve_changed")).collect { rec ->
            n++
            val e = kivi.Json.bodyAs(rec, ClaimReserveChanged::class.java)
            println("   ${e.claimId} → ${e.reserveCents} cents (${e.reason})")
        }
        println("   $n reserve-change event(s) delivered — policy.issued/endorsed and " +
            "claim.reported never crossed the wire")

        println("\n== what this demo does NOT show, on purpose")
        println("   kivi retention hold --reason \"SIU fraud review\" <ledger> <period>   # legal hold: CLI-only,")
        println("   offline, deliberately never a server RPC — see OPERATIONS.md §2.1/§14 and the docs page.")

        println("\nINSURANCE DEMO OK")
    }
    c.close()
}
