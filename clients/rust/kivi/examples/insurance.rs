//! Insurance policy lifecycle — what a policy administration system's audit
//! trail looks like when it is built on kivi instead of bolted onto one.
//!
//! The point this example exists to make: a policy's insured, policyholder,
//! asset, coverages and premium are NOT crammed into kivi's built-in
//! Table/Graph views — each meaningful business fact (issuance, endorsement,
//! a claim, a reserve change) is its OWN richly-shaped event, exactly as it
//! would be named in the business ("policy.issued", not a generic
//! "changed"). kivi is the event backbone underneath a policy admin system,
//! not a replacement for its relational read model — see
//! docs/kivi-docs.html's "Worked example" section for the full reasoning.
//!
//! TYPED events, no raw JSON: each event is a serde struct. `append_typed`
//! takes it directly, `body_as` decodes a record's body back INTO a struct —
//! entity in, entity out, with serde (already the SDK's serialization
//! framework), no ORM.
//!
//! The scene: a claim happens BEFORE a second vehicle is endorsed onto the
//! policy. subject() answers "what do we know about this policy RIGHT NOW"
//! (both vehicles); the as-of query answers the question a claims dispute
//! actually turns on — "was the second vehicle covered on the day of THIS
//! loss?" — and the honest answer is no, because the record proves the
//! endorsement came later.
//!
//!     cargo run --example insurance -- <addr> [token]

use kivi::Client;
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;

const POLICY_ID: &str = "POL-1001";

// -- the domain, as plain typed entities (no JSON in the business code) ------

#[derive(Serialize, Deserialize)]
struct Asset {
    r#type: String,
    plate: String,
}

#[derive(Serialize)]
struct Coverage {
    code: String,
    limit_cents: i64,
    deductible_cents: i64,
}

#[derive(Serialize)]
struct PolicyIssued {
    policy_id: String,
    insured: String,
    policyholder: String,
    asset: Asset,
    premium_cents: i64,
    effective_date: String,
    coverages: Vec<Coverage>,
}

#[derive(Serialize)]
struct PolicyEndorsed {
    policy_id: String,
    endorsement_no: i64,
    kind: String,
    asset: Asset,
    effective_date: String,
}

#[derive(Serialize)]
struct ClaimReported {
    claim_id: String,
    policy_id: String,
    loss_date: String,
    description: String,
}

#[derive(Serialize, Deserialize)]
struct ClaimReserveChanged {
    claim_id: String,
    reserve_cents: i64,
    reason: String,
}

/// The thin SHADOW written on the policy_id subject — not a duplicate of the
/// rich event, just the fields worth an instant, traced whole-row lookup.
#[derive(Serialize)]
struct Property {
    subject: String,
    attribute: String,
    value: serde_json::Value,
}

fn cov(code: &str, limit: i64, ded: i64) -> Coverage {
    Coverage {
        code: code.into(),
        limit_cents: limit,
        deductible_cents: ded,
    }
}
fn prop(attr: &str, value: serde_json::Value) -> Property {
    Property {
        subject: POLICY_ID.into(),
        attribute: attr.into(),
        value,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: insurance <addr> [token]");
        std::process::exit(2);
    }
    let token = args.get(2).cloned().unwrap_or_default();
    let c = Client::connect(&args[1], token).await?; // verification ON by default

    println!("== issue the policy (one vehicle) — a typed event, not a generic row");
    c.append_typed(
        "policy.issued",
        &PolicyIssued {
            policy_id: POLICY_ID.into(),
            insured: "jane-doe".into(),
            policyholder: "jane-doe".into(),
            asset: Asset {
                r#type: "vehicle".into(),
                plate: "1FA-2024".into(),
            },
            premium_cents: 84900,
            effective_date: "2026-01-01".into(),
            coverages: vec![
                cov("LIABILITY", 10_000_000, 0),
                cov("COLLISION", 5_000_000, 50_000),
            ],
        },
    )
    .await?;
    c.append_typed("property", &prop("status", "active".into()))
        .await?;
    c.append_typed("property", &prop("asset_count", 1.into()))
        .await?;

    println!("== a claim is reported against the ONE vehicle on record (FNOL)");
    let claim = c
        .append_typed(
            "claim.reported",
            &ClaimReported {
                claim_id: "CLM-5001".into(),
                policy_id: POLICY_ID.into(),
                loss_date: "2026-03-10".into(),
                description: "rear-end collision".into(),
            },
        )
        .await?;
    println!("   filed as record {}", claim.no);

    println!("== an adjuster sets, then revises, the reserve — TWO events, not an overwrite");
    c.append_typed(
        "claim.reserve_changed",
        &ClaimReserveChanged {
            claim_id: "CLM-5001".into(),
            reserve_cents: 300_000,
            reason: "initial estimate".into(),
        },
    )
    .await?;
    let final_reserve = c
        .append_typed(
            "claim.reserve_changed",
            &ClaimReserveChanged {
                claim_id: "CLM-5001".into(),
                reserve_cents: 450_000,
                reason: "body shop estimate came in higher".into(),
            },
        )
        .await?;

    println!("== FIVE DAYS LATER: a second vehicle is endorsed onto the policy");
    c.append_typed(
        "policy.endorsed",
        &PolicyEndorsed {
            policy_id: POLICY_ID.into(),
            endorsement_no: 1,
            kind: "asset_added".into(),
            asset: Asset {
                r#type: "vehicle".into(),
                plate: "9ZR-2021".into(),
            },
            effective_date: "2026-03-15".into(),
        },
    )
    .await?;
    c.append_typed("property", &prop("asset_count", 2.into()))
        .await?;

    println!("\n== subject(): everything we know about the policy RIGHT NOW, one traced call");
    let now = c.subject(POLICY_ID).await?;
    println!(
        "   {}  (established by {} events, scope: records 0..{})",
        now.value,
        now.trace.len(),
        now.scope
    );

    println!("\n== the question a claims dispute actually turns on:");
    println!("   \"was the second vehicle covered on the day of the March 10 loss?\"");
    let as_of_claim = c.subject_at(POLICY_ID, Some(claim.no)).await?;
    println!(
        "   as of record {} (the moment the claim was filed): {}",
        claim.no, as_of_claim.value
    );
    println!(
        "   → asset_count is 1: the endorsement had not happened yet. Not fabricated — proven."
    );

    println!("\n== why(): the FINAL reserve receipt, read back AS A TYPED ENTITY (body_as)");
    for rec in c.why(&[final_reserve.no]).await? {
        let e: ClaimReserveChanged = kivi::body_as(&rec)?;
        println!(
            "   claim {}: reserve now {} cents ({})",
            e.claim_id, e.reserve_cents, e.reason
        );
    }

    println!(
        "\n== subscribe(): a downstream reserve-monitor gets TYPED events, one event type only"
    );
    let mut n = 0;
    let mut stream = c
        .subscribe(0, false, vec!["claim.reserve_changed".to_string()])
        .await?;
    while let Some(rec) = stream.next().await {
        n += 1;
        let e: ClaimReserveChanged = kivi::body_as(&rec?)?;
        println!(
            "   {} → {} cents ({})",
            e.claim_id, e.reserve_cents, e.reason
        );
    }
    println!(
        "   {n} reserve-change event(s) delivered — policy.issued/endorsed and claim.reported never crossed the wire"
    );

    println!("\n== what this demo does NOT show, on purpose");
    println!("   kivi retention hold --reason \"SIU fraud review\" <ledger> <period>   # legal hold: CLI-only,");
    println!("   offline, deliberately never a server RPC — see OPERATIONS.md §2.1/§14 and the docs page.");

    println!("\nINSURANCE DEMO OK");
    Ok(())
}
