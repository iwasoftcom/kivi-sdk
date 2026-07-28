//! kivi Rust SDK conformance runner (G3.0 scenarios S1-S10, the parity
//! scenarios S12-S14: identity/login, semantic similar, head + as-of, and
//! S16: paged view reads). Usage:
//!
//!   conformance-runner <clean> <tamper-record> <tamper-seal> <token> <auth>
//!
//! auth serves a seeded kivi user conf-writer/conf-pass-123 (writer) — its
//! record 0 is that kivi.user event.

use kivi::{Client, KiviError};
use serde_json::{json, Value};
use tokio_stream::StreamExt;

static BIG: i64 = 9_007_199_254_740_993; // 2^53+1 — dies in any double conversion

async fn step<F, Fut>(pass: &mut i32, total: &mut i32, name: &str, fn_: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    *total += 1;
    match fn_().await {
        Ok(()) => {
            *pass += 1;
            println!("  {name}: ok");
        }
        Err(e) => println!("  {name}: FAIL — {e}"),
    }
}

fn is_kind(e: &KiviError, want: &str) -> bool {
    matches!(
        (e, want),
        (KiviError::NotFound(_), "not_found")
            | (KiviError::Unauthenticated(_), "unauthenticated")
            | (KiviError::PreconditionFailed(_), "precondition")
            | (KiviError::Verification(_), "verification")
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: conformance-runner <clean> <tamper-record> <tamper-seal> <token> <auth>");
        std::process::exit(2);
    }
    let clean_addr = &args[1];
    let tr_addr = &args[2];
    let ts_addr = &args[3];
    let token = &args[4];
    let auth_addr = &args[5];

    let c = Client::connect(clean_addr, token.clone()).await?;
    println!("kivi Rust SDK conformance:");

    let mut pass = 0;
    let mut total = 0;

    step(&mut pass, &mut total, "S1 receipt", || async {
        let r = c
            .append(
                "property",
                &json!({"subject":"dog","attribute":"sound","value":"bark"}),
            )
            .await?;
        if r.no != 0 || r.hash.len() != 64 {
            return Err(format!("{r:?}").into());
        }
        let r2 = c
            .append(
                "property",
                &json!({"subject":"dog","attribute":"sound","value":"woof"}),
            )
            .await?;
        if r2.no != 1 || r2.offset <= r.offset {
            return Err(format!("{r2:?}").into());
        }
        Ok(())
    })
    .await;

    step(&mut pass, &mut total, "S2 int64 fidelity", || async {
        c.append(
            "property",
            &json!({"subject":"num","attribute":"big","value":BIG}),
        )
        .await?;
        let a = c.table("num", "big").await?;
        let got = a.value.as_i64().ok_or("value is not an integer")?;
        if got != BIG {
            return Err(format!("int64 mangled: {:?}", a.value).into());
        }
        Ok(())
    })
    .await;

    step(
        &mut pass,
        &mut total,
        "S3 traced answers, honest refusals",
        || async {
            let a = c.table("dog", "sound").await?;
            if a.trace.is_empty() || a.scope <= 0 {
                return Err(format!("{a:?}").into());
            }
            match c.table("ghost", "attr").await {
                Err(e) if is_kind(&e, "not_found") => {}
                other => return Err(format!("missing cell: {other:?}").into()),
            }
            // an untraced answer is unrepresentable — structurally
            if kivi::TracedAnswer::new(Value::Null, vec![], 0).is_ok() {
                return Err("a traceless answer was constructable".into());
            }
            Ok(())
        },
    )
    .await;

    step(&mut pass, &mut total, "S4 why", || async {
        let a = c.table("num", "big").await?;
        let recs = c.why(&a.trace).await?;
        if recs.len() != 1 {
            return Err(format!("{recs:?}").into());
        }
        let got = recs[0]["body"]["value"]
            .as_i64()
            .ok_or("why value not an int")?;
        if got != BIG {
            return Err(format!("why fetched {got}").into());
        }
        Ok(())
    })
    .await;

    step(
        &mut pass,
        &mut total,
        "S5 verified replay (clean)",
        || async {
            c.seal().await?;
            let rep = c.verify_ledger().await?;
            let mut n: i64 = 0;
            let mut stream = c.replay(0, false).await?;
            while let Some(r) = stream.next().await {
                r?;
                n += 1;
            }
            if n != rep.records {
                return Err(format!("replayed {n}, ledger holds {}", rep.records).into());
            }
            Ok(())
        },
    )
    .await;

    step(&mut pass, &mut total, "S6 tamper trap (record)", || async {
        let t = Client::connect(tr_addr, "").await?;
        t.append("note", &json!({"k":"tamper-me"})).await?;
        let mut stream = t.replay(0, false).await?;
        let mut caught = false;
        while let Some(r) = stream.next().await {
            if r.is_err() {
                caught = true;
                break;
            }
        }
        if !caught {
            return Err("a corrupted record sailed through".into());
        }
        Ok(())
    })
    .await;

    step(&mut pass, &mut total, "S7 tamper trap (seal)", || async {
        let s = Client::connect(ts_addr, "").await?;
        s.append("note", &json!({"k":1})).await?;
        s.seal().await?;
        let mut stream = s.replay(0, false).await?;
        let mut caught = false;
        while let Some(r) = stream.next().await {
            if r.is_err() {
                caught = true;
                break;
            }
        }
        if !caught {
            return Err("a forged seal sailed through".into());
        }
        Ok(())
    })
    .await;

    step(&mut pass, &mut total, "S8 auth", || async {
        let bare = Client::connect(clean_addr, "").await?;
        match bare.verify_ledger().await {
            Err(e) if is_kind(&e, "unauthenticated") => {}
            other => return Err(format!("tokenless call: {other:?}").into()),
        }
        let wrong = Client::connect(clean_addr, "wrong").await?;
        match wrong.verify_ledger().await {
            Err(e) if is_kind(&e, "unauthenticated") => {}
            other => return Err(format!("wrong token: {other:?}").into()),
        }
        c.verify_ledger().await?;
        Ok(())
    })
    .await;

    step(&mut pass, &mut total, "S9 erase flow", || async {
        #[derive(serde::Serialize)]
        struct Note {
            v: String,
        }
        let r = c
            .append_private_typed(
                "note",
                &Note {
                    v: "top-secret".into(),
                },
            )
            .await?; // typed entity overload
        let rec = c.get_record(r.no, true).await?;
        if rec["body"]["v"] != "top-secret" {
            return Err(format!("unsealed read: {rec:?}").into());
        }
        c.erase(r.no, "conformance").await?;
        match c.erase(r.no, "again").await {
            Err(e) if is_kind(&e, "precondition") => {}
            other => return Err(format!("second erase: {other:?}").into()),
        }
        let rec2 = c.get_record(r.no, true).await?;
        if rec2.to_string().contains("top-secret") || rec2["body"]["kivi.sealed"] != true {
            return Err(format!("erased body not sealed: {rec2:?}").into());
        }
        Ok(())
    })
    .await;

    step(
        &mut pass,
        &mut total,
        "S10 concurrency parity (Rust's async)",
        || async {
            let mut handles = Vec::new();
            for g in 0..8 {
                let c2 = c.clone();
                handles.push(tokio::spawn(async move {
                    c2.append("metric", &json!({"series":"conc","value":g}))
                        .await
                }));
            }
            for h in handles {
                h.await??;
            }
            let rep = c.verify_ledger().await?;
            if !rep.ok {
                return Err(format!("post-concurrency verify: {rep:?}").into());
            }
            Ok(())
        },
    )
    .await;

    step(
        &mut pass,
        &mut total,
        "S12 identity (login + per-call bearer)",
        || async {
            let u = Client::connect(auth_addr, "").await?;
            match u.login("conf-writer", "wrong-pass").await {
                Err(e) if is_kind(&e, "unauthenticated") => {}
                other => return Err(format!("wrong password: {other:?}").into()),
            }
            let sess = u.login("conf-writer", "conf-pass-123").await?;
            if sess.role != "writer" || sess.token.is_empty() {
                return Err(format!("login: {sess:?}").into());
            }
            u.append("note", &json!({"who":"conf-writer"})).await?;
            let bare = Client::connect(auth_addr, "").await?;
            match bare.verify_ledger().await {
                Err(e) if is_kind(&e, "unauthenticated") => {}
                other => return Err(format!("anonymous call accepted: {other:?}").into()),
            }
            bare.with_bearer(sess.token).verify_ledger().await?;
            Ok(())
        },
    )
    .await;

    step(
        &mut pass,
        &mut total,
        "S13 similar (traced semantic search)",
        || async {
            let u = Client::connect(auth_addr, token.clone()).await?;
            let r = u
                .append(
                    "note",
                    &json!({"text":"the zebra escaped the painting exhibition"}),
                )
                .await?;
            u.append(
                "note",
                &json!({"text":"database replication lag is boring"}),
            )
            .await?;
            let a = u.similar("zebra exhibition painting", 3).await?;
            if a.hits.is_empty() || a.hits[0].no != r.no {
                return Err(format!("top hit is not the zebra record: {:?}", a.hits).into());
            }
            if a.model.is_empty() || a.scope < r.no || a.hits[0].record.is_none() {
                return Err(format!(
                    "untraced similarity answer: model={} scope={}",
                    a.model, a.scope
                )
                .into());
            }
            Ok(())
        },
    )
    .await;

    step(
        &mut pass,
        &mut total,
        "S14 head + as-of (time travel)",
        || async {
            let rep = c.verify_ledger().await?;
            let head = c.head().await?;
            if head.no != rep.records - 1 || head.hash.len() != 64 {
                return Err(format!(
                    "head disagrees with verify: {} vs {}",
                    head.no,
                    rep.records - 1
                )
                .into());
            }
            // record 0 was dog.sound=bark, overwritten later by woof (S1)
            let a = c.table_at("dog", "sound", Some(0)).await?;
            if a.value != "bark" || a.scope != 0 || a.trace != vec![0] {
                return Err(format!("as-of 0: {a:?}").into());
            }
            let now = c.table("dog", "sound").await?;
            if now.value != "woof" {
                return Err(format!("time travel changed the present: {now:?}").into());
            }
            Ok(())
        },
    )
    .await;

    step(
        &mut pass,
        &mut total,
        "S16 paged view reads (keyset + snapshot pinning)",
        || async {
            for s in ["pgA", "pgB", "pgC"] {
                c.append("property", &json!({"subject":s,"attribute":"a","value":s}))
                    .await?;
            }
            let p1 = c.view_page("table", "pg", 2).await?;
            if p1.entries.len() != 2
                || p1.entries[0].key != "pgA"
                || p1.entries[1].key != "pgB"
                || p1.next_key != "pgB"
                || p1.hash.len() != 64
            {
                return Err(format!("page 1: {p1:?}").into());
            }
            // a write lands BETWEEN pages — the pinned walk must not see it
            c.append(
                "property",
                &json!({"subject":"pgD","attribute":"a","value":4}),
            )
            .await?;
            let p2 = c
                .view_page_at("table", &p1.next_key, 10, Some(p1.scope))
                .await?;
            if p2.entries.len() != 1
                || p2.entries[0].key != "pgC"
                || p2.next_key != ""
                || p2.hash != p1.hash
                || p2.scope != p1.scope
            {
                return Err(format!("pinned page drifted: {p2:?}").into());
            }
            let now = c.view_page("table", "pg", 10).await?;
            if now.entries.len() != 4 || now.hash == p1.hash {
                return Err(format!("unpinned page: {now:?}").into());
            }
            Ok(())
        },
    )
    .await;

    step(
        &mut pass,
        &mut total,
        "S17 Subscribe (type-filtered feed)",
        || async {
            c.append("sub-other", &json!({"i": 1})).await?;
            c.append("sub-wanted", &json!({"i": 2})).await?;
            let mut got: Vec<Value> = Vec::new();
            let mut stream = c
                .subscribe(0, false, vec!["sub-wanted".to_string()])
                .await?;
            while let Some(item) = stream.next().await {
                got.push(item?);
            }
            if got.len() != 1 || got[0]["type"] != "sub-wanted" {
                return Err(format!("type filter leaked or missed a record: {got:?}").into());
            }
            Ok(())
        },
    )
    .await;

    step(
        &mut pass,
        &mut total,
        "S18 QuerySubject (whole-row read)",
        || async {
            c.append(
                "property",
                &json!({"subject":"subj-whole","attribute":"a","value":1}),
            )
            .await?;
            c.append(
                "property",
                &json!({"subject":"subj-whole","attribute":"b","value":2}),
            )
            .await?;
            let a = c.subject("subj-whole").await?;
            if a.value != json!({"a":1,"b":2}) || a.trace.len() != 2 {
                return Err(format!("whole row wrong: {a:?}").into());
            }
            Ok(())
        },
    )
    .await;

    step(
        &mut pass,
        &mut total,
        "S20 typed entity round-trip (entity in, entity out)",
        || async {
            use serde::{Deserialize, Serialize};
            #[derive(Serialize, Deserialize, PartialEq, Debug)]
            struct Size {
                w: i64,
                h: i64,
            }
            #[derive(Serialize, Deserialize, PartialEq, Debug)]
            struct Widget {
                name: String,
                weight_g: i64,
                size: Size,
            }
            let r = c
                .append_typed(
                    "widget",
                    &Widget {
                        name: "cog".into(),
                        weight_g: BIG,
                        size: Size { w: 3, h: 4 },
                    },
                )
                .await?;
            let out: Widget = c.get_record_as(r.no, false).await?;
            if out.name != "cog" || out.weight_g != BIG || out.size != (Size { w: 3, h: 4 }) {
                return Err(format!("typed round-trip mismatch: {out:?}").into());
            }
            Ok(())
        },
    )
    .await;

    let verdict = if pass == total { "PASS" } else { "FAIL" };
    println!("CONFORMANCE {verdict} {pass}/{total}");
    if pass != total {
        std::process::exit(1);
    }
    Ok(())
}
