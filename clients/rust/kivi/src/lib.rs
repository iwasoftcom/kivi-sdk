//! kivi Rust SDK — the untrusting client for the kivi event ledger.
//!
//! The SDK constitution, enforced here and tested by the conformance suite:
//!   - an answer without a trace is UNREPRESENTABLE (`TracedAnswer::new`
//!     refuses an empty trace);
//!   - client-side verification is ON by default: `replay` re-hashes every
//!     record, checks chain linkage and gapless numbering, and verifies
//!     Ed25519 seals — a lying server or wire returns `KiviError::Verification`;
//!   - honest refusals map to a typed `KiviError` — `NotFound` is never a
//!     silent `None`;
//!   - identity: a bearer token at dial time, `login()` for kivi-user
//!     sessions, and `with_bearer()` views for per-caller credentials over
//!     one shared channel — the server decides everything, per call.
//!
//! Numbers travel as JSON strings end to end and are decoded with
//! `serde_json`, whose default `Number` holds any i64/u64 exactly (no float
//! detour) — int64 values round-trip exactly (conformance S2).

pub mod pb {
    tonic::include_proto!("kivi.v1");
}
mod verify;

pub use verify::{ChainChecker, RecordIntegrityChecker};

use futures_core::Stream;
use pb::kivi_client::KiviClient as RawKiviClient;
use serde_json::Value;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::Channel;
use tonic::{Request, Status};

/// Honest refusals, typed. `NotFound` is never a fabricated `None`.
#[derive(Debug)]
pub enum KiviError {
    NotFound(String),
    Unauthenticated(String),
    PreconditionFailed(String),
    InvalidArgument(String),
    Unavailable(String),
    RateLimited(String),
    Verification(String),
    Other(String),
}

impl std::fmt::Display for KiviError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, msg) = match self {
            KiviError::NotFound(m) => ("not found", m),
            KiviError::Unauthenticated(m) => ("unauthenticated", m),
            KiviError::PreconditionFailed(m) => ("precondition failed", m),
            KiviError::InvalidArgument(m) => ("invalid argument", m),
            KiviError::Unavailable(m) => ("unavailable", m),
            KiviError::RateLimited(m) => ("rate limited", m),
            KiviError::Verification(m) => ("verification failed — the server or the wire lied", m),
            KiviError::Other(m) => ("error", m),
        };
        write!(f, "kivi: {kind}: {msg}")
    }
}
impl std::error::Error for KiviError {}

impl From<Status> for KiviError {
    fn from(s: Status) -> Self {
        let msg = s.message().to_string();
        match s.code() {
            tonic::Code::NotFound => KiviError::NotFound(msg),
            tonic::Code::Unauthenticated => KiviError::Unauthenticated(msg),
            tonic::Code::FailedPrecondition => KiviError::PreconditionFailed(msg),
            tonic::Code::InvalidArgument => KiviError::InvalidArgument(msg),
            tonic::Code::Unavailable => KiviError::Unavailable(msg),
            tonic::Code::ResourceExhausted => KiviError::RateLimited(msg),
            _ => KiviError::Other(format!("{}: {}", s.code(), msg)),
        }
    }
}

fn json_err(e: serde_json::Error) -> KiviError {
    KiviError::Other(format!("json: {e}"))
}

/// Decode an already-fetched record's BODY into a TYPED entity `T` — the
/// "entity out" for records from `replay`, `subscribe`, `why` or
/// `get_record`. Zero extra dependency (serde).
///
///     let e: ClaimReserveChanged = kivi::body_as(&rec)?;
pub fn body_as<T: serde::de::DeserializeOwned>(rec: &Value) -> Result<T, KiviError> {
    let body = rec.get("body").cloned().unwrap_or(Value::Null);
    serde_json::from_value(body).map_err(json_err)
}

/// The proof of a write: record number, byte offset, hash.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub no: i64,
    pub offset: i64,
    pub hash: String,
}

/// Value + the events that established it + the ledger scope it was derived
/// from. Constructing one without a trace is refused — by design (the whole
/// point of the second constitutional rule above).
#[derive(Debug, Clone)]
pub struct TracedAnswer {
    pub value: Value,
    pub trace: Vec<i64>,
    pub scope: i64,
}

impl TracedAnswer {
    pub fn new(value: Value, trace: Vec<i64>, scope: i64) -> Result<Self, KiviError> {
        if trace.is_empty() {
            return Err(KiviError::Verification(
                "an answer without a trace is unrepresentable".into(),
            ));
        }
        Ok(TracedAnswer {
            value,
            trace,
            scope,
        })
    }
}

/// A whole compiled view plus its canonical digest.
#[derive(Debug, Clone)]
pub struct ViewState {
    pub state: Value,
    pub scope: i64,
    pub hash: String,
}

/// Mirrors the server's dataset-wide audit.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub ok: bool,
    pub records: i64,
    pub seals: i64,
    pub unsealed_tail: i64,
    pub torn_tail: bool,
    pub has_defect: bool,
    pub defect_no: i64,
    pub defect_reason: String,
}

/// The cheap orientation answer: last record number + head hash (no audit).
#[derive(Debug, Clone)]
pub struct Head {
    pub no: i64,
    pub hash: String,
}

/// The result of a login: the bearer token plus its honest envelope.
#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub role: String,
    pub expires_unix: i64,
}

/// One traced similarity hit: the record's address, its score, and the raw
/// receipt itself — an untraced score does not exist.
#[derive(Debug, Clone)]
pub struct SimilarHit {
    pub no: i64,
    pub score: f32,
    pub record: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct SimilarAnswer {
    pub hits: Vec<SimilarHit>,
    pub scope: i64,
    pub model: String,
}

/// One row of a paged view read: canonical key + decoded value (trace inside).
#[derive(Debug, Clone)]
pub struct ViewEntry {
    pub key: String,
    pub value: Value,
}

/// One directed, traced relation edge: source —relation→ target, set by record `no`.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub relation: String,
    pub target: String,
    pub no: i64,
}

/// A node found by a traversal, with its depth and the edge record numbers
/// along the shortest discovering path (the proof).
#[derive(Debug, Clone)]
pub struct GraphReached {
    pub node: String,
    pub depth: i64,
    pub trace: Vec<i64>,
}

/// One step of a path: `from` —relation→ `to`, via edge record `no`.
#[derive(Debug, Clone)]
pub struct GraphHop {
    pub from: String,
    pub relation: String,
    pub to: String,
    pub no: i64,
}

/// One page of a keyset walk over a compiled view. `next_key` empty = done.
/// `scope`/`hash` stamp the SNAPSHOT: pass `scope` back as `as_of` and every
/// later page keeps describing that same moment.
#[derive(Debug, Clone)]
pub struct ViewPage {
    pub entries: Vec<ViewEntry>,
    pub next_key: String,
    pub scope: i64,
    pub hash: String,
}

/// Per-call bearer credential, carried through tonic's interceptor mechanism
/// so one `Client` (one channel) can serve many callers — the credential
/// travels with the CALL, not the connection. `""` = no credential.
#[derive(Clone)]
struct BearerInterceptor {
    token: Arc<Mutex<String>>,
}

impl Interceptor for BearerInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let token = self.token.lock().unwrap().clone();
        if !token.is_empty() {
            let val = MetadataValue::try_from(format!("Bearer {token}"))
                .map_err(|_| Status::invalid_argument("bad bearer token"))?;
            req.metadata_mut().insert("authorization", val);
        }
        Ok(req)
    }
}

type Stub =
    RawKiviClient<tonic::service::interceptor::InterceptedService<Channel, BearerInterceptor>>;

/// The kivi client for Rust. Async-first (tokio). Cheap to clone: clones
/// share the underlying channel (tonic channels are already connection-pooled
/// and cloneable), and `with_bearer` gives a clone with its OWN credential.
///
/// Implementation note: the channel is kept separate from the interceptor and
/// a fresh intercepted stub is built per call from `self.token` — this is
/// what makes `with_bearer` correct: each `Client` value's OWN `token` Arc is
/// the one consulted, never a stale interceptor captured by an earlier clone.
#[derive(Clone)]
pub struct Client {
    channel: Channel,
    token: Arc<Mutex<String>>,
    pub verify_streams: bool,
}

impl Client {
    /// Connect (insecure transport; put TLS termination in front, or extend
    /// with tonic's TLS config when needed).
    pub async fn connect(addr: &str, token: impl Into<String>) -> Result<Self, KiviError> {
        let endpoint = if addr.starts_with("http") {
            addr.to_string()
        } else {
            format!("http://{addr}")
        };
        let channel = Channel::from_shared(endpoint)
            .map_err(|e| KiviError::Other(e.to_string()))?
            .connect()
            .await
            .map_err(|e| KiviError::Unavailable(e.to_string()))?;
        Ok(Client {
            channel,
            token: Arc::new(Mutex::new(token.into())),
            verify_streams: true,
        })
    }

    fn stub(&self) -> Stub {
        RawKiviClient::with_interceptor(
            self.channel.clone(),
            BearerInterceptor {
                token: self.token.clone(),
            },
        )
    }

    /// Disable client-side stream verification — only when you consciously
    /// trust the server and the wire.
    pub fn without_stream_verification(mut self) -> Self {
        self.verify_streams = false;
        self
    }

    /// Swap the bearer credential (after login or on rotation).
    pub fn set_token(&self, token: impl Into<String>) {
        *self.token.lock().unwrap() = token.into();
    }

    /// A view of this client over the SAME channel with ANOTHER identity —
    /// per-caller credentials for stateless multi-tenant frontends. Dropping
    /// a view never closes the shared channel (it is reference-counted).
    pub fn with_bearer(&self, token: impl Into<String>) -> Self {
        Client {
            channel: self.channel.clone(),
            token: Arc::new(Mutex::new(token.into())),
            verify_streams: self.verify_streams,
        }
    }

    // -- identity plane ------------------------------------------------------

    /// Authenticate as a kivi USER and install the session token on this
    /// client: from here on every call runs with that user's role and every
    /// write is receipted under their name. Security stays in ONE center —
    /// the server's identity plane; the client only carries the credential.
    pub async fn login(&self, username: &str, password: &str) -> Result<Session, KiviError> {
        let r = self
            .stub()
            .login(pb::LoginRequest {
                username: username.into(),
                password: password.into(),
            })
            .await?
            .into_inner();
        self.set_token(r.token.clone());
        Ok(Session {
            token: r.token,
            role: r.role,
            expires_unix: r.expires_unix,
        })
    }

    // -- write plane ----------------------------------------------------------

    pub async fn append(&self, event_type: &str, body: &Value) -> Result<Receipt, KiviError> {
        let r = self
            .stub()
            .append(pb::AppendRequest {
                r#type: event_type.into(),
                body_json: body.to_string(),
                ..Default::default()
            })
            .await?
            .into_inner();
        Ok(Receipt {
            no: r.no,
            offset: r.offset,
            hash: r.hash,
        })
    }

    /// Append a TYPED entity (serde `Serialize`) — the "entity in" write: you
    /// pass a struct, kivi serializes it (and re-canonicalizes server-side,
    /// so your field order never matters). Zero extra dependency: serde is
    /// already the crate's serialization framework.
    pub async fn append_typed<T: serde::Serialize>(
        &self,
        event_type: &str,
        entity: &T,
    ) -> Result<Receipt, KiviError> {
        let body = serde_json::to_value(entity).map_err(json_err)?;
        self.append(event_type, &body).await
    }

    pub async fn append_private(
        &self,
        event_type: &str,
        body: &Value,
    ) -> Result<Receipt, KiviError> {
        let r = self
            .stub()
            .append_private(pb::AppendRequest {
                r#type: event_type.into(),
                body_json: body.to_string(),
                ..Default::default()
            })
            .await?
            .into_inner();
        Ok(Receipt {
            no: r.no,
            offset: r.offset,
            hash: r.hash,
        })
    }

    /// Append a private (per-record encrypted) TYPED entity — the "entity in"
    /// for erasable bodies. Pass a struct, not a hand-written JSON string;
    /// parity with [`append_typed`](Self::append_typed).
    pub async fn append_private_typed<T: serde::Serialize>(
        &self,
        event_type: &str,
        entity: &T,
    ) -> Result<Receipt, KiviError> {
        let body = serde_json::to_value(entity).map_err(json_err)?;
        self.append_private(event_type, &body).await
    }

    /// Crypto-erase a private record. A reason is mandatory — even
    /// forgetting leaves a trace.
    pub async fn erase(&self, no: i64, reason: &str) -> Result<Receipt, KiviError> {
        let r = self
            .stub()
            .erase(pb::EraseRequest {
                no,
                reason: reason.into(),
            })
            .await?
            .into_inner();
        Ok(Receipt {
            no: r.no,
            offset: r.offset,
            hash: r.hash,
        })
    }

    pub async fn seal(&self) -> Result<Receipt, KiviError> {
        let r = self.stub().seal(pb::Empty {}).await?.into_inner();
        Ok(Receipt {
            no: r.no,
            offset: r.offset,
            hash: r.hash,
        })
    }

    // -- read plane -----------------------------------------------------------

    pub async fn verify_ledger(&self) -> Result<VerifyReport, KiviError> {
        let r = self.stub().verify(pb::Empty {}).await?.into_inner();
        Ok(VerifyReport {
            ok: r.ok,
            records: r.records,
            seals: r.seals,
            unsealed_tail: r.unsealed_tail,
            torn_tail: r.torn_tail,
            has_defect: r.has_defect,
            defect_no: r.defect_no,
            defect_reason: r.defect_reason,
        })
    }

    /// The cheap orientation call: last record number + head hash — no audit
    /// runs. Use it to page a tail; use `verify_ledger` when integrity itself
    /// is the question.
    pub async fn head(&self) -> Result<Head, KiviError> {
        let r = self.stub().head(pb::Empty {}).await?.into_inner();
        Ok(Head {
            no: r.head_no,
            hash: r.head_hash,
        })
    }

    /// Traced read of the CURRENT value.
    pub async fn table(&self, subject: &str, attribute: &str) -> Result<TracedAnswer, KiviError> {
        self.table_at(subject, attribute, None).await
    }

    /// Time travel: the answer AS OF record `as_of` — "what did we know when
    /// the ledger stopped there?" (`None` = the current head).
    pub async fn table_at(
        &self,
        subject: &str,
        attribute: &str,
        as_of: Option<i64>,
    ) -> Result<TracedAnswer, KiviError> {
        let r = self
            .stub()
            .query_table(pb::TableRequest {
                subject: subject.into(),
                attribute: attribute.into(),
                as_of,
            })
            .await?
            .into_inner();
        let value: Value = serde_json::from_str(&r.value_json).map_err(json_err)?;
        TracedAnswer::new(value, r.trace, r.scope)
    }

    /// `table`'s whole-row sibling (G15): every attribute known about one
    /// subject, plus the union of every event that established one of them —
    /// "what do we know about X?" without knowing which attributes to ask
    /// for first.
    pub async fn subject(&self, subject: &str) -> Result<TracedAnswer, KiviError> {
        self.subject_at(subject, None).await
    }

    /// Time travel, same contract as `table_at`.
    pub async fn subject_at(
        &self,
        subject: &str,
        as_of: Option<i64>,
    ) -> Result<TracedAnswer, KiviError> {
        let r = self
            .stub()
            .query_subject(pb::SubjectRequest {
                subject: subject.into(),
                as_of,
            })
            .await?
            .into_inner();
        let value: Value = serde_json::from_str(&r.value_json).map_err(json_err)?;
        TracedAnswer::new(value, r.trace, r.scope)
    }

    /// Fetch the receipt records behind a trace — the raw immutable events.
    pub async fn why(&self, trace: &[i64]) -> Result<Vec<Value>, KiviError> {
        let r = self
            .stub()
            .why(pb::WhyRequest {
                trace: trace.to_vec(),
            })
            .await?
            .into_inner();
        r.records
            .into_iter()
            .map(|x| serde_json::from_str(&x.record_json).map_err(json_err))
            .collect()
    }

    /// One record by number (`unseal=true` opens a private body if the key
    /// still exists).
    pub async fn get_record(&self, no: i64, unseal: bool) -> Result<Value, KiviError> {
        let r = self
            .stub()
            .get_record(pb::GetRecordRequest { no, unseal })
            .await?
            .into_inner();
        serde_json::from_str(&r.record_json).map_err(json_err)
    }

    /// Fetch record `no` and decode its body into a TYPED entity `T` — the
    /// "entity out" read. Zero extra dependency (serde).
    pub async fn get_record_as<T: serde::de::DeserializeOwned>(
        &self,
        no: i64,
        unseal: bool,
    ) -> Result<T, KiviError> {
        body_as(&self.get_record(no, unseal).await?)
    }

    pub async fn graph(&self) -> Result<ViewState, KiviError> {
        let r = self.stub().query_graph(pb::Empty {}).await?.into_inner();
        Ok(ViewState {
            state: serde_json::from_str(&r.state_json).map_err(json_err)?,
            scope: r.scope,
            hash: r.hash,
        })
    }

    /// Direct outgoing relation edges of `node`. `as_of` pins the graph to a
    /// record number (`None` = current). Returns `(edges, truncated)`.
    pub async fn graph_neighbors(
        &self,
        node: &str,
        as_of: Option<i64>,
    ) -> Result<(Vec<GraphEdge>, bool), KiviError> {
        let r = self
            .stub()
            .graph_neighbors(pb::GraphNeighborsRequest {
                node: node.into(),
                as_of,
            })
            .await?
            .into_inner();
        let edges = r
            .edges
            .into_iter()
            .map(|e| GraphEdge {
                relation: e.relation,
                target: e.target,
                no: e.no,
            })
            .collect();
        Ok((edges, r.truncated))
    }

    /// Every node reachable from `node` within `depth` hops (0 = server default),
    /// each with its edge trace. `limit` 0 = server default. Returns
    /// `(nodes, truncated)`.
    pub async fn graph_reachable(
        &self,
        node: &str,
        depth: i64,
        limit: i64,
        as_of: Option<i64>,
    ) -> Result<(Vec<GraphReached>, bool), KiviError> {
        let r = self
            .stub()
            .graph_reachable(pb::GraphReachableRequest {
                node: node.into(),
                depth,
                limit,
                as_of,
            })
            .await?
            .into_inner();
        let nodes = r
            .nodes
            .into_iter()
            .map(|n| GraphReached {
                node: n.node,
                depth: n.depth,
                trace: n.trace,
            })
            .collect();
        Ok((nodes, r.truncated))
    }

    /// Shortest edge path from `from` to `to` within `depth` hops (0 = server
    /// default). Returns `(hops, found, truncated)`.
    pub async fn graph_path(
        &self,
        from: &str,
        to: &str,
        depth: i64,
        as_of: Option<i64>,
    ) -> Result<(Vec<GraphHop>, bool, bool), KiviError> {
        let r = self
            .stub()
            .graph_path(pb::GraphPathRequest {
                from: from.into(),
                to: to.into(),
                depth,
                as_of,
            })
            .await?
            .into_inner();
        let hops = r
            .hops
            .into_iter()
            .map(|h| GraphHop {
                from: h.from,
                relation: h.relation,
                to: h.to,
                no: h.no,
            })
            .collect();
        Ok((hops, r.found, r.truncated))
    }

    pub async fn series(&self, series: &str) -> Result<ViewState, KiviError> {
        let r = self
            .stub()
            .query_series(pb::SeriesRequest {
                series: series.into(),
            })
            .await?
            .into_inner();
        Ok(ViewState {
            state: serde_json::from_str(&r.state_json).map_err(json_err)?,
            scope: r.scope,
            hash: r.hash,
        })
    }

    /// Keyset pagination over a compiled view (table|graph|series) at the
    /// current head. `limit` 0 = server default (100, capped at 1000).
    pub async fn view_page(
        &self,
        view: &str,
        after_key: &str,
        limit: i64,
    ) -> Result<ViewPage, KiviError> {
        self.view_page_at(view, after_key, limit, None).await
    }

    /// Keyset pagination PINNED to a snapshot: pass page 1's `scope` as
    /// `as_of` and every later page keeps describing that same moment, no
    /// matter what writers do in between.
    pub async fn view_page_at(
        &self,
        view: &str,
        after_key: &str,
        limit: i64,
        as_of: Option<i64>,
    ) -> Result<ViewPage, KiviError> {
        let r = self
            .stub()
            .query_view_page(pb::ViewPageRequest {
                view: view.into(),
                after_key: after_key.into(),
                limit,
                as_of,
            })
            .await?
            .into_inner();
        let mut entries = Vec::with_capacity(r.entries.len());
        for e in r.entries {
            entries.push(ViewEntry {
                key: e.key,
                value: serde_json::from_str(&e.value_json).map_err(json_err)?,
            });
        }
        Ok(ViewPage {
            entries,
            next_key: r.next_key,
            scope: r.scope,
            hash: r.hash,
        })
    }

    /// Traced semantic search: every hit is a record number + score + the
    /// raw receipt; the answer names the model and the covered scope.
    pub async fn similar(&self, query: &str, k: i64) -> Result<SimilarAnswer, KiviError> {
        let r = self
            .stub()
            .similar(pb::SimilarRequest {
                query: query.into(),
                k,
            })
            .await?
            .into_inner();
        let mut hits = Vec::with_capacity(r.hits.len());
        for h in r.hits {
            let record = if h.record_json.is_empty() {
                None
            } else {
                Some(serde_json::from_str(&h.record_json).map_err(json_err)?)
            };
            hits.push(SimilarHit {
                no: h.no,
                score: h.score,
                record,
            });
        }
        Ok(SimilarAnswer {
            hits,
            scope: r.scope,
            model: r.model,
        })
    }

    // -- streams: verified replay (the untrusting client) ----------------------

    /// Stream records from `start`; `follow=true` never ends (CDC). With
    /// verification on (the client default), every record is re-hashed,
    /// chain and numbering are checked and seals are Ed25519-verified
    /// CLIENT-SIDE before you see it — a lying stream yields
    /// `KiviError::Verification`.
    pub async fn replay(
        &self,
        start: i64,
        follow: bool,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Value, KiviError>> + Send>>, KiviError> {
        let verify = self.verify_streams;
        let inbound = self
            .stub()
            .replay(pb::ReplayRequest {
                from: start,
                follow,
            })
            .await?
            .into_inner();
        let mut checker = ChainChecker::new(true);
        let out = async_stream::try_stream! {
            tokio::pin!(inbound);
            use tokio_stream::StreamExt;
            while let Some(msg) = inbound.next().await {
                let reply = msg.map_err(KiviError::from)?;
                if verify {
                    checker.check(&reply.record_json)?;
                }
                let v: Value = serde_json::from_str(&reply.record_json).map_err(json_err)?;
                yield v;
            }
        };
        Ok(Box::pin(out))
    }

    /// `replay`'s type-filtered sibling (G14): the server drops non-matching
    /// records before they cross the wire, so a consumer that only cares
    /// about one or two event types never receives (and discards)
    /// everything else.
    ///
    /// Honesty note: because the server may drop records, this does NOT
    /// carry `replay`'s gapless/chain-adjacency guarantee. With
    /// verification on (the client default), each delivered record's OWN
    /// hash is recomputed (and its Ed25519 signature checked, for
    /// kivi.seal records) — proving "byte-exact what the ledger holds" —
    /// but numbering gaps and prev_hash discontinuities are EXPECTED and
    /// never yield `KiviError::Verification`. A consumer that must prove
    /// it received every record uses `replay` instead.
    pub async fn subscribe(
        &self,
        start: i64,
        follow: bool,
        types: Vec<String>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Value, KiviError>> + Send>>, KiviError> {
        let verify = self.verify_streams;
        let inbound = self
            .stub()
            .subscribe(pb::SubscribeRequest {
                from: start,
                follow,
                types,
            })
            .await?
            .into_inner();
        let mut checker = RecordIntegrityChecker::new(true);
        let out = async_stream::try_stream! {
            tokio::pin!(inbound);
            use tokio_stream::StreamExt;
            while let Some(msg) = inbound.next().await {
                let reply = msg.map_err(KiviError::from)?;
                if verify {
                    checker.check(&reply.record_json)?;
                }
                let v: Value = serde_json::from_str(&reply.record_json).map_err(json_err)?;
                yield v;
            }
        };
        Ok(Box::pin(out))
    }
}
