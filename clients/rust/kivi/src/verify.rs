//! Client-side verification (K3) — the untrusting client, Rust edition.
//!
//! Byte-fidelity strategy: the server already sends CANONICAL JSON (sorted
//! keys, compact, raw UTF-8). Instead of re-serializing (and risking a
//! mismatch from a different JSON library's formatting choices), the
//! canonical CORE is recovered by SPLICING the raw bytes: a tiny scanner
//! records the byte span of each top-level member, and the core is the
//! record minus the `hash` and `sig` spans. What gets hashed is
//! byte-identical to what the writer hashed (same technique as the JVM SDK).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ops::Range;

use crate::KiviError;

const SEAL_TYPE: &str = "kivi.seal";

/// One top-level member's byte span within a canonical record: `from` points
/// at the `{` or the preceding `,`; `to` is exclusive, just past the value.
struct TopLevel<'a> {
    raw: &'a [u8],
    spans: BTreeMap<String, Range<usize>>,
}

impl<'a> TopLevel<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, KiviError> {
        let fail = |msg: &str| KiviError::Verification(format!("malformed record: {msg}"));
        if raw.is_empty() || raw[0] != b'{' {
            return Err(fail("not an object"));
        }
        let mut spans = BTreeMap::new();
        let mut i = 1usize;
        while i < raw.len() && raw[i] != b'}' {
            let member_start = i - 1; // the '{' or the ',' before this member
            if raw[i] != b'"' {
                return Err(fail("expected a key"));
            }
            let key_end = scan_string(raw, i)?;
            let key = String::from_utf8_lossy(&raw[i + 1..key_end - 1]).into_owned();
            i = key_end;
            if i >= raw.len() || raw[i] != b':' {
                return Err(fail("expected ':'"));
            }
            i += 1;
            i = scan_value(raw, i)?;
            spans.insert(key, member_start..i);
            if i < raw.len() && raw[i] == b',' {
                i += 1;
            }
        }
        Ok(TopLevel { raw, spans })
    }

    /// The canonical core: the record bytes minus the `sig` and `hash` members.
    fn core_bytes(&self) -> Result<Vec<u8>, KiviError> {
        let mut drop: Vec<&Range<usize>> = Vec::with_capacity(2);
        for key in ["sig", "hash"] {
            drop.push(
                self.spans
                    .get(key)
                    .ok_or_else(|| KiviError::Verification(format!("record missing {key}")))?,
            );
        }
        drop.sort_by_key(|r| r.start);
        let mut out = Vec::with_capacity(self.raw.len());
        let mut pos = 0usize;
        for r in drop {
            out.extend_from_slice(&self.raw[pos..r.start]);
            pos = r.end;
        }
        out.extend_from_slice(&self.raw[pos..]);
        Ok(out)
    }

    fn string_field(&self, key: &str) -> Option<String> {
        let r = self.spans.get(key)?;
        let member = std::str::from_utf8(&self.raw[r.start..r.end]).ok()?;
        let v = &member[member.find(':')? + 1..];
        Some(if let Some(s) = v.strip_prefix('"') {
            s.strip_suffix('"').unwrap_or(s).to_string()
        } else {
            v.to_string()
        })
    }

    fn int_field(&self, key: &str) -> Option<i64> {
        self.string_field(key)?.parse().ok()
    }

    fn raw_field(&self, key: &str) -> Option<&'a [u8]> {
        let r = self.spans.get(key)?;
        let member = &self.raw[r.start..r.end];
        let colon = member.iter().position(|&b| b == b':')?;
        Some(&member[colon + 1..])
    }
}

fn scan_string(raw: &[u8], from: usize) -> Result<usize, KiviError> {
    let mut i = from + 1;
    while i < raw.len() {
        match raw[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err(KiviError::Verification("unterminated string".into()))
}

fn scan_value(raw: &[u8], from: usize) -> Result<usize, KiviError> {
    let mut i = from;
    match raw.get(i) {
        Some(b'"') => scan_string(raw, i),
        Some(b'{') | Some(b'[') => {
            let mut depth = 0i32;
            while i < raw.len() {
                match raw[i] {
                    b'"' => {
                        i = scan_string(raw, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Err(KiviError::Verification("unterminated container".into()))
        }
        Some(_) => {
            while i < raw.len() && raw[i] != b',' && raw[i] != b'}' {
                i += 1;
            }
            Ok(i)
        }
        None => Err(KiviError::Verification("value out of bounds".into())),
    }
}

fn ed25519_verify(sig: &[u8], msg: &[u8], pk: &[u8]) -> bool {
    let Ok(pk32): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(sig64): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk32) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&sig64)).is_ok()
}

/// One record's OWN hash (and Ed25519 seal signature, for kivi.seal records)
/// — the part ChainChecker and RecordIntegrityChecker share, regardless of
/// whether gaps between records are expected. Returns the record's number.
fn check_record_integrity(top: &TopLevel, check_seals: bool) -> Result<i64, KiviError> {
    let no = top
        .int_field("no")
        .ok_or_else(|| KiviError::Verification("record without a number".into()))?;
    let digest = hex::encode(Sha256::digest(top.core_bytes()?));
    if Some(digest) != top.string_field("hash") {
        return Err(KiviError::Verification(format!(
            "record {no}: hash mismatch — content altered in flight or at rest"
        )));
    }
    if check_seals && top.string_field("type").as_deref() == Some(SEAL_TYPE) {
        let body = top
            .raw_field("body")
            .ok_or_else(|| KiviError::Verification(format!("seal {no}: no body")))?;
        let body_str = std::str::from_utf8(body).unwrap_or("");
        let pk_hex = extract_pk(body_str)
            .ok_or_else(|| KiviError::Verification(format!("seal {no}: no pk")))?;
        let sig_hex = top
            .string_field("sig")
            .ok_or_else(|| KiviError::Verification(format!("seal {no}: unsigned")))?;
        let pk = hex::decode(&pk_hex)
            .map_err(|_| KiviError::Verification(format!("seal {no}: bad pk hex")))?;
        let sig = hex::decode(&sig_hex)
            .map_err(|_| KiviError::Verification(format!("seal {no}: bad sig hex")))?;
        if !ed25519_verify(&sig, &top.core_bytes()?, &pk) {
            return Err(KiviError::Verification(format!(
                "seal {no}: Ed25519 signature invalid"
            )));
        }
    }
    Ok(no)
}

/// Verifies a replay stream record by record: hash, gapless numbering, chain
/// linkage and (optionally) Ed25519 seals. A lying stream returns
/// `KiviError::Verification` — the server or the wire cannot get away with it.
pub struct ChainChecker {
    check_seals: bool,
    prev_hash: Option<String>,
    next_no: Option<i64>,
}

impl ChainChecker {
    pub fn new(check_seals: bool) -> Self {
        ChainChecker {
            check_seals,
            prev_hash: None,
            next_no: None,
        }
    }

    pub fn check(&mut self, record_json: &str) -> Result<(), KiviError> {
        let raw = record_json.as_bytes();
        let top = TopLevel::parse(raw)?;
        let no = check_record_integrity(&top, self.check_seals)?;
        if let Some(want) = self.next_no {
            if no != want {
                return Err(KiviError::Verification(format!(
                    "record numbering broken: expected {want}, got {no}"
                )));
            }
        }
        if let Some(want) = &self.prev_hash {
            if top.string_field("prev_hash").as_deref() != Some(want.as_str()) {
                return Err(KiviError::Verification(format!(
                    "record {no}: chain linkage broken"
                )));
            }
        }
        self.prev_hash = top.string_field("hash");
        self.next_no = Some(no + 1);
        Ok(())
    }
}

/// Subscribe's checker (G14): each record's OWN hash/signature is verified,
/// but — unlike ChainChecker — numbering gaps and prev_hash discontinuities
/// are EXPECTED (server-side type filtering causes them by design) and are
/// never treated as tampering.
pub struct RecordIntegrityChecker {
    check_seals: bool,
}

impl RecordIntegrityChecker {
    pub fn new(check_seals: bool) -> Self {
        RecordIntegrityChecker { check_seals }
    }

    pub fn check(&mut self, record_json: &str) -> Result<(), KiviError> {
        let top = TopLevel::parse(record_json.as_bytes())?;
        check_record_integrity(&top, self.check_seals)?;
        Ok(())
    }
}

/// Cheap extraction of `"pk":"<64 hex chars>"` from a raw body span — avoids
/// pulling in a JSON parser just for one field inside an already-scanned span.
fn extract_pk(body: &str) -> Option<String> {
    let marker = "\"pk\":\"";
    let i = body.find(marker)? + marker.len();
    let rest = &body[i..];
    let end = rest.find('"')?;
    let candidate = &rest[..end];
    if candidate.len() == 64 && candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(candidate.to_string())
    } else {
        None
    }
}
