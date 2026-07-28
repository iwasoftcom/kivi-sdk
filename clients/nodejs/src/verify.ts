// Client-side verification (K3) — the untrusting client, Node.js edition.
//
// Byte-fidelity strategy: the server already sends CANONICAL JSON (sorted
// keys, compact, raw UTF-8). Instead of re-serializing through JSON.parse +
// JSON.stringify (which would also silently truncate int64 precision to a
// float — exactly what conformance S2 exists to catch), the canonical CORE
// is recovered by SPLICING the raw bytes: a tiny scanner records the byte
// span of each top-level member, and the core is the record minus the `hash`
// and `sig` spans. What gets hashed is byte-identical to what the writer
// hashed (the same technique the JVM and Rust SDKs use).

import * as crypto from "node:crypto";

export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

const SEAL_TYPE = "kivi.seal";

/** Byte span [from, to) of one top-level member within a canonical record. */
type Span = [number, number];

class TopLevel {
  private raw: Buffer;
  private spans = new Map<string, Span>();

  constructor(raw: Buffer) {
    this.raw = raw;
    if (raw.length === 0 || raw[0] !== 0x7b /* '{' */) {
      throw new VerificationError("malformed record: not an object");
    }
    let i = 1;
    while (i < raw.length && raw[i] !== 0x7d /* '}' */) {
      const memberStart = i - 1; // the '{' or the ',' before this member
      if (raw[i] !== 0x22 /* '"' */) {
        throw new VerificationError("malformed record: expected a key");
      }
      const keyEnd = this.scanString(i);
      const key = raw.toString("utf8", i + 1, keyEnd - 1);
      i = keyEnd;
      if (raw[i] !== 0x3a /* ':' */) {
        throw new VerificationError("malformed record: expected ':'");
      }
      i++;
      i = this.scanValue(i);
      this.spans.set(key, [memberStart, i]);
      if (raw[i] === 0x2c /* ',' */) i++;
    }
  }

  private scanString(from: number): number {
    let i = from + 1;
    while (i < this.raw.length) {
      if (this.raw[i] === 0x5c /* backslash */) i += 2;
      else if (this.raw[i] === 0x22 /* '"' */) return i + 1;
      else i++;
    }
    throw new VerificationError("malformed record: unterminated string");
  }

  private scanValue(from: number): number {
    let i = from;
    const c = this.raw[i];
    if (c === 0x22 /* '"' */) return this.scanString(i);
    if (c === 0x7b || c === 0x5b /* '{' or '[' */) {
      let depth = 0;
      while (i < this.raw.length) {
        const b = this.raw[i];
        if (b === 0x22) {
          i = this.scanString(i);
          continue;
        }
        if (b === 0x7b || b === 0x5b) depth++;
        else if (b === 0x7d || b === 0x5d) {
          depth--;
          if (depth === 0) return i + 1;
        }
        i++;
      }
      throw new VerificationError("malformed record: unterminated container");
    }
    // number / true / false / null
    while (i < this.raw.length && this.raw[i] !== 0x2c && this.raw[i] !== 0x7d) i++;
    return i;
  }

  /** The canonical core: the record bytes minus the `sig` and `hash` members. */
  coreBytes(): Buffer {
    const sig = this.spans.get("sig");
    const hash = this.spans.get("hash");
    if (!sig || !hash) {
      throw new VerificationError("record missing sig or hash");
    }
    const drop = [sig, hash].sort((a, b) => a[0] - b[0]);
    const parts: Buffer[] = [];
    let pos = 0;
    for (const [from, to] of drop) {
      parts.push(this.raw.subarray(pos, from));
      pos = to;
    }
    parts.push(this.raw.subarray(pos));
    return Buffer.concat(parts);
  }

  stringField(key: string): string | undefined {
    const span = this.spans.get(key);
    if (!span) return undefined;
    const member = this.raw.toString("utf8", span[0], span[1]);
    const v = member.slice(member.indexOf(":") + 1);
    return v.startsWith('"') ? v.slice(1, -1) : v;
  }

  intField(key: string): number | undefined {
    const v = this.stringField(key);
    return v === undefined ? undefined : Number(v);
  }

  rawField(key: string): string | undefined {
    const span = this.spans.get(key);
    if (!span) return undefined;
    const member = this.raw.toString("utf8", span[0], span[1]);
    return member.slice(member.indexOf(":") + 1);
  }
}

// Fixed 12-byte SPKI DER prefix for a raw 32-byte Ed25519 public key
// (SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING }); the well-known
// wrapping every ecosystem uses to hand Node's WebCrypto-derived `crypto`
// module a raw key without an external dependency.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519Verify(sig: Buffer, msg: Buffer, pk: Buffer): boolean {
  if (sig.length !== 64 || pk.length !== 32) return false;
  try {
    const der = Buffer.concat([ED25519_SPKI_PREFIX, pk]);
    const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    return crypto.verify(null, msg, key, sig);
  } catch {
    return false;
  }
}

/** One record's OWN hash (and Ed25519 seal signature, for kivi.seal records)
 * — the part ChainChecker and RecordIntegrityChecker share, regardless of
 * whether gaps between records are expected. Returns the record's number. */
function checkRecordIntegrity(top: TopLevel, checkSeals: boolean): number {
  const no = top.intField("no");
  if (no === undefined) {
    throw new VerificationError("record without a number");
  }
  const digest = crypto.createHash("sha256").update(top.coreBytes()).digest("hex");
  if (digest !== top.stringField("hash")) {
    throw new VerificationError(
      `record ${no}: hash mismatch — content altered in flight or at rest`,
    );
  }
  if (checkSeals && top.stringField("type") === SEAL_TYPE) {
    const body = top.rawField("body");
    if (!body) throw new VerificationError(`seal ${no}: no body`);
    const pkMatch = /"pk":"([0-9a-f]{64})"/.exec(body);
    if (!pkMatch) throw new VerificationError(`seal ${no}: no pk`);
    const sigHex = top.stringField("sig");
    if (!sigHex) throw new VerificationError(`seal ${no}: unsigned`);
    const sig = Buffer.from(sigHex, "hex");
    const pk = Buffer.from(pkMatch[1], "hex");
    if (!ed25519Verify(sig, top.coreBytes(), pk)) {
      throw new VerificationError(`seal ${no}: Ed25519 signature invalid`);
    }
  }
  return no;
}

/**
 * Verifies a replay stream record by record: hash, gapless numbering, chain
 * linkage and (optionally) Ed25519 seals. A lying stream throws
 * VerificationError — the server or the wire cannot get away with it.
 */
export class ChainChecker {
  private checkSeals: boolean;
  private prevHash: string | undefined;
  private nextNo: number | undefined;

  constructor(checkSeals = true) {
    this.checkSeals = checkSeals;
  }

  check(recordJson: string): void {
    const raw = Buffer.from(recordJson, "utf8");
    const top = new TopLevel(raw);
    const no = checkRecordIntegrity(top, this.checkSeals);
    if (this.nextNo !== undefined && no !== this.nextNo) {
      throw new VerificationError(
        `record numbering broken: expected ${this.nextNo}, got ${no}`,
      );
    }
    if (this.prevHash !== undefined && top.stringField("prev_hash") !== this.prevHash) {
      throw new VerificationError(`record ${no}: chain linkage broken`);
    }
    this.prevHash = top.stringField("hash");
    this.nextNo = no + 1;
  }
}

/** Subscribe's checker (G14): each record's OWN hash/signature is verified,
 * but — unlike ChainChecker — numbering gaps and prev_hash discontinuities
 * are EXPECTED (server-side type filtering causes them by design) and are
 * never treated as tampering. */
export class RecordIntegrityChecker {
  private checkSeals: boolean;

  constructor(checkSeals = true) {
    this.checkSeals = checkSeals;
  }

  check(recordJson: string): void {
    const raw = Buffer.from(recordJson, "utf8");
    checkRecordIntegrity(new TopLevel(raw), this.checkSeals);
  }
}
