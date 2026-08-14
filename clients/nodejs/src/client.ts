// kivi Node.js SDK — the untrusting client for the kivi event ledger
// (TypeScript, compiled to CommonJS; runs on plain `node`, no ts-node needed).
//
// The SDK constitution, enforced here and tested by the conformance suite:
//   - an answer without a trace is UNREPRESENTABLE (constructing one with an
//     empty trace throws);
//   - client-side verification is ON by default: replay() re-hashes every
//     record, checks chain linkage and gapless numbering, and verifies
//     Ed25519 seals — a lying server or wire throws VerificationError;
//   - honest refusals map to typed errors — a missing cell never resolves
//     to a fabricated null;
//   - identity: a bearer token at construction, login() for kivi-user
//     sessions, and withBearer() views for per-caller credentials over one
//     shared channel — the server decides everything, per call.
//
// int64 fidelity (conformance S2): `TracedAnswer.valueJson` is the RAW JSON
// text, not parsed — JSON.parse would silently truncate integers beyond
// 2^53 to a double, exactly the failure this guards against (the same
// choice the Kotlin and .NET SDKs make). Use `JSON.parse` yourself for the
// common case, or a BigInt-aware parser when an exact int64 matters.

import * as fs from "node:fs";
import * as path from "node:path";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

// JSON.rawJSON (Node 21+/V8 12.6+) lets JSON.stringify embed an exact,
// unquoted number token verbatim — the only way to serialize a BigInt
// without either throwing (JSON.stringify's default) or round-tripping it
// through an imprecise `number` first. TypeScript's bundled lib types don't
// carry this declaration yet even at ESNext (checked: TS 5.9), so it is
// declared here rather than waiting on the compiler.
declare global {
  interface JSON {
    rawJSON(value: string | number): { toJSON(): string };
  }
}

import { ChainChecker, RecordIntegrityChecker, VerificationError } from "./verify";
import { parseJson } from "./json";
import { wrapGrpcError } from "./errors";

/** Decode an already-fetched record's BODY into a typed shape T — the "entity
 * out" for records from replay/subscribe/why/getRecord. TypeScript types are
 * compile-time only, so this is a cast over the parsed (int64-safe) body; it
 * gives you IDE typing and autocomplete without a runtime schema library. */
export function bodyAs<T>(recordJson: string): T {
  const rec = parseJson(recordJson) as { body: unknown };
  return rec.body as T;
}

export { VerificationError, ChainChecker, RecordIntegrityChecker } from "./verify";
export {
  KiviError,
  NotFoundError,
  UnauthenticatedError,
  PreconditionFailedError,
  InvalidArgumentError,
  UnavailableError,
  RateLimitedError,
} from "./errors";

/** Locate kivi.proto. In the published package it is bundled at the package
 * root (next to dist/); in the repo it lives at api/kivi.proto, found by
 * walking up. Both cases are covered so the package works standalone. */
function findProto(): string {
  const bundled = path.join(__dirname, "..", "kivi.proto"); // published: <pkg>/kivi.proto, dist/ is __dirname
  if (fs.existsSync(bundled)) return bundled;
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, "api", "kivi.proto");
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("cannot locate kivi.proto (looked for a bundled copy and api/kivi.proto above " + __dirname + ")");
}

const packageDef = protoLoader.loadSync(findProto(), {
  keepCase: false,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});
const proto = grpc.loadPackageDefinition(packageDef) as any;
const KiviServiceCtor = proto.kivi.v1.Kivi as grpc.ServiceClientConstructor;

function call<TReq, TRes>(
  client: grpc.Client,
  method: string,
  req: TReq,
  meta: grpc.Metadata,
): Promise<TRes> {
  return new Promise((resolve, reject) => {
    (client as any)[method](req, meta, (err: grpc.ServiceError | null, res: TRes) => {
      if (err) reject(wrapGrpcError(err));
      else resolve(res);
    });
  });
}

/** JSON.stringify with one fix: a `bigint` in the body serializes as the
 * exact unquoted integer it is (via JSON.rawJSON), never through
 * JSON.stringify's default behavior of THROWING on bigint, and never by a
 * caller having to pre-round it into an imprecise `number` first. Values
 * that don't fit a safe `number` (matching parseJson's own read-side rule)
 * should be passed as `bigint` for this exact reason. */
function stringifyBody(body: unknown): string {
  return JSON.stringify(body, (_key, value) =>
    typeof value === "bigint" ? JSON.rawJSON(value.toString()) : value,
  );
}

export interface Receipt {
  no: number;
  offset: number;
  hash: string;
}

/** Value + the events that established it + the ledger scope it was derived
 * from. `valueJson` is the raw JSON text (see the module doc on int64
 * fidelity). Constructing one without a trace throws — by design. */
export class TracedAnswer {
  readonly valueJson: string;
  readonly trace: number[];
  readonly scope: number;

  constructor(valueJson: string, trace: number[], scope: number) {
    if (trace.length === 0) {
      throw new VerificationError("an answer without a trace is unrepresentable");
    }
    this.valueJson = valueJson;
    this.trace = trace;
    this.scope = scope;
  }

  /** Convenience: JSON.parse the value (loses int64 precision beyond 2^53 —
   * use valueJson directly when exactness matters, e.g. via a BigInt parser). */
  value(): unknown {
    return JSON.parse(this.valueJson);
  }
}

export interface ViewState {
  stateJson: string;
  scope: number;
  hash: string;
}

export interface VerifyReport {
  ok: boolean;
  records: number;
  seals: number;
  unsealedTail: number;
  tornTail: boolean;
  hasDefect: boolean;
  defectNo: number;
  defectReason: string;
}

export interface Head {
  no: number;
  hash: string;
}

/** The result of a login: the bearer token plus its honest envelope. */
export interface Session {
  token: string;
  role: string;
  expiresUnix: number;
}

/** One traced similarity hit: the record's address, its score, and the raw
 * receipt itself (JSON text) — an untraced score does not exist. */
export interface SimilarHit {
  no: number;
  score: number;
  recordJson: string;
}

export interface SimilarAnswer {
  hits: SimilarHit[];
  scope: number;
  model: string;
}

/** One row of a paged view read: canonical key + that entry's JSON text. */
export interface ViewEntry {
  key: string;
  valueJson: string;
}

/** One page of a keyset walk over a compiled view. nextKey === "" means
 * done. scope/hash stamp the SNAPSHOT: pass scope back as asOf and every
 * later page keeps describing that same moment. */
export interface ViewPage {
  entries: ViewEntry[];
  nextKey: string;
  scope: number;
  hash: string;
}

/** One directed, traced relation: source —relation→ target, set by record `no`. */
export interface GraphEdge {
  relation: string;
  target: string;
  no: number;
}

/** A node found by a traversal, with its depth and the edge record numbers
 * along the shortest discovering path (the proof). */
export interface GraphReached {
  node: string;
  depth: number;
  trace: number[];
}

/** One step of a path: from —relation→ to, via edge record `no`. */
export interface GraphHop {
  from: string;
  relation: string;
  to: string;
  no: number;
}

export interface ClientOptions {
  token?: string;
  /** Client-side stream verification; default true (the untrusting client). */
  verify?: boolean;
  credentials?: grpc.ChannelCredentials;
}

/**
 * The kivi client for Node.js. Backed by @grpc/grpc-js. Cheap to derive:
 * `withBearer` returns a view over the SAME underlying gRPC client with its
 * OWN credential — one connection, many callers, exactly like the other
 * SDKs' per-call identity story.
 */
export class KiviClient {
  private grpcClient: grpc.Client;
  private token: string;
  readonly verifyStreams: boolean;
  private ownsClient: boolean;

  constructor(addr: string, options: ClientOptions = {}) {
    this.grpcClient = new KiviServiceCtor(
      addr,
      options.credentials ?? grpc.credentials.createInsecure(),
    );
    this.token = options.token ?? "";
    this.verifyStreams = options.verify ?? true;
    this.ownsClient = true;
  }

  private static fromShared(
    grpcClient: grpc.Client,
    token: string,
    verify: boolean,
  ): KiviClient {
    const c = Object.create(KiviClient.prototype) as KiviClient;
    c.grpcClient = grpcClient;
    c.token = token;
    (c as any).verifyStreams = verify;
    c.ownsClient = false;
    return c;
  }

  /** Close the underlying connection. A withBearer() view never closes the
   * shared connection it was derived from. */
  close(): void {
    if (this.ownsClient) this.grpcClient.close();
  }

  private meta(): grpc.Metadata {
    const md = new grpc.Metadata();
    if (this.token) md.set("authorization", `Bearer ${this.token}`);
    return md;
  }

  /** Swap the bearer credential (after login or on rotation). */
  setToken(token: string): void {
    this.token = token;
  }

  /** A view of this client over the SAME connection with ANOTHER identity —
   * per-caller credentials for stateless multi-tenant frontends. Closing a
   * view never closes the shared connection. */
  withBearer(token: string): KiviClient {
    return KiviClient.fromShared(this.grpcClient, token, this.verifyStreams);
  }

  // -- identity plane --------------------------------------------------------

  /** Authenticate as a kivi USER and install the session token on this
   * client: from here on every call runs with that user's role and every
   * write is receipted under their name. Security stays in ONE center — the
   * server's identity plane; the client only carries the credential. */
  async login(username: string, password: string): Promise<Session> {
    const r = await call<any, any>(
      this.grpcClient,
      "login",
      { username, password },
      this.meta(),
    );
    this.token = r.token;
    return { token: r.token, role: r.role, expiresUnix: Number(r.expiresUnix) };
  }

  // -- write plane ------------------------------------------------------------

  async append(type: string, body: unknown): Promise<Receipt> {
    const r = await call<any, any>(
      this.grpcClient,
      "append",
      { type, bodyJson: stringifyBody(body) },
      this.meta(),
    );
    return { no: Number(r.no), offset: Number(r.offset), hash: r.hash };
  }

  async appendPrivate(type: string, body: unknown): Promise<Receipt> {
    const r = await call<any, any>(
      this.grpcClient,
      "appendPrivate",
      { type, bodyJson: stringifyBody(body) },
      this.meta(),
    );
    return { no: Number(r.no), offset: Number(r.offset), hash: r.hash };
  }

  /** Crypto-erase a private record. A reason is mandatory — even
   * forgetting leaves a trace. */
  async erase(no: number, reason: string): Promise<Receipt> {
    const r = await call<any, any>(
      this.grpcClient,
      "erase",
      { no, reason },
      this.meta(),
    );
    return { no: Number(r.no), offset: Number(r.offset), hash: r.hash };
  }

  async seal(): Promise<Receipt> {
    const r = await call<any, any>(this.grpcClient, "seal", {}, this.meta());
    return { no: Number(r.no), offset: Number(r.offset), hash: r.hash };
  }

  // -- read plane -------------------------------------------------------------

  async verifyLedger(): Promise<VerifyReport> {
    const r = await call<any, any>(this.grpcClient, "verify", {}, this.meta());
    return {
      ok: r.ok,
      records: Number(r.records),
      seals: Number(r.seals),
      unsealedTail: Number(r.unsealedTail),
      tornTail: r.tornTail,
      hasDefect: r.hasDefect,
      defectNo: Number(r.defectNo),
      defectReason: r.defectReason,
    };
  }

  /** The cheap orientation call: (no, hash) — no audit runs. Use it to page
   * a tail; use verifyLedger when integrity itself is the question. */
  async head(): Promise<Head> {
    const r = await call<any, any>(this.grpcClient, "head", {}, this.meta());
    return { no: Number(r.headNo), hash: r.headHash };
  }

  /** Traced read of the current value; pass asOf for time travel — "what
   * did we know when the ledger stopped at record N" (omit for the head). */
  async table(subject: string, attribute: string, asOf?: number): Promise<TracedAnswer> {
    const req: any = { subject, attribute };
    if (asOf !== undefined) req.asOf = asOf;
    const r = await call<any, any>(this.grpcClient, "queryTable", req, this.meta());
    return new TracedAnswer(r.valueJson, (r.trace ?? []).map(Number), Number(r.scope));
  }

  /** table()'s whole-row sibling (G15): every attribute known about one
   * subject, plus the union of every event that established one of them —
   * "what do we know about X?" without knowing which attributes to ask for
   * first. Same traced contract as table(). */
  async subject(subject: string, asOf?: number): Promise<TracedAnswer> {
    const req: any = { subject };
    if (asOf !== undefined) req.asOf = asOf;
    const r = await call<any, any>(this.grpcClient, "querySubject", req, this.meta());
    return new TracedAnswer(r.valueJson, (r.trace ?? []).map(Number), Number(r.scope));
  }

  async why(trace: number[]): Promise<string[]> {
    const r = await call<any, any>(
      this.grpcClient,
      "why",
      { trace },
      this.meta(),
    );
    return (r.records ?? []).map((x: any) => x.recordJson);
  }

  async getRecord(no: number, unseal = false): Promise<string> {
    const r = await call<any, any>(
      this.grpcClient,
      "getRecord",
      { no, unseal },
      this.meta(),
    );
    return r.recordJson;
  }

  /** Fetch record `no` and decode its body into a typed shape T. */
  async getRecordAs<T>(no: number, unseal = false): Promise<T> {
    return bodyAs<T>(await this.getRecord(no, unseal));
  }

  async graph(): Promise<ViewState> {
    const r = await call<any, any>(this.grpcClient, "queryGraph", {}, this.meta());
    return { stateJson: r.stateJson, scope: Number(r.scope), hash: r.hash };
  }

  async series(series = ""): Promise<ViewState> {
    const r = await call<any, any>(
      this.grpcClient,
      "querySeries",
      { series },
      this.meta(),
    );
    return { stateJson: r.stateJson, scope: Number(r.scope), hash: r.hash };
  }

  /** Direct outgoing relation edges of `node`. asOf pins the graph to a record
   * number (undefined = current). */
  async graphNeighbors(
    node: string,
    asOf?: number,
  ): Promise<{ edges: GraphEdge[]; truncated: boolean }> {
    const req: any = { node };
    if (asOf !== undefined) req.asOf = asOf;
    const r = await call<any, any>(this.grpcClient, "graphNeighbors", req, this.meta());
    const edges: GraphEdge[] = (r.edges ?? []).map((e: any) => ({
      relation: e.relation,
      target: e.target,
      no: Number(e.no),
    }));
    return { edges, truncated: !!r.truncated };
  }

  /** Every node reachable from `node` within `depth` hops (0 = server default),
   * each with its edge trace. limit 0 = server default. */
  async graphReachable(
    node: string,
    depth = 0,
    limit = 0,
    asOf?: number,
  ): Promise<{ nodes: GraphReached[]; truncated: boolean }> {
    const req: any = { node, depth, limit };
    if (asOf !== undefined) req.asOf = asOf;
    const r = await call<any, any>(this.grpcClient, "graphReachable", req, this.meta());
    const nodes: GraphReached[] = (r.nodes ?? []).map((n: any) => ({
      node: n.node,
      depth: Number(n.depth),
      trace: (n.trace ?? []).map((x: any) => Number(x)),
    }));
    return { nodes, truncated: !!r.truncated };
  }

  /** Shortest edge path from `from` to `to` within `depth` hops (0 = server
   * default). found=false when none exists inside the bound. */
  async graphPath(
    from: string,
    to: string,
    depth = 0,
    asOf?: number,
  ): Promise<{ hops: GraphHop[]; found: boolean; truncated: boolean }> {
    const req: any = { from, to, depth };
    if (asOf !== undefined) req.asOf = asOf;
    const r = await call<any, any>(this.grpcClient, "graphPath", req, this.meta());
    const hops: GraphHop[] = (r.hops ?? []).map((h: any) => ({
      from: h.from,
      relation: h.relation,
      to: h.to,
      no: Number(h.no),
    }));
    return { hops, found: !!r.found, truncated: !!r.truncated };
  }

  /** Keyset pagination over a compiled view (table|graph|series). Pass
   * asOf = an earlier page's scope to pin the whole walk to one snapshot —
   * writers cannot smear it. limit 0 = server default (100, capped 1000). */
  async viewPage(
    view: string,
    afterKey = "",
    limit = 0,
    asOf?: number,
  ): Promise<ViewPage> {
    const req: any = { view, afterKey, limit };
    if (asOf !== undefined) req.asOf = asOf;
    const r = await call<any, any>(this.grpcClient, "queryViewPage", req, this.meta());
    const entries: ViewEntry[] = (r.entries ?? []).map((e: any) => ({
      key: e.key,
      valueJson: e.valueJson,
    }));
    return { entries, nextKey: r.nextKey, scope: Number(r.scope), hash: r.hash };
  }

  /** Traced semantic search: every hit is a record number + score + the raw
   * receipt; the answer names the model and the covered scope. */
  async similar(query: string, k = 5): Promise<SimilarAnswer> {
    const r = await call<any, any>(
      this.grpcClient,
      "similar",
      { query, k },
      this.meta(),
    );
    const hits: SimilarHit[] = (r.hits ?? []).map((h: any) => ({
      no: Number(h.no),
      score: h.score,
      recordJson: h.recordJson,
    }));
    return { hits, scope: Number(r.scope), model: r.model };
  }

  // -- streams: verified replay (the untrusting client) ------------------------

  /** Stream records from `start`; follow=true never ends (CDC). With
   * verification on (the default), every record is re-hashed, chain and
   * numbering are checked and seals are Ed25519-verified CLIENT-SIDE before
   * you see it — a lying stream throws VerificationError.
   *
   * grpc-js's readable stream is a Node `Readable` in object mode, so
   * `for await` drives it directly: 'error' events surface as thrown
   * exceptions, 'end' as normal completion — no hand-rolled event plumbing. */
  async *replay(
    start = 0,
    follow = false,
    verify?: boolean,
  ): AsyncGenerator<string, void, unknown> {
    const doVerify = verify ?? this.verifyStreams;
    const checker = doVerify ? new ChainChecker(true) : null;
    const stream = (this.grpcClient as any).replay(
      { from: start, follow },
      this.meta(),
    ) as grpc.ClientReadableStream<any>;
    try {
      for await (const msg of stream as any) {
        const recordJson: string = msg.recordJson;
        if (checker) checker.check(recordJson);
        yield recordJson;
      }
    } catch (e) {
      throw e instanceof VerificationError ? e : wrapGrpcError(e as grpc.ServiceError);
    } finally {
      stream.cancel();
    }
  }

  /** replay()'s type-filtered sibling (G14): the server drops non-matching
   * records before they cross the wire, so a consumer that only cares about
   * one or two event types never receives (and discards) everything else.
   *
   * Honesty note: because the server may drop records, this does NOT carry
   * replay()'s gapless/chain-adjacency guarantee. With verification on (the
   * default), each delivered record's OWN hash is recomputed (and its
   * Ed25519 signature checked, for kivi.seal records) — proving
   * "byte-exact what the ledger holds" — but numbering gaps and prev_hash
   * discontinuities are EXPECTED and never thrown as tampering. A consumer
   * that must prove it received every record uses replay() instead. */
  async *subscribe(
    start = 0,
    follow = false,
    types: string[] = [],
    verify?: boolean,
  ): AsyncGenerator<string, void, unknown> {
    const doVerify = verify ?? this.verifyStreams;
    const checker = doVerify ? new RecordIntegrityChecker(true) : null;
    const stream = (this.grpcClient as any).subscribe(
      { from: start, follow, types },
      this.meta(),
    ) as grpc.ClientReadableStream<any>;
    try {
      for await (const msg of stream as any) {
        const recordJson: string = msg.recordJson;
        if (checker) checker.check(recordJson);
        yield recordJson;
      }
    } catch (e) {
      throw e instanceof VerificationError ? e : wrapGrpcError(e as grpc.ServiceError);
    } finally {
      stream.cancel();
    }
  }
}
