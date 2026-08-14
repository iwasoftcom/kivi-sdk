// kivi .NET SDK (PLAN3 G3.4, K2+K3): async-first (Task — the .NET idiom) with
// a sync facade. The SDK constitution:
//   - an answer without a trace is unconstructable (TracedAnswer throws);
//   - client-side verification is ON by default (hash+chain+numbering+seals);
//   - honest refusals are typed exceptions — NotFound is never a null.
using System.Text.Json;
using Grpc.Core;
using Grpc.Net.Client;
using Kivi.V1;

namespace Kivi;

public class KiviException(string message) : Exception(message);
public class NotFoundException(string m) : KiviException(m);
public class UnauthenticatedException(string m) : KiviException(m);
public class PreconditionException(string m) : KiviException(m);
public class InvalidArgumentException(string m) : KiviException(m);
public class UnavailableException(string m) : KiviException(m);
public class RateLimitedException(string m) : KiviException(m);

public readonly record struct Receipt(long No, long Offset, string Hash);

/// <summary>valueJson + the events that established it + the derivation scope.
/// Constructing one without a trace throws — by design.</summary>
public sealed record TracedAnswer
{
    public string ValueJson { get; }
    public IReadOnlyList<long> Trace { get; }
    public long Scope { get; }

    public TracedAnswer(string valueJson, IReadOnlyList<long> trace, long scope)
    {
        if (trace.Count == 0)
            throw new ArgumentException("an answer without a trace is unrepresentable");
        (ValueJson, Trace, Scope) = (valueJson, trace, scope);
    }
}

public readonly record struct LedgerReport(bool Ok, long Records, long Seals,
    long UnsealedTail, bool TornTail, bool HasDefect, long DefectNo, string DefectReason);

/// <summary>One traced similarity hit: the record's address, its score, and
/// the raw receipt itself — an untraced score does not exist.</summary>
public readonly record struct SimilarHit(long No, float Score, string RecordJson);

public readonly record struct SimilarAnswer(IReadOnlyList<SimilarHit> Hits,
    long Scope, string Model);

/// <summary>The result of a login: the bearer token plus its honest envelope.</summary>
public readonly record struct Session(string Token, string Role, long ExpiresUnix);

/// <summary>One row of a paged view read: canonical key + that entry's JSON (trace inside).</summary>
public readonly record struct PagedEntry(string Key, string ValueJson);

/// <summary>One page of a keyset walk over a compiled view. NextKey == "" means
/// done. Scope/Hash stamp the SNAPSHOT: pass Scope back as asOf and every later
/// page keeps describing that same moment.</summary>
public readonly record struct PagedView(IReadOnlyList<PagedEntry> Entries,
    string NextKey, long Scope, string Hash);

/// <summary>One directed, traced relation: Source —Relation→ Target, set by
/// record No.</summary>
public readonly record struct GraphEdge(string Relation, string Target, long No);

/// <summary>A node found by a traversal, with its depth and the edge record
/// numbers along the shortest discovering path (the proof).</summary>
public readonly record struct GraphReached(string Node, long Depth, IReadOnlyList<long> Trace);

/// <summary>One step of a path: From —Relation→ To, via edge record No.</summary>
public readonly record struct GraphHop(string From, string Relation, string To, long No);

public sealed class KiviClient : IDisposable
{
    private readonly GrpcChannel _channel;
    private readonly bool _ownsChannel;
    private readonly V1.Kivi.KiviClient _stub;
    private Metadata _md = [];
    public bool VerifyStreams { get; }

    public KiviClient(string addr, string? token = null, bool verify = true)
    {
        _channel = GrpcChannel.ForAddress(addr.StartsWith("http") ? addr : $"http://{addr}");
        _ownsChannel = true;
        _stub = new V1.Kivi.KiviClient(_channel);
        if (token != null) _md.Add("authorization", $"Bearer {token}");
        VerifyStreams = verify;
    }

    private KiviClient(GrpcChannel shared, string? token, bool verify)
    {
        _channel = shared;
        _ownsChannel = false;
        _stub = new V1.Kivi.KiviClient(_channel);
        if (token != null) _md.Add("authorization", $"Bearer {token}");
        VerifyStreams = verify;
    }

    /// <summary>A view of this client over the SAME channel with ANOTHER
    /// identity — per-caller credentials for stateless multi-tenant
    /// frontends. Disposing a view never closes the shared channel.</summary>
    public KiviClient WithBearer(string token) => new(_channel, token, VerifyStreams);

    /// <summary>Swap the bearer credential (after login or on rotation).</summary>
    public void SetToken(string? token)
    {
        var md = new Metadata();
        if (token != null) md.Add("authorization", $"Bearer {token}");
        _md = md;
    }

    public void Dispose() { if (_ownsChannel) _channel.Dispose(); }

    private static KiviException Wrap(RpcException e) => e.StatusCode switch
    {
        StatusCode.NotFound => new NotFoundException(e.Status.Detail),
        StatusCode.Unauthenticated => new UnauthenticatedException(e.Status.Detail),
        StatusCode.FailedPrecondition => new PreconditionException(e.Status.Detail),
        StatusCode.InvalidArgument => new InvalidArgumentException(e.Status.Detail),
        StatusCode.Unavailable => new UnavailableException(e.Status.Detail),
        StatusCode.ResourceExhausted => new RateLimitedException(e.Status.Detail),
        _ => new KiviException(e.Status.ToString()),
    };

    private async Task<T> Call<T>(Func<Task<T>> f)
    {
        try { return await f().ConfigureAwait(false); }
        catch (RpcException e) { throw Wrap(e); }
    }

    public Task<Receipt> AppendAsync(string type, string bodyJson) => Call(async () =>
    {
        var r = await _stub.AppendAsync(new AppendRequest { Type = type, BodyJson = bodyJson }, _md);
        return new Receipt(r.No, r.Offset, r.Hash);
    });

    public Task<Receipt> AppendPrivateAsync(string type, string bodyJson) => Call(async () =>
    {
        var r = await _stub.AppendPrivateAsync(new AppendRequest { Type = type, BodyJson = bodyJson }, _md);
        return new Receipt(r.No, r.Offset, r.Hash);
    });

    // -- typed "entity in, entity out" (System.Text.Json, already in the runtime) --

    /// <summary>Snake_case field names — the kivi ecosystem convention
    /// (policy_id, premium_cents). PascalCase C# records map to it both ways.</summary>
    internal static readonly JsonSerializerOptions JsonOpts =
        new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    /// <summary>Append a TYPED entity — you pass an object, kivi serializes it
    /// (and re-canonicalizes server-side, so field order never matters).</summary>
    public Task<Receipt> AppendAsync<T>(string type, T entity) =>
        AppendAsync(type, JsonSerializer.Serialize(entity, JsonOpts));

    /// <summary>Append a private (per-record encrypted) TYPED entity — an object,
    /// not a JSON string. Erasable later; see EraseAsync.</summary>
    public Task<Receipt> AppendPrivateAsync<T>(string type, T entity) =>
        AppendPrivateAsync(type, JsonSerializer.Serialize(entity, JsonOpts));

    /// <summary>Decode an already-fetched record's BODY into a TYPED entity —
    /// the "entity out" for records from ReplayAsync/SubscribeAll/Why/GetRecord.</summary>
    public static T BodyAs<T>(string recordJson)
    {
        using var doc = JsonDocument.Parse(recordJson);
        return doc.RootElement.GetProperty("body").Deserialize<T>(JsonOpts)!;
    }

    /// <summary>Fetch record <c>no</c> and decode its body into a typed entity.</summary>
    public Task<T> GetRecordBodyAsAsync<T>(long no, bool unseal = false) => Call(async () =>
        BodyAs<T>(await GetRecordAsync(no, unseal)));

    public Task<Receipt> EraseAsync(long no, string reason) => Call(async () =>
    {
        var r = await _stub.EraseAsync(new EraseRequest { No = no, Reason = reason }, _md);
        return new Receipt(r.No, r.Offset, r.Hash);
    });

    public Task<Receipt> SealAsync() => Call(async () =>
    {
        var r = await _stub.SealAsync(new Empty(), _md);
        return new Receipt(r.No, r.Offset, r.Hash);
    });

    public Task<LedgerReport> VerifyLedgerAsync() => Call(async () =>
    {
        var r = await _stub.VerifyAsync(new Empty(), _md);
        return new LedgerReport(r.Ok, r.Records, r.Seals, r.UnsealedTail,
            r.TornTail, r.HasDefect, r.DefectNo, r.DefectReason);
    });

    /// <summary>Traced read; asOf answers "what did we know when the ledger
    /// stopped at record N" — time travel is free by design.</summary>
    public Task<TracedAnswer> TableAsync(string subject, string attribute,
        long? asOf = null) => Call(async () =>
    {
        var req = new TableRequest { Subject = subject, Attribute = attribute };
        if (asOf is long n) req.AsOf = n;
        var r = await _stub.QueryTableAsync(req, _md);
        return new TracedAnswer(r.ValueJson, r.Trace.ToList(), r.Scope);
    });

    /// <summary>TableAsync's whole-row sibling (G15): every attribute known
    /// about one subject, plus the union of every event that established one
    /// of them — "what do we know about X?" without knowing which attributes
    /// to ask for first. Same traced contract as TableAsync.</summary>
    public Task<TracedAnswer> SubjectAsync(string subject, long? asOf = null) => Call(async () =>
    {
        var req = new SubjectRequest { Subject = subject };
        if (asOf is long n) req.AsOf = n;
        var r = await _stub.QuerySubjectAsync(req, _md);
        return new TracedAnswer(r.ValueJson, r.Trace.ToList(), r.Scope);
    });

    /// <summary>Authenticate as a kivi USER and install the session token:
    /// every later call runs with that user's role and every write is
    /// receipted under their name. Security stays in ONE center — the server.</summary>
    public Task<Session> LoginAsync(string username, string password) => Call(async () =>
    {
        var r = await _stub.LoginAsync(new LoginRequest
        { Username = username, Password = password }, _md);
        SetToken(r.Token);
        return new Session(r.Token, r.Role, r.ExpiresUnix);
    });

    /// <summary>The cheap orientation call: (HeadNo, HeadHash) — no audit runs.</summary>
    public Task<(long HeadNo, string HeadHash)> HeadAsync() => Call(async () =>
    {
        var r = await _stub.HeadAsync(new Empty(), _md);
        return (r.HeadNo, r.HeadHash);
    });

    /// <summary>Keyset pagination over a compiled view (table|graph|series).
    /// Pin a consistent walk by passing page 1's Scope as asOf; limit 0 =
    /// server default (100, capped at 1000).</summary>
    public Task<PagedView> ViewPageAsync(string view, string afterKey = "",
        long limit = 0, long? asOf = null) => Call(async () =>
    {
        var req = new ViewPageRequest { View = view, AfterKey = afterKey, Limit = limit };
        if (asOf is long n) req.AsOf = n;
        var r = await _stub.QueryViewPageAsync(req, _md);
        return new PagedView(
            r.Entries.Select(e => new PagedEntry(e.Key, e.ValueJson)).ToList(),
            r.NextKey, r.Scope, r.Hash);
    });

    /// <summary>Direct outgoing relation edges of <paramref name="node"/>. asOf
    /// pins the graph to a record number (null = current).</summary>
    public Task<(IReadOnlyList<GraphEdge> Edges, bool Truncated)> GraphNeighborsAsync(
        string node, long? asOf = null) => Call(async () =>
    {
        var req = new GraphNeighborsRequest { Node = node };
        if (asOf is long n) req.AsOf = n;
        var r = await _stub.GraphNeighborsAsync(req, _md);
        return ((IReadOnlyList<GraphEdge>)r.Edges
            .Select(e => new GraphEdge(e.Relation, e.Target, e.No)).ToList(), r.Truncated);
    });

    /// <summary>Every node reachable from <paramref name="node"/> within
    /// <paramref name="depth"/> hops (0 = server default), each with its edge
    /// trace. limit 0 = server default.</summary>
    public Task<(IReadOnlyList<GraphReached> Nodes, bool Truncated)> GraphReachableAsync(
        string node, long depth = 0, long limit = 0, long? asOf = null) => Call(async () =>
    {
        var req = new GraphReachableRequest { Node = node, Depth = depth, Limit = limit };
        if (asOf is long n) req.AsOf = n;
        var r = await _stub.GraphReachableAsync(req, _md);
        return ((IReadOnlyList<GraphReached>)r.Nodes
            .Select(x => new GraphReached(x.Node, x.Depth, x.Trace.ToList())).ToList(), r.Truncated);
    });

    /// <summary>Shortest edge path from <paramref name="from"/> to
    /// <paramref name="to"/> within <paramref name="depth"/> hops (0 = server
    /// default). Found=false when none exists inside the bound.</summary>
    public Task<(IReadOnlyList<GraphHop> Hops, bool Found, bool Truncated)> GraphPathAsync(
        string from, string to, long depth = 0, long? asOf = null) => Call(async () =>
    {
        var req = new GraphPathRequest { From = from, To = to, Depth = depth };
        if (asOf is long n) req.AsOf = n;
        var r = await _stub.GraphPathAsync(req, _md);
        return ((IReadOnlyList<GraphHop>)r.Hops
            .Select(h => new GraphHop(h.From, h.Relation, h.To, h.No)).ToList(), r.Found, r.Truncated);
    });

    /// <summary>Traced semantic search: every hit is a record number + score
    /// + the receipt itself; the answer names the model and covered scope.</summary>
    public Task<SimilarAnswer> SimilarAsync(string query, long k = 5) => Call(async () =>
    {
        var r = await _stub.SimilarAsync(new SimilarRequest { Query = query, K = k }, _md);
        return new SimilarAnswer(
            r.Hits.Select(h => new SimilarHit(h.No, h.Score, h.RecordJson)).ToList(),
            r.Scope, r.Model);
    });

    public Task<List<string>> WhyAsync(IEnumerable<long> trace) => Call(async () =>
    {
        var req = new WhyRequest();
        req.Trace.AddRange(trace);
        var r = await _stub.WhyAsync(req, _md);
        return r.Records.Select(x => x.RecordJson).ToList();
    });

    public Task<string> GetRecordAsync(long no, bool unseal = false) => Call(async () =>
    {
        var r = await _stub.GetRecordAsync(new GetRecordRequest { No = no, Unseal = unseal }, _md);
        return r.RecordJson;
    });

    /// <summary>Verified replay: every record is re-hashed, chain+numbering
    /// checked and seals Ed25519-verified CLIENT-SIDE (default). Throws
    /// VerificationException on a lying stream.</summary>
    public async IAsyncEnumerable<string> ReplayAsync(long start = 0, bool follow = false,
        bool? verify = null, bool checkSeals = true)
    {
        var checker = (verify ?? VerifyStreams) ? new ChainChecker(checkSeals) : null;
        using var call = _stub.Replay(new ReplayRequest { From = start, Follow = follow }, _md);
        while (true)
        {
            bool ok;
            try { ok = await call.ResponseStream.MoveNext(default).ConfigureAwait(false); }
            catch (RpcException e) { throw Wrap(e); }
            if (!ok) yield break;
            var json = call.ResponseStream.Current.RecordJson;
            checker?.Check(json);
            yield return json;
        }
    }

    /// <summary>ReplayAsync's type-filtered sibling (G14): the server drops
    /// non-matching records before they cross the wire, so a consumer that
    /// only cares about one or two event types never receives (and
    /// discards) everything else.
    ///
    /// Honesty note: because the server may drop records, this does NOT
    /// carry ReplayAsync's gapless/chain-adjacency guarantee. With
    /// verification on (default), each delivered record's OWN hash is
    /// recomputed (and its Ed25519 signature checked, for kivi.seal
    /// records) — proving "byte-exact what the ledger holds" — but
    /// numbering gaps and prev_hash discontinuities are EXPECTED and never
    /// thrown as tampering. A consumer that must prove it received every
    /// record uses ReplayAsync instead.</summary>
    public async IAsyncEnumerable<string> SubscribeAsync(long start = 0, bool follow = false,
        IEnumerable<string>? types = null, bool? verify = null, bool checkSeals = true)
    {
        var checker = (verify ?? VerifyStreams) ? new RecordIntegrityChecker(checkSeals) : null;
        var req = new SubscribeRequest { From = start, Follow = follow };
        if (types is not null) req.Types_.AddRange(types);
        using var call = _stub.Subscribe(req, _md);
        while (true)
        {
            bool ok;
            try { ok = await call.ResponseStream.MoveNext(default).ConfigureAwait(false); }
            catch (RpcException e) { throw Wrap(e); }
            if (!ok) yield break;
            var json = call.ResponseStream.Current.RecordJson;
            checker?.Check(json);
            yield return json;
        }
    }

    // -- sync facade (documented blocking wrappers over the async engine) ----

    public Receipt Append(string type, string bodyJson) =>
        AppendAsync(type, bodyJson).GetAwaiter().GetResult();
    public Receipt Append<T>(string type, T entity) =>
        AppendAsync(type, entity).GetAwaiter().GetResult();
    public Receipt AppendPrivate<T>(string type, T entity) =>
        AppendPrivateAsync(type, entity).GetAwaiter().GetResult();
    public T GetRecordBodyAs<T>(long no, bool unseal = false) =>
        GetRecordBodyAsAsync<T>(no, unseal).GetAwaiter().GetResult();
    public TracedAnswer Table(string subject, string attribute, long? asOf = null) =>
        TableAsync(subject, attribute, asOf).GetAwaiter().GetResult();
    public TracedAnswer Subject(string subject, long? asOf = null) =>
        SubjectAsync(subject, asOf).GetAwaiter().GetResult();
    public Session Login(string username, string password) =>
        LoginAsync(username, password).GetAwaiter().GetResult();
    public (long HeadNo, string HeadHash) Head() => HeadAsync().GetAwaiter().GetResult();
    public SimilarAnswer Similar(string query, long k = 5) =>
        SimilarAsync(query, k).GetAwaiter().GetResult();
    public PagedView ViewPage(string view, string afterKey = "", long limit = 0, long? asOf = null) =>
        ViewPageAsync(view, afterKey, limit, asOf).GetAwaiter().GetResult();
    public LedgerReport VerifyLedger() => VerifyLedgerAsync().GetAwaiter().GetResult();
    public List<string> Why(IEnumerable<long> trace) => WhyAsync(trace).GetAwaiter().GetResult();
    public List<string> ReplayAll(bool verify = true)
    {
        var outp = new List<string>();
        var e = ReplayAsync(verify: verify).GetAsyncEnumerator();
        try { while (e.MoveNextAsync().AsTask().GetAwaiter().GetResult()) outp.Add(e.Current); }
        finally { e.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
        return outp;
    }
    public List<string> SubscribeAll(IEnumerable<string>? types = null, bool verify = true)
    {
        var outp = new List<string>();
        var e = SubscribeAsync(types: types, verify: verify).GetAsyncEnumerator();
        try { while (e.MoveNextAsync().AsTask().GetAwaiter().GetResult()) outp.Add(e.Current); }
        finally { e.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
        return outp;
    }
}
