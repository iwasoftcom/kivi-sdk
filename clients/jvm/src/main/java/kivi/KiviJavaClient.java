// kivi Java SDK — the pure-Java, first-class client (same JVM artifact as the
// Kotlin client; same constitution, Java idiom: blocking calls + a verified
// Iterator for streams).
//
//   - an answer without a trace is unconstructable (TracedAnswer throws);
//   - client-side verification is ON by default: replayed records are
//     re-hashed, chain and numbering checked, seals Ed25519-verified — a
//     lying server or wire throws VerificationException;
//   - honest refusals are typed exceptions — NotFound is never a null;
//   - identity: constructor token (service), login() sessions, and
//     withBearer() views for per-caller credentials over one shared channel.
package kivi;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import kivi.v1.KiviGrpc;
import kivi.v1.KiviOuterClass;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Supplier;

/**
 * The kivi client for Java. Thread-safe (gRPC channels and stubs are).
 *
 * <pre>{@code
 * try (var c = new KiviJavaClient("localhost:4741", System.getenv("KIVI_TOKEN"))) {
 *     Receipt r = c.append("property",
 *         "{\"subject\":\"dog\",\"attribute\":\"sound\",\"value\":\"bark\"}");
 *     TracedAnswer a = c.table("dog", "sound");   // value + trace + scope
 *     List<String> receipts = c.why(a.getTrace()); // the records themselves
 * }
 * }</pre>
 */
public final class KiviJavaClient implements AutoCloseable {

    /** The cheap orientation answer: last record number + head hash (no audit). */
    public record Head(long no, String hash) {}

    private final ManagedChannel channel;
    private final boolean ownsChannel;
    private final boolean verifyStreams;
    private volatile KiviGrpc.KiviBlockingStub stub;
    private volatile EntityCodec codec = EntityCodec.DEFAULT;

    /** Connect without a credential (open dev servers, or login() next). */
    public KiviJavaClient(String addr) { this(addr, null, true); }

    /** Connect with a bearer token (service token or a session token). */
    public KiviJavaClient(String addr, String token) { this(addr, token, true); }

    /** Full control: {@code verify=false} disables client-side stream verification. */
    public KiviJavaClient(String addr, String token, boolean verify) {
        this.channel = ManagedChannelBuilder.forTarget(addr).usePlaintext().build();
        this.ownsChannel = true;
        this.verifyStreams = verify;
        this.stub = stubWith(token);
    }

    private KiviJavaClient(ManagedChannel shared, String token, boolean verify) {
        this.channel = shared;
        this.ownsChannel = false;
        this.verifyStreams = verify;
        this.stub = stubWith(token);
    }

    private KiviGrpc.KiviBlockingStub stubWith(String token) {
        KiviGrpc.KiviBlockingStub s = KiviGrpc.newBlockingStub(channel);
        if (token != null && !token.isEmpty()) {
            Metadata md = new Metadata();
            md.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER),
                    "Bearer " + token);
            s = s.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(md));
        }
        return s;
    }

    /** Swap the bearer credential (after a login elsewhere, or on rotation). */
    public void setToken(String token) { this.stub = stubWith(token); }

    /**
     * Use a custom {@link EntityCodec} for the typed layer instead of kivi's
     * built-in (dependency-free) mapper — e.g. a Jackson- or Gson-backed one.
     * Returns this client for fluent setup; the core never imports your library.
     */
    public KiviJavaClient withCodec(EntityCodec codec) {
        this.codec = codec == null ? EntityCodec.DEFAULT : codec;
        return this;
    }

    /**
     * A view of this client over the SAME channel with ANOTHER identity —
     * per-caller credentials for stateless multi-tenant frontends. Closing a
     * view never closes the shared channel.
     */
    public KiviJavaClient withBearer(String token) {
        return new KiviJavaClient(channel, token, verifyStreams);
    }

    @Override public void close() { if (ownsChannel) channel.shutdownNow(); }

    // ---- error mapping: honest refusals become typed exceptions -------------

    private static KiviException wrap(StatusRuntimeException e) {
        Status st = e.getStatus();
        String d = st.getDescription() == null ? st.toString() : st.getDescription();
        return switch (st.getCode()) {
            case NOT_FOUND -> new NotFoundException(d);
            case UNAUTHENTICATED -> new UnauthenticatedException(d);
            case FAILED_PRECONDITION -> new PreconditionException(d);
            case INVALID_ARGUMENT -> new InvalidArgumentException(d);
            case UNAVAILABLE -> new UnavailableException(d);
            case RESOURCE_EXHAUSTED -> new RateLimitedException(d);
            default -> new KiviException(st.toString());
        };
    }

    private static <T> T call(Supplier<T> f) {
        try { return f.get(); } catch (StatusRuntimeException e) { throw wrap(e); }
    }

    // ---- identity plane ------------------------------------------------------

    /**
     * Authenticate as a kivi USER and install the session token on this
     * client: from here on every call runs with that user's role and every
     * write is receipted under their name. Security stays in ONE center —
     * the server's identity plane; the client only carries the credential.
     */
    public Session login(String username, String password) {
        KiviOuterClass.LoginReply r = call(() -> stub.login(
                KiviOuterClass.LoginRequest.newBuilder()
                        .setUsername(username).setPassword(password).build()));
        setToken(r.getToken());
        return new Session(r.getToken(), r.getRole(), r.getExpiresUnix());
    }

    // ---- write plane ---------------------------------------------------------

    /** Append one event; the receipt is proof (bodyJson = the event body as JSON). */
    public Receipt append(String type, String bodyJson) {
        KiviOuterClass.Receipt r = call(() -> stub.append(
                KiviOuterClass.AppendRequest.newBuilder()
                        .setType(type).setBodyJson(bodyJson).build()));
        return new Receipt(r.getNo(), r.getOffset(), r.getHash());
    }

    /**
     * Append a TYPED entity — you pass a {@code record} (or Map/List), kivi
     * serializes it with the active {@link EntityCodec} (default: kivi's own
     * dependency-free mapper) and re-canonicalizes server-side, so field order
     * never matters. "Entity in" — bring Jackson via {@link #withCodec}, or none.
     */
    public Receipt append(String type, Object entity) {
        return append(type, codec.toJson(entity));
    }

    /** Fetch record {@code no} and map its BODY into a record type {@code cls}
     *  — the "entity out" typed read. The envelope is always parsed by kivi's
     *  core reader; only the body is handed to the active {@link EntityCodec}. */
    public <T> T getRecordBodyAs(long no, boolean unseal, Class<T> cls) {
        Object body = ((java.util.Map<?, ?>) Json.parse(getRecord(no, unseal))).get("body");
        return codec.fromJson(Json.encode(body), cls);
    }

    /** Append with a per-record encrypted body (crypto-erasable later). */
    public Receipt appendPrivate(String type, String bodyJson) {
        KiviOuterClass.Receipt r = call(() -> stub.appendPrivate(
                KiviOuterClass.AppendRequest.newBuilder()
                        .setType(type).setBodyJson(bodyJson).build()));
        return new Receipt(r.getNo(), r.getOffset(), r.getHash());
    }

    /** Append a private (per-record encrypted) TYPED entity — an object (record/
     *  Map), not a JSON string; serialized by the active {@link EntityCodec}. */
    public Receipt appendPrivate(String type, Object entity) {
        return appendPrivate(type, codec.toJson(entity));
    }

    /** Crypto-erase a private record. A reason is mandatory — even forgetting leaves a trace. */
    public Receipt erase(long no, String reason) {
        KiviOuterClass.Receipt r = call(() -> stub.erase(
                KiviOuterClass.EraseRequest.newBuilder().setNo(no).setReason(reason).build()));
        return new Receipt(r.getNo(), r.getOffset(), r.getHash());
    }

    /** Ed25519-sign the open period. */
    public Receipt seal() {
        KiviOuterClass.Receipt r = call(() -> stub.seal(
                KiviOuterClass.Empty.getDefaultInstance()));
        return new Receipt(r.getNo(), r.getOffset(), r.getHash());
    }

    // ---- read plane ----------------------------------------------------------

    /** Full cryptographic audit of the server's ledger. */
    public VerifyReport verifyLedger() {
        KiviOuterClass.VerifyReport r = call(() -> stub.verify(
                KiviOuterClass.Empty.getDefaultInstance()));
        return new VerifyReport(r.getOk(), r.getRecords(), r.getSeals(),
                r.getUnsealedTail(), r.getTornTail(),
                r.getHasDefect(), r.getDefectNo(), r.getDefectReason());
    }

    /** The cheap orientation call: last record number + head hash — no audit runs. */
    public Head head() {
        KiviOuterClass.HeadReply r = call(() -> stub.head(
                KiviOuterClass.Empty.getDefaultInstance()));
        return new Head(r.getHeadNo(), r.getHeadHash());
    }

    /** Traced read of the CURRENT value: value + trace + scope; a missing cell throws {@link NotFoundException}. */
    public TracedAnswer table(String subject, String attribute) {
        return table(subject, attribute, null);
    }

    /**
     * Time travel: the answer AS OF record {@code asOf} — "what did we know
     * when the ledger stopped there?" ({@code null} = the current head).
     */
    public TracedAnswer table(String subject, String attribute, Long asOf) {
        KiviOuterClass.TableRequest.Builder b = KiviOuterClass.TableRequest.newBuilder()
                .setSubject(subject).setAttribute(attribute);
        if (asOf != null) b.setAsOf(asOf);
        KiviOuterClass.TracedAnswer r = call(() -> stub.queryTable(b.build()));
        return new TracedAnswer(r.getValueJson(), r.getTraceList(), r.getScope());
    }

    /**
     * {@code table}'s whole-row sibling (G15): every attribute known about
     * one subject, plus the union of every event that established one of
     * them — "what do we know about X?" without knowing which attributes to
     * ask for first.
     */
    public TracedAnswer subject(String subject) {
        return subject(subject, null);
    }

    /** Time travel, same contract as {@link #table(String, String, Long)}. */
    public TracedAnswer subject(String subject, Long asOf) {
        KiviOuterClass.SubjectRequest.Builder b = KiviOuterClass.SubjectRequest.newBuilder()
                .setSubject(subject);
        if (asOf != null) b.setAsOf(asOf);
        KiviOuterClass.TracedAnswer r = call(() -> stub.querySubject(b.build()));
        return new TracedAnswer(r.getValueJson(), r.getTraceList(), r.getScope());
    }

    /** Fetch the receipt records behind a trace — the raw immutable events, canonical JSON. */
    public List<String> why(List<Long> trace) {
        KiviOuterClass.RecordList r = call(() -> stub.why(
                KiviOuterClass.WhyRequest.newBuilder().addAllTrace(trace).build()));
        List<String> out = new ArrayList<>(r.getRecordsCount());
        for (KiviOuterClass.RecordReply rr : r.getRecordsList()) out.add(rr.getRecordJson());
        return out;
    }

    /** One record by number ({@code unseal=true} opens a private body if the key still exists). */
    public String getRecord(long no, boolean unseal) {
        KiviOuterClass.RecordReply r = call(() -> stub.getRecord(
                KiviOuterClass.GetRecordRequest.newBuilder().setNo(no).setUnseal(unseal).build()));
        return r.getRecordJson();
    }

    /** Keyset pagination over a compiled view (table|graph|series) at the current head. */
    public ViewPage viewPage(String view, String afterKey, long limit) {
        return viewPage(view, afterKey, limit, null);
    }

    /**
     * Keyset pagination pinned to a snapshot: pass page 1's scope as
     * {@code asOf} and every later page keeps describing that same moment,
     * no matter what writers do in between. {@code limit} 0 = server default
     * (100, capped at 1000).
     */
    public ViewPage viewPage(String view, String afterKey, long limit, Long asOf) {
        KiviOuterClass.ViewPageRequest.Builder b = KiviOuterClass.ViewPageRequest.newBuilder()
                .setView(view).setAfterKey(afterKey).setLimit(limit);
        if (asOf != null) b.setAsOf(asOf);
        KiviOuterClass.ViewPage r = call(() -> stub.queryViewPage(b.build()));
        List<ViewEntry> entries = new ArrayList<>(r.getEntriesCount());
        for (KiviOuterClass.ViewEntry e : r.getEntriesList())
            entries.add(new ViewEntry(e.getKey(), e.getValueJson()));
        return new ViewPage(entries, r.getNextKey(), r.getScope(), r.getHash());
    }

    /**
     * Traced semantic search: every hit is a record number + score + the raw
     * receipt; the answer names the model and the covered scope.
     */
    public SimilarAnswer similar(String query, long k) {
        KiviOuterClass.SimilarReply r = call(() -> stub.similar(
                KiviOuterClass.SimilarRequest.newBuilder().setQuery(query).setK(k).build()));
        List<SimilarHit> hits = new ArrayList<>(r.getHitsCount());
        for (KiviOuterClass.SimilarHit h : r.getHitsList())
            hits.add(new SimilarHit(h.getNo(), h.getScore(), h.getRecordJson()));
        return new SimilarAnswer(hits, r.getScope(), r.getModel());
    }

    /** Direct outgoing relation edges of {@code node}. {@code asOf} pins the
     * graph to a record number (null = current). */
    public GraphEdges graphNeighbors(String node, Long asOf) {
        KiviOuterClass.GraphNeighborsRequest.Builder b =
                KiviOuterClass.GraphNeighborsRequest.newBuilder().setNode(node);
        if (asOf != null) b.setAsOf(asOf);
        KiviOuterClass.GraphEdges r = call(() -> stub.graphNeighbors(b.build()));
        List<GraphEdge> edges = new ArrayList<>(r.getEdgesCount());
        for (KiviOuterClass.GraphEdge e : r.getEdgesList())
            edges.add(new GraphEdge(e.getRelation(), e.getTarget(), e.getNo()));
        return new GraphEdges(edges, r.getTruncated());
    }

    /** Every node reachable from {@code node} within {@code depth} hops
     * (0 = server default), each with its edge trace. {@code limit} 0 = default. */
    public GraphReach graphReachable(String node, long depth, long limit, Long asOf) {
        KiviOuterClass.GraphReachableRequest.Builder b =
                KiviOuterClass.GraphReachableRequest.newBuilder()
                        .setNode(node).setDepth(depth).setLimit(limit);
        if (asOf != null) b.setAsOf(asOf);
        KiviOuterClass.GraphReachableReply r = call(() -> stub.graphReachable(b.build()));
        List<GraphReached> nodes = new ArrayList<>(r.getNodesCount());
        for (KiviOuterClass.GraphReached n : r.getNodesList())
            nodes.add(new GraphReached(n.getNode(), n.getDepth(),
                    new ArrayList<>(n.getTraceList())));
        return new GraphReach(nodes, r.getTruncated());
    }

    /** Shortest edge path from {@code from} to {@code to} within {@code depth}
     * hops (0 = server default). found=false when none exists inside the bound. */
    public GraphPath graphPath(String from, String to, long depth, Long asOf) {
        KiviOuterClass.GraphPathRequest.Builder b =
                KiviOuterClass.GraphPathRequest.newBuilder()
                        .setFrom(from).setTo(to).setDepth(depth);
        if (asOf != null) b.setAsOf(asOf);
        KiviOuterClass.GraphPathReply r = call(() -> stub.graphPath(b.build()));
        List<GraphHop> hops = new ArrayList<>(r.getHopsCount());
        for (KiviOuterClass.GraphHop h : r.getHopsList())
            hops.add(new GraphHop(h.getFrom(), h.getRelation(), h.getTo(), h.getNo()));
        return new GraphPath(hops, r.getFound(), r.getTruncated());
    }

    // ---- streams: verified replay (the untrusting client) ---------------------

    /** Verified replay with the client's default verification setting. */
    public Iterator<String> replay(long start, boolean follow) {
        return replay(start, follow, verifyStreams);
    }

    /**
     * Stream records from {@code start}; {@code follow=true} never ends (CDC).
     * With verification on, every record is re-hashed, chain and numbering are
     * checked and seals are Ed25519-verified CLIENT-SIDE before you see it —
     * a lying stream throws {@link VerificationException}.
     */
    public Iterator<String> replay(long start, boolean follow, boolean verify) {
        Iterator<KiviOuterClass.RecordReply> inner = call(() -> stub.replay(
                KiviOuterClass.ReplayRequest.newBuilder().setFrom(start).setFollow(follow).build()));
        ChainChecker checker = verify ? new ChainChecker(true) : null;
        return new Iterator<>() {
            @Override public boolean hasNext() {
                try { return inner.hasNext(); }
                catch (StatusRuntimeException e) { throw wrap(e); }
            }
            @Override public String next() {
                String json;
                try { json = inner.next().getRecordJson(); }
                catch (StatusRuntimeException e) { throw wrap(e); }
                if (checker != null) checker.check(json);
                return json;
            }
        };
    }

    /** Convenience: the whole ledger as a verified list (bounded replay). */
    public List<String> replayAll(boolean verify) {
        List<String> out = new ArrayList<>();
        Iterator<String> it = replay(0, false, verify);
        while (it.hasNext()) out.add(it.next());
        return out;
    }

    /** Type-filtered live feed with the client's default verification setting. */
    public Iterator<String> subscribe(long start, boolean follow, List<String> types) {
        return subscribe(start, follow, types, verifyStreams);
    }

    /**
     * {@code replay}'s type-filtered sibling (G14): the server drops
     * non-matching records before they cross the wire, so a consumer that
     * only cares about one or two event types never receives (and
     * discards) everything else.
     *
     * <p>Honesty note: because the server may drop records, this does NOT
     * carry {@code replay}'s gapless/chain-adjacency guarantee. With
     * verification on, each delivered record's OWN hash is recomputed (and
     * its Ed25519 signature checked, for kivi.seal records) — proving
     * "byte-exact what the ledger holds" — but numbering gaps and
     * prev_hash discontinuities are EXPECTED and never throw. A consumer
     * that must prove it received every record uses {@code replay} instead.
     */
    public Iterator<String> subscribe(long start, boolean follow, List<String> types, boolean verify) {
        Iterator<KiviOuterClass.RecordReply> inner = call(() -> stub.subscribe(
                KiviOuterClass.SubscribeRequest.newBuilder()
                        .setFrom(start).setFollow(follow).addAllTypes(types).build()));
        RecordIntegrityChecker checker = verify ? new RecordIntegrityChecker(true) : null;
        return new Iterator<>() {
            @Override public boolean hasNext() {
                try { return inner.hasNext(); }
                catch (StatusRuntimeException e) { throw wrap(e); }
            }
            @Override public String next() {
                String json;
                try { json = inner.next().getRecordJson(); }
                catch (StatusRuntimeException e) { throw wrap(e); }
                if (checker != null) checker.check(json);
                return json;
            }
        };
    }
}
