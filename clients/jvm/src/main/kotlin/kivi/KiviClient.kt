// kivi JVM SDK (PLAN3 G3.3, K2+K3): Kotlin coroutines are the JVM async idiom
// (suspend functions + Flow); KiviBlockingClient is the Java-friendly sync
// facade over the same engine. The SDK constitution:
//   - an answer without a trace is unconstructable (TracedAnswer requires it);
//   - client-side verification is ON by default (hash+chain+numbering+seals);
//   - honest refusals are typed exceptions — NotFound is never a null.
package kivi

import io.grpc.ManagedChannel
import io.grpc.ManagedChannelBuilder
import io.grpc.Metadata
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.stub.MetadataUtils
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kivi.v1.KiviGrpcKt
import kivi.v1.KiviOuterClass as Pb

open class KiviException(message: String) : RuntimeException(message)
class NotFoundException(m: String) : KiviException(m)
class UnauthenticatedException(m: String) : KiviException(m)
class PreconditionException(m: String) : KiviException(m)
class InvalidArgumentException(m: String) : KiviException(m)
class UnavailableException(m: String) : KiviException(m)
class RateLimitedException(m: String) : KiviException(m)

data class Receipt(val no: Long, val offset: Long, val hash: String)

/** value(+raw json) + the events that established it + the derivation scope.
 * Constructing one without a trace throws — by design. */
data class TracedAnswer(val valueJson: String, val trace: List<Long>, val scope: Long) {
    init { require(trace.isNotEmpty()) { "an answer without a trace is unrepresentable" } }
}

data class VerifyReport(val ok: Boolean, val records: Long, val seals: Long,
                        val unsealedTail: Long, val tornTail: Boolean,
                        val hasDefect: Boolean, val defectNo: Long, val defectReason: String)

/** One traced similarity hit: the record's address, its score, and the raw
 * receipt itself — an untraced score does not exist. */
data class SimilarHit(val no: Long, val score: Float, val recordJson: String)

data class SimilarAnswer(val hits: List<SimilarHit>, val scope: Long, val model: String)

/** The result of a login: the bearer token plus its honest envelope. */
data class Session(val token: String, val role: String, val expiresUnix: Long)

/** One row of a paged view read: canonical key + that entry's JSON (trace inside). */
data class ViewEntry(val key: String, val valueJson: String)

/** One page of a keyset walk over a compiled view. nextKey == "" means done.
 * scope/hash stamp the SNAPSHOT: pass scope back as asOf and every later page
 * keeps describing that same moment. */
data class ViewPage(val entries: List<ViewEntry>, val nextKey: String,
                    val scope: Long, val hash: String)

private fun wrap(e: StatusException): KiviException = when (e.status.code) {
    Status.Code.NOT_FOUND -> NotFoundException(e.status.description ?: "not found")
    Status.Code.UNAUTHENTICATED -> UnauthenticatedException(e.status.description ?: "unauthenticated")
    Status.Code.FAILED_PRECONDITION -> PreconditionException(e.status.description ?: "precondition")
    Status.Code.INVALID_ARGUMENT -> InvalidArgumentException(e.status.description ?: "invalid")
    Status.Code.UNAVAILABLE -> UnavailableException(e.status.description ?: "unavailable")
    Status.Code.RESOURCE_EXHAUSTED -> RateLimitedException(e.status.description ?: "rate limited")
    else -> KiviException(e.status.toString())
}

class KiviClient(
    addr: String,
    token: String? = null,
    val verifyStreams: Boolean = true,
    channel: ManagedChannel? = null,
    private val ownsChannel: Boolean = channel == null,
) : AutoCloseable {
    private val chan = channel ?: ManagedChannelBuilder.forTarget(addr).usePlaintext().build()
    @Volatile private var stub: KiviGrpcKt.KiviCoroutineStub
    @Volatile private var codec: EntityCodec = EntityCodec.DEFAULT

    init {
        stub = stubWith(token)
    }

    private fun stubWith(token: String?): KiviGrpcKt.KiviCoroutineStub {
        var s = KiviGrpcKt.KiviCoroutineStub(chan)
        if (token != null) {
            val md = Metadata()
            md.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer $token")
            s = s.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(md))
        }
        return s
    }

    /** Swap the bearer credential (after login or on rotation). */
    fun setToken(token: String?) { stub = stubWith(token) }

    /** Use a custom [EntityCodec] for the typed layer instead of kivi's
     *  built-in (dependency-free) mapper — e.g. a Jackson-backed one. Returns
     *  this client for fluent setup; the core never imports your library. */
    fun withCodec(codec: EntityCodec): KiviClient { this.codec = codec; return this }

    /** A view of this client over the SAME channel with ANOTHER identity —
     * per-caller credentials for stateless multi-tenant frontends. Closing a
     * view never closes the shared channel. */
    fun withBearer(token: String): KiviClient =
        KiviClient("", token, verifyStreams, chan, ownsChannel = false)

    override fun close() { if (ownsChannel) chan.shutdownNow() }

    private suspend fun <T> call(block: suspend () -> T): T =
        try { block() } catch (e: StatusException) { throw wrap(e) }

    /** Authenticate as a kivi USER and install the session token: from here
     * on every call runs with that user's role and every write is receipted
     * under their name. Security stays in ONE center — the server. */
    suspend fun login(username: String, password: String): Session = call {
        val r = stub.login(Pb.LoginRequest.newBuilder()
            .setUsername(username).setPassword(password).build())
        setToken(r.token)
        Session(r.token, r.role, r.expiresUnix)
    }

    /** The cheap orientation call: (headNo, headHash) — no audit runs. */
    suspend fun head(): Pair<Long, String> = call {
        stub.head(Pb.Empty.getDefaultInstance()).let { it.headNo to it.headHash }
    }

    /** Keyset pagination over a compiled view (table|graph|series). Pin a
     * consistent walk by passing page 1's scope as asOf. limit 0 = server
     * default (100, capped at 1000). */
    suspend fun viewPage(view: String, afterKey: String = "", limit: Long = 0,
                         asOf: Long? = null): ViewPage = call {
        val b = Pb.ViewPageRequest.newBuilder()
            .setView(view).setAfterKey(afterKey).setLimit(limit)
        if (asOf != null) b.setAsOf(asOf)
        val r = stub.queryViewPage(b.build())
        ViewPage(r.entriesList.map { ViewEntry(it.key, it.valueJson) },
            r.nextKey, r.scope, r.hash)
    }

    /** Traced semantic search: every hit is a record number + score + the
     * receipt itself; the answer names the model and the covered scope. */
    suspend fun similar(query: String, k: Long = 5): SimilarAnswer = call {
        val r = stub.similar(Pb.SimilarRequest.newBuilder().setQuery(query).setK(k).build())
        SimilarAnswer(r.hitsList.map { SimilarHit(it.no, it.score, it.recordJson) },
            r.scope, r.model)
    }

    suspend fun append(type: String, bodyJson: String): Receipt = call {
        stub.append(Pb.AppendRequest.newBuilder().setType(type).setBodyJson(bodyJson).build())
            .let { Receipt(it.no, it.offset, it.hash) }
    }

    /** Append a TYPED entity — pass a `@JvmRecord data class` (or Map/List);
     *  kivi serializes it with the active [EntityCodec] (default: kivi's own
     *  dependency-free mapper) and re-canonicalizes server-side, so field order
     *  never matters. "Entity in" — bring Jackson via [withCodec], or none. */
    suspend fun append(type: String, entity: Any): Receipt = append(type, codec.toJson(entity))

    /** Fetch record [no] and map its body into [cls] — the "entity out". The
     *  envelope is always parsed by kivi's core reader; only the body is handed
     *  to the active [EntityCodec]. */
    suspend fun <T> getRecordBodyAs(no: Long, cls: Class<T>, unseal: Boolean = false): T {
        @Suppress("UNCHECKED_CAST")
        val body = (Json.parse(getRecord(no, unseal)) as Map<String, Any?>)["body"]
        return codec.fromJson(Json.encode(body), cls)
    }

    suspend fun appendPrivate(type: String, bodyJson: String): Receipt = call {
        stub.appendPrivate(Pb.AppendRequest.newBuilder().setType(type).setBodyJson(bodyJson).build())
            .let { Receipt(it.no, it.offset, it.hash) }
    }

    /** Append a private (per-record encrypted) TYPED entity — an object, not a
     *  JSON string; serialized by the active [EntityCodec]. Erasable via [erase]. */
    suspend fun appendPrivate(type: String, entity: Any): Receipt = appendPrivate(type, codec.toJson(entity))

    suspend fun erase(no: Long, reason: String): Receipt = call {
        stub.erase(Pb.EraseRequest.newBuilder().setNo(no).setReason(reason).build())
            .let { Receipt(it.no, it.offset, it.hash) }
    }

    suspend fun seal(): Receipt = call {
        stub.seal(Pb.Empty.getDefaultInstance()).let { Receipt(it.no, it.offset, it.hash) }
    }

    suspend fun verifyLedger(): VerifyReport = call {
        stub.verify(Pb.Empty.getDefaultInstance()).let {
            VerifyReport(it.ok, it.records, it.seals, it.unsealedTail, it.tornTail,
                it.hasDefect, it.defectNo, it.defectReason)
        }
    }

    /** Traced read; asOf answers "what did we know when the ledger stopped
     * at record N" — time travel is free by design. */
    suspend fun table(subject: String, attribute: String, asOf: Long? = null): TracedAnswer = call {
        val b = Pb.TableRequest.newBuilder().setSubject(subject).setAttribute(attribute)
        if (asOf != null) b.setAsOf(asOf)
        stub.queryTable(b.build())
            .let { TracedAnswer(it.valueJson, it.traceList, it.scope) }
    }

    /** table()'s whole-row sibling (G15): every attribute known about one
     * subject, plus the union of every event that established one of them —
     * "what do we know about X?" without knowing which attributes to ask for
     * first. Same traced contract as table(). */
    suspend fun subject(subject: String, asOf: Long? = null): TracedAnswer = call {
        val b = Pb.SubjectRequest.newBuilder().setSubject(subject)
        if (asOf != null) b.setAsOf(asOf)
        stub.querySubject(b.build())
            .let { TracedAnswer(it.valueJson, it.traceList, it.scope) }
    }

    suspend fun why(trace: List<Long>): List<String> = call {
        stub.why(Pb.WhyRequest.newBuilder().addAllTrace(trace).build())
            .recordsList.map { it.recordJson }
    }

    suspend fun getRecord(no: Long, unseal: Boolean = false): String = call {
        stub.getRecord(Pb.GetRecordRequest.newBuilder().setNo(no).setUnseal(unseal).build())
            .recordJson
    }

    /** Verified replay: every record is re-hashed, chain+numbering checked and
     * seals Ed25519-verified CLIENT-SIDE (default). Raises VerificationException
     * on a lying stream. */
    fun replay(start: Long = 0, follow: Boolean = false,
               verify: Boolean? = null, checkSeals: Boolean = true): Flow<String> = flow {
        val checker = if (verify ?: verifyStreams) ChainChecker(checkSeals) else null
        try {
            stub.replay(Pb.ReplayRequest.newBuilder().setFrom(start).setFollow(follow).build())
                .collect { reply ->
                    checker?.check(reply.recordJson)
                    emit(reply.recordJson)
                }
        } catch (e: StatusException) {
            throw wrap(e)
        }
    }

    /** replay()'s type-filtered sibling (G14): the server drops non-matching
     * records before they cross the wire. Honesty note: because filtering
     * creates gaps by design, this does NOT carry replay()'s gapless/
     * chain-adjacency guarantee — each record's OWN hash/signature is still
     * verified, but numbering gaps and prev_hash discontinuities are
     * EXPECTED and never thrown as tampering. Use replay() when you must
     * prove no record was skipped. */
    fun subscribe(start: Long = 0, follow: Boolean = false, types: List<String> = emptyList(),
                  verify: Boolean? = null, checkSeals: Boolean = true): Flow<String> = flow {
        val checker = if (verify ?: verifyStreams) RecordIntegrityChecker(checkSeals) else null
        try {
            stub.subscribe(Pb.SubscribeRequest.newBuilder()
                    .setFrom(start).setFollow(follow).addAllTypes(types).build())
                .collect { reply ->
                    checker?.check(reply.recordJson)
                    emit(reply.recordJson)
                }
        } catch (e: StatusException) {
            throw wrap(e)
        }
    }
}

/** Java-friendly blocking facade over the coroutine client. */
class KiviBlockingClient(addr: String, token: String? = null, verify: Boolean = true) : AutoCloseable {
    private val inner = KiviClient(addr, token, verify)
    override fun close() = inner.close()

    fun append(type: String, bodyJson: String): Receipt = runBlocking { inner.append(type, bodyJson) }
    fun table(subject: String, attribute: String, asOf: Long? = null): TracedAnswer =
        runBlocking { inner.table(subject, attribute, asOf) }
    fun subject(subject: String, asOf: Long? = null): TracedAnswer =
        runBlocking { inner.subject(subject, asOf) }
    fun login(username: String, password: String): Session =
        runBlocking { inner.login(username, password) }
    fun head(): Pair<Long, String> = runBlocking { inner.head() }
    fun similar(query: String, k: Long = 5): SimilarAnswer =
        runBlocking { inner.similar(query, k) }
    fun viewPage(view: String, afterKey: String = "", limit: Long = 0, asOf: Long? = null): ViewPage =
        runBlocking { inner.viewPage(view, afterKey, limit, asOf) }
    fun verifyLedger(): VerifyReport = runBlocking { inner.verifyLedger() }
    fun why(trace: List<Long>): List<String> = runBlocking { inner.why(trace) }
    fun replayAll(verify: Boolean = true): List<String> = runBlocking {
        val out = ArrayList<String>()
        inner.replay(verify = verify).collect { out.add(it) }
        out
    }
    fun subscribeAll(types: List<String> = emptyList(), verify: Boolean = true): List<String> = runBlocking {
        val out = ArrayList<String>()
        inner.subscribe(types = types, verify = verify).collect { out.add(it) }
        out
    }
}
