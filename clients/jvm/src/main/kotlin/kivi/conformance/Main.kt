// kivi JVM SDK conformance runner (G3.0 scenarios S1–S10 + the parity
// scenarios S12–S14: identity/login, semantic similar, head + as-of, and
// S15: the pure-Java client examined from Java source).
// S10 = coroutine parity: the JVM's async idiom, exercised concurrently.
package kivi.conformance

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.count
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.runBlocking
import kivi.*
import kotlin.system.exitProcess

var pass = 0
var total = 0

fun step(name: String, body: () -> Unit) {
    total++
    try {
        body()
        pass++
        println("  $name: ok")
    } catch (e: Throwable) {
        println("  $name: FAIL — ${e::class.simpleName}: ${e.message}")
    }
}

const val BIG = "9007199254740993" // 2^53+1 — dies in any double conversion

@JvmRecord data class Size(val w: Long, val h: Long)
@JvmRecord data class Widget(val name: String, val weightG: Long, val size: Size)

fun main(args: Array<String>) {
    if (args.size != 5) {
        System.err.println("usage: runner <clean> <tamper-record> <tamper-seal> <token> <auth>")
        exitProcess(2)
    }
    val (cleanAddr, trAddr, tsAddr, token) = args
    val authAddr = args[4]
    val c = KiviClient(cleanAddr, token)
    println("kivi JVM SDK conformance:")

    step("S1 receipt") {
        runBlocking {
            val r = c.append("property", """{"subject":"dog","attribute":"sound","value":"bark"}""")
            check(r.no == 0L && r.hash.length == 64) { "$r" }
            val r2 = c.append("property", """{"subject":"dog","attribute":"sound","value":"woof"}""")
            check(r2.no == 1L && r2.offset > r.offset) { "$r2" }
        }
    }

    step("S2 int64 fidelity") {
        runBlocking {
            c.append("property", """{"subject":"num","attribute":"big","value":$BIG}""")
            val a = c.table("num", "big")
            check(a.valueJson == BIG) { "int64 mangled: ${a.valueJson}" }
        }
    }

    step("S3 traced answers, honest refusals") {
        runBlocking {
            val a = c.table("dog", "sound")
            check(a.trace.isNotEmpty() && a.scope > 0 && a.valueJson == "\"woof\"") { "$a" }
            try {
                c.table("ghost", "attr")
                error("missing cell did not raise NotFound")
            } catch (e: NotFoundException) { /* honest refusal */ }
            try {
                TracedAnswer("1", emptyList(), 1)
                error("a traceless answer was constructable")
            } catch (e: IllegalArgumentException) { /* by design */ }
        }
    }

    step("S4 why") {
        runBlocking {
            val a = c.table("num", "big")
            val recs = c.why(a.trace)
            check(recs.size == 1 && recs[0].contains("\"value\":$BIG")) { "$recs" }
        }
    }

    step("S5 verified replay (clean)") {
        runBlocking {
            c.seal()
            val want = c.verifyLedger().records
            val got = c.replay(verify = true).count().toLong()
            check(got == want) { "replayed $got, ledger holds $want" }
        }
    }

    step("S6 tamper trap (record)") {
        runBlocking {
            KiviClient(trAddr).use { t ->
                t.append("note", """{"k":"tamper-me"}""")
                try {
                    t.replay(verify = true).collect { }
                    error("a corrupted record sailed through verification")
                } catch (e: VerificationException) { /* caught */ }
            }
        }
    }

    step("S7 tamper trap (seal)") {
        runBlocking {
            KiviClient(tsAddr).use { s ->
                s.append("note", """{"k":1}""")
                s.seal()
                try {
                    s.replay(verify = true).collect { }
                    error("a forged seal sailed through verification")
                } catch (e: VerificationException) { /* caught */ }
            }
        }
    }

    step("S8 auth") {
        runBlocking {
            KiviClient(cleanAddr).use { bare ->
                try {
                    bare.verifyLedger(); error("tokenless call was accepted")
                } catch (e: UnauthenticatedException) { }
            }
            KiviClient(cleanAddr, "wrong").use { w ->
                try {
                    w.verifyLedger(); error("wrong token was accepted")
                } catch (e: UnauthenticatedException) { }
            }
            check(c.verifyLedger().records >= 0)
        }
    }

    step("S9 erase flow") {
        runBlocking {
            val r = c.appendPrivate("note", mapOf("v" to "top-secret"))  // typed object overload
            check(c.getRecord(r.no, unseal = true).contains("top-secret"))
            c.erase(r.no, "conformance")
            try {
                c.erase(r.no, "again"); error("second erase did not fail")
            } catch (e: PreconditionException) { }
            val rec2 = c.getRecord(r.no, unseal = true)
            check(!rec2.contains("top-secret") && rec2.contains("kivi.sealed")) { rec2 }
        }
    }

    step("S10 coroutine parity (JVM async)") {
        runBlocking {
            coroutineScope {
                (0 until 8).map { g ->
                    async { c.append("metric", """{"series":"conc","value":$g}""") }
                }.awaitAll()
            }
            check(c.verifyLedger().ok)
            // and the blocking (Java-friendly) facade agrees with the world
            KiviBlockingClient(cleanAddr, token).use { b ->
                check(b.table("num", "big").valueJson == BIG)
                check(b.replayAll(verify = true).isNotEmpty())
            }
        }
    }

    step("S12 identity (login + per-call bearer)") {
        runBlocking {
            KiviClient(authAddr).use { u ->
                try {
                    u.login("conf-writer", "wrong-pass"); error("wrong password accepted")
                } catch (e: UnauthenticatedException) { }
                val sess = u.login("conf-writer", "conf-pass-123")
                check(sess.role == "writer" && sess.token.isNotEmpty()) { "$sess" }
                u.append("note", """{"who":"conf-writer"}""") // session identity writes
                KiviClient(authAddr).use { bare ->
                    try {
                        bare.verifyLedger(); error("anonymous call accepted")
                    } catch (e: UnauthenticatedException) { }
                    // per-call bearer: same channel, another identity
                    check(bare.withBearer(sess.token).verifyLedger().records >= 0)
                }
            }
        }
    }

    step("S13 similar (traced semantic search)") {
        runBlocking {
            KiviClient(authAddr, token).use { u ->
                val r = u.append("note", """{"text":"the zebra escaped the painting exhibition"}""")
                u.append("note", """{"text":"database replication lag is boring"}""")
                val a = u.similar("zebra exhibition painting", 3)
                check(a.hits.isNotEmpty() && a.hits[0].no == r.no) { "${a.hits}" }
                check(a.model.isNotEmpty() && a.scope >= r.no &&
                    a.hits[0].recordJson.isNotEmpty()) { "$a" }
            }
        }
    }

    step("S14 head + as-of (time travel)") {
        runBlocking {
            val (headNo, headHash) = c.head()
            check(headNo == c.verifyLedger().records - 1 && headHash.length == 64)
            // record 0 was dog.sound=bark, later overwritten by woof (S1)
            val a = c.table("dog", "sound", asOf = 0)
            check(a.valueJson == "\"bark\"" && a.scope == 0L &&
                a.trace == listOf(0L)) { "$a" }
            check(c.table("dog", "sound").valueJson == "\"woof\"")
        }
    }

    step("S16 paged view reads (keyset + snapshot pinning)") {
        runBlocking {
            for (s in listOf("pgA", "pgB", "pgC"))
                c.append("property", """{"subject":"$s","attribute":"a","value":"$s"}""")
            val p1 = c.viewPage("table", afterKey = "pg", limit = 2)
            check(p1.entries.map { it.key } == listOf("pgA", "pgB") &&
                p1.nextKey == "pgB" && p1.hash.length == 64) { "$p1" }
            // a write lands BETWEEN pages — the pinned walk must not see it
            c.append("property", """{"subject":"pgD","attribute":"a","value":4}""")
            val p2 = c.viewPage("table", afterKey = p1.nextKey, limit = 10, asOf = p1.scope)
            check(p2.entries.map { it.key } == listOf("pgC") && p2.nextKey == "" &&
                p2.hash == p1.hash && p2.scope == p1.scope) { "pinned page drifted: $p2" }
            // an unpinned page tells today's truth
            val now = c.viewPage("table", afterKey = "pg", limit = 10)
            check(now.entries.size == 4 && now.hash != p1.hash) { "$now" }
        }
    }

    step("S17 Subscribe (type-filtered feed)") {
        runBlocking {
            c.append("sub-other", """{"i":1}""")
            c.append("sub-wanted", """{"i":2}""")
            val got = ArrayList<String>()
            c.subscribe(types = listOf("sub-wanted")).collect { got.add(it) }
            check(got.size == 1 && got[0].contains("\"type\":\"sub-wanted\"")) { "$got" }
        }
    }

    step("S18 QuerySubject (whole-row read)") {
        runBlocking {
            c.append("property", """{"subject":"subj-whole","attribute":"a","value":1}""")
            c.append("property", """{"subject":"subj-whole","attribute":"b","value":2}""")
            val a = c.subject("subj-whole")
            check(a.valueJson == """{"a":1,"b":2}""" && a.trace.size == 2) { "$a" }
        }
    }

    step("S19 Json (dependency-free parse)") {
        @Suppress("UNCHECKED_CAST")
        val obj = Json.parse(
            """{"policy_id":"POL1111","limit":$BIG,"tags":["a","b"],"active":true,"note":null}""",
        ) as Map<String, Any?>
        check(obj["policy_id"] == "POL1111") { "string field: $obj" }
        check(obj["limit"] == BIG.toLong()) { "int64 fidelity lost: ${obj["limit"]}" }
        check(obj["tags"] == listOf("a", "b")) { "array: ${obj["tags"]}" }
        check(obj["active"] == true) { "bool: ${obj["active"]}" }
        check(obj.containsKey("note") && obj["note"] == null) { "null: $obj" }

        // round-trip against a REAL record from the server
        val recJson = runBlocking {
            c.append("property", """{"subject":"json-rt","attribute":"a","value":42}""")
            var last = ""
            c.replay(start = 0, follow = false).collect { last = it }
            last
        }
        @Suppress("UNCHECKED_CAST")
        val rec = Json.parse(recJson) as Map<String, Any?>
        check(rec["no"] is Long && rec["type"] is String && rec["body"] is Map<*, *>) { "$rec" }
    }

    step("S20 typed entity round-trip (entity in, entity out)") {
        val r = runBlocking { c.append("widget", Widget("cog", BIG.toLong(), Size(3, 4))) }
        val out = runBlocking { c.getRecordBodyAs(r.no, Widget::class.java) }
        check(out.name == "cog") { "name: ${out.name}" }
        check(out.weightG == BIG.toLong()) { "int64 fidelity lost: ${out.weightG}" }
        check(out.size == Size(3, 4)) { "nested: ${out.size}" }
    }

    step("S21 graph traversal (traced neighbors / reachable / shortest path)") {
        runBlocking {
            // directed chain gN1 —owns→ gN2 —owns→ gN3 out of `relation` events
            val e1 = c.append("relation", """{"source":"gN1","relation":"owns","target":"gN2"}""")
            val e2 = c.append("relation", """{"source":"gN2","relation":"owns","target":"gN3"}""")
            // neighbors: gN1 has exactly one outgoing edge, to gN2, set by e1
            val n = c.graphNeighbors("gN1")
            check(n.edges.size == 1 && n.edges[0].target == "gN2" &&
                n.edges[0].relation == "owns" && n.edges[0].no == e1.no) { "neighbors(gN1): ${n.edges}" }
            // reachable: gN3 at depth 2 with traced edge path [e1, e2]
            val reached = c.graphReachable("gN1", depth = 3)
            val gn3 = reached.nodes.find { it.node == "gN3" }
            check(gn3 != null && gn3.depth == 2L && gn3.trace == listOf(e1.no, e2.no)) {
                "reachable(gN1): gN3=$gn3"
            }
            // shortest path: two hops, each naming its edge record number
            val p = c.graphPath("gN1", "gN3")
            check(p.found && p.hops.size == 2 &&
                p.hops[0].from == "gN1" && p.hops[0].to == "gN2" && p.hops[0].no == e1.no &&
                p.hops[1].from == "gN2" && p.hops[1].to == "gN3" && p.hops[1].no == e2.no) {
                "path(gN1→gN3): found=${p.found} hops=${p.hops}"
            }
            // as-of e1: gN2→gN3 did not exist yet, so gN3 is unreachable
            val early = c.graphReachable("gN1", depth = 3, asOf = e1.no)
            check(early.nodes.none { it.node == "gN3" }) { "as-of ${e1.no} reached gN3 too early" }
        }
    }

    step("S15 Java SDK parity (pure Java client)") {
        // the scenario body lives in JavaScenario.java — Java source is the proof
        JavaScenario.run(cleanAddr, token, authAddr)
    }

    val verdict = if (pass == total) "PASS" else "FAIL"
    println("CONFORMANCE $verdict $pass/$total")
    c.close()
    exitProcess(if (pass == total) 0 else 1)
}

private operator fun <T> Array<T>.component4(): T = this[3]
