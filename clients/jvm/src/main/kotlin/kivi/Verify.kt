// Client-side verification (K3) — the untrusting client, JVM edition.
//
// Byte-fidelity strategy: the server already sends CANONICAL JSON (sorted
// keys, compact, raw UTF-8). Instead of re-serializing (and fighting number
// formatting in yet another language), the canonical CORE is recovered by
// SPLICING the raw bytes: a tiny JSON scanner records the spans of the
// top-level "sig" and "hash" members, and the core is the record minus those
// spans. What gets hashed is byte-identical to what the writer hashed.
package kivi

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.EdECPoint
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.math.BigInteger

class VerificationException(message: String) : RuntimeException(message)

/** Spans of the top-level members of one canonical record. */
internal class TopLevel(val raw: ByteArray) {
    // memberSpan[key] = fromIndex (inclusive, at the comma-or-brace BEFORE the
    // key) .. toIndex (exclusive, after the value)
    val spans = LinkedHashMap<String, IntRange>()

    init {
        var i = 0
        fun fail(msg: String): Nothing = throw VerificationException("malformed record: $msg")
        if (raw.isEmpty() || raw[0] != '{'.code.toByte()) fail("no object")
        i = 1
        while (i < raw.size && raw[i] != '}'.code.toByte()) {
            val memberStart = i - 1 // points at '{' or ','
            if (raw[i] != '"'.code.toByte()) fail("expected key at $i")
            val keyEnd = scanString(i)
            val key = String(raw, i + 1, keyEnd - i - 2, Charsets.UTF_8)
            i = keyEnd
            if (raw[i] != ':'.code.toByte()) fail("expected ':' at $i")
            i++
            i = scanValue(i)
            spans[key] = memberStart until i
            if (i < raw.size && raw[i] == ','.code.toByte()) i++
        }
    }

    private fun scanString(from: Int): Int {
        var i = from + 1
        while (i < raw.size) {
            when (raw[i]) {
                '\\'.code.toByte() -> i += 2
                '"'.code.toByte() -> return i + 1
                else -> i++
            }
        }
        throw VerificationException("unterminated string")
    }

    private fun scanValue(from: Int): Int {
        var i = from
        when (raw[i]) {
            '"'.code.toByte() -> return scanString(i)
            '{'.code.toByte(), '['.code.toByte() -> {
                var depth = 0
                while (i < raw.size) {
                    when (raw[i]) {
                        '"'.code.toByte() -> { i = scanString(i); continue }
                        '{'.code.toByte(), '['.code.toByte() -> depth++
                        '}'.code.toByte(), ']'.code.toByte() -> { depth--; if (depth == 0) return i + 1 }
                    }
                    i++
                }
                throw VerificationException("unterminated container")
            }
            else -> { // number / true / false / null
                while (i < raw.size && raw[i] != ','.code.toByte() && raw[i] != '}'.code.toByte()) i++
                return i
            }
        }
    }

    /** The canonical core: the record bytes minus the sig and hash members. */
    fun coreBytes(): ByteArray {
        val drop = listOf(spans["sig"] ?: fail("sig"), spans["hash"] ?: fail("hash"))
            .sortedBy { it.first }
        val out = java.io.ByteArrayOutputStream(raw.size)
        var pos = 0
        for (r in drop) {
            out.write(raw, pos, r.first - pos)
            pos = r.last + 1
        }
        out.write(raw, pos, raw.size - pos)
        return out.toByteArray()
    }

    fun stringField(key: String): String? {
        val r = spans[key] ?: return null
        val s = String(raw, r.first, r.last + 1 - r.first, Charsets.UTF_8)
        val q1 = s.indexOf(':')
        val v = s.substring(q1 + 1)
        return if (v.startsWith("\"")) v.substring(1, v.length - 1) else v
    }

    fun longField(key: String): Long? = stringField(key)?.toLongOrNull()

    private fun fail(what: String): Nothing =
        throw VerificationException("record missing the $what member")
}

private val HEX = "0123456789abcdef"
private fun hex(b: ByteArray): String {
    val sb = StringBuilder(b.size * 2)
    for (x in b) {
        sb.append(HEX[(x.toInt() shr 4) and 0xf]).append(HEX[x.toInt() and 0xf])
    }
    return sb.toString()
}

private fun unhex(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in out.indices) out[i] = s.substring(2 * i, 2 * i + 2).toInt(16).toByte()
    return out
}

/** Ed25519 verify with the JDK's built-in provider (JDK 15+). */
fun ed25519Verify(sig: ByteArray, msg: ByteArray, rawPk: ByteArray): Boolean {
    if (sig.size != 64 || rawPk.size != 32) return false
    return try {
        val y = rawPk.reversedArray().copyOf() // little-endian → big-endian
        val xOdd = (y[0].toInt() and 0x80) != 0
        y[0] = (y[0].toInt() and 0x7f).toByte()
        val spec = EdECPublicKeySpec(NamedParameterSpec.ED25519,
            EdECPoint(xOdd, BigInteger(1, y)))
        val pk = KeyFactory.getInstance("Ed25519").generatePublic(spec)
        val s = Signature.getInstance("Ed25519")
        s.initVerify(pk)
        s.update(msg)
        s.verify(sig)
    } catch (e: Exception) {
        false
    }
}

/** One record's OWN hash (and Ed25519 seal signature, for kivi.seal records) —
 * the part ChainChecker and RecordIntegrityChecker share, regardless of
 * whether gaps between records are expected. Returns the record's number. */
private fun checkRecordIntegrity(raw: ByteArray, checkSeals: Boolean): Long {
    val top = TopLevel(raw)
    val no = top.longField("no")
        ?: throw VerificationException("record without a number")
    val digest = hex(MessageDigest.getInstance("SHA-256").digest(top.coreBytes()))
    if (digest != top.stringField("hash"))
        throw VerificationException("record $no: hash mismatch — content altered")
    if (checkSeals && top.stringField("type") == "kivi.seal") {
        // pk lives inside body: cheap extraction from the raw span
        val body = top.spans["body"]?.let {
            String(raw, it.first, it.last + 1 - it.first, Charsets.UTF_8)
        } ?: throw VerificationException("seal $no: no body")
        val pkm = Regex("\"pk\":\"([0-9a-f]{64})\"").find(body)
            ?: throw VerificationException("seal $no: no pk")
        val sig = top.stringField("sig")
            ?: throw VerificationException("seal $no: unsigned")
        if (sig == "null" || !ed25519Verify(unhex(sig), top.coreBytes(), unhex(pkm.groupValues[1])))
            throw VerificationException("seal $no: Ed25519 signature invalid")
    }
    return no
}

/** Verifies a replay stream record by record: hash, gapless numbering, chain
 * linkage and (optionally) Ed25519 seals. */
class ChainChecker(private val checkSeals: Boolean = true) {
    private var prevHash: String? = null
    private var nextNo: Long? = null

    fun check(recordJson: String) {
        val raw = recordJson.toByteArray(Charsets.UTF_8)
        val no = checkRecordIntegrity(raw, checkSeals)
        val top = TopLevel(raw)
        nextNo?.let {
            if (no != it) throw VerificationException("numbering broken: expected $it, got $no")
        }
        prevHash?.let {
            if (top.stringField("prev_hash") != it)
                throw VerificationException("record $no: chain linkage broken")
        }
        prevHash = top.stringField("hash")
        nextNo = no + 1
    }
}

/** Subscribe's checker (G14): each record's OWN hash/signature is verified,
 * but — unlike ChainChecker — numbering gaps and prev_hash discontinuities
 * are EXPECTED (server-side type filtering causes them by design) and are
 * never treated as tampering. */
class RecordIntegrityChecker(private val checkSeals: Boolean = true) {
    fun check(recordJson: String) {
        checkRecordIntegrity(recordJson.toByteArray(Charsets.UTF_8), checkSeals)
    }
}
