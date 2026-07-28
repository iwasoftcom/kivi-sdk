// Json — a minimal, DEPENDENCY-FREE JSON parser for the JVM SDK (Java and
// Kotlin both call it; it is why the SDK's runtime deps stay gRPC + protobuf
// + coroutines only, same as Verify.kt's byte-level scanner for the same
// reason). kivi's own core is Go-stdlib-only for the same principle — the
// client follows suit instead of pulling in Jackson/Gson for one convenience.
//
// Canonical JSON in, plain JVM objects out: object -> LinkedHashMap<String,
// Any?> (insertion order preserved — the server already sends keys sorted),
// array -> List<Any?>, string -> String, true/false -> Boolean, null -> null.
//
// Int64 fidelity matters here exactly as it does server-side (conformance
// S2): an integer that fits in a Long parses as a Long, never silently
// rounded through a Double the way JavaScript's JSON.parse would.
package kivi

object Json {
    @JvmStatic
    fun parse(text: String): Any? {
        val p = Parser(text)
        val v = p.parseValue()
        p.skipWs()
        if (!p.atEnd()) throw IllegalArgumentException("trailing data after JSON value at ${p.i}")
        return v
    }

    // ---- typed "entity in, entity out" (records-focused, ZERO dependency) ----
    //
    // The JDK has no JSON<->object mapper, so — exactly like the hand-written
    // parser above (rather than pulling in Jackson) — a small one lives here.
    // It targets IMMUTABLE records: a Java `record`, or a Kotlin
    // `@JvmRecord data class` (which compiles to a real java.lang.Record). That
    // is the right shape for kivi events, and keeps the reflection trivial:
    // getRecordComponents() gives names+types both ways. Supported: records,
    // String, long/int/short/byte, double/float, boolean, null, List<...>, and
    // nested records. Anything else is an honest IllegalArgumentException.

    /** Serialize a record (or Map/List/primitive) to a JSON string — the
     *  "entity in" write. Field order is the record's declaration order; the
     *  kivi server re-canonicalizes, so order never matters. */
    @JvmStatic
    fun encode(value: Any?): String = StringBuilder().also { encodeInto(it, value) }.toString()

    /** Parse a JSON string and map it INTO a record type — the "entity out". */
    @JvmStatic
    fun <T> mapTo(text: String, cls: Class<T>): T {
        @Suppress("UNCHECKED_CAST")
        return coerce(parse(text), cls, null) as T
    }

    /** Decode an already-fetched record's BODY into a record type — the
     *  "entity out" for records from replay/subscribe/why/getRecord. */
    @JvmStatic
    fun <T> bodyAs(recordJson: String, cls: Class<T>): T {
        @Suppress("UNCHECKED_CAST")
        val rec = parse(recordJson) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        return coerce(rec["body"], cls, null) as T
    }

    private fun encodeInto(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is String -> encodeString(sb, v)
            is Boolean -> sb.append(v.toString())
            is Int, is Long, is Short, is Byte -> sb.append(v.toString())
            is Double, is Float -> sb.append(v.toString())
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, value) in v) {
                    if (!first) sb.append(','); first = false
                    encodeString(sb, k.toString()); sb.append(':'); encodeInto(sb, value)
                }
                sb.append('}')
            }
            is Iterable<*> -> {
                sb.append('[')
                var first = true
                for (e in v) { if (!first) sb.append(','); first = false; encodeInto(sb, e) }
                sb.append(']')
            }
            else -> {
                val cls = v.javaClass
                if (!cls.isRecord) {
                    throw IllegalArgumentException(
                        "cannot encode ${cls.name}: use a record / @JvmRecord data class, Map, List or primitive")
                }
                sb.append('{')
                cls.recordComponents.forEachIndexed { i, comp ->
                    if (i > 0) sb.append(',')
                    encodeString(sb, camelToSnake(comp.name)); sb.append(':')
                    val accessor = comp.accessor.apply { isAccessible = true } // works for any record visibility
                    encodeInto(sb, accessor.invoke(v))
                }
                sb.append('}')
            }
        }
    }

    /** camelCase record component → snake_case JSON key (kivi ecosystem
     *  convention), so JVM DTOs stay idiomatic while the wire stays snake_case
     *  — the same mapping the .NET SDK applies. */
    private fun camelToSnake(name: String): String {
        val sb = StringBuilder(name.length + 4)
        for (c in name) {
            if (c.isUpperCase()) sb.append('_').append(c.lowercaseChar()) else sb.append(c)
        }
        return sb.toString()
    }

    private fun encodeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
    }

    private fun coerce(value: Any?, cls: Class<*>, generic: java.lang.reflect.Type?): Any? {
        if (value == null) return null
        when (cls) {
            String::class.java -> return value as String
            java.lang.Long.TYPE, java.lang.Long::class.java -> return (value as Number).toLong()
            Integer.TYPE, Integer::class.java -> return (value as Number).toInt()
            java.lang.Short.TYPE, java.lang.Short::class.java -> return (value as Number).toShort()
            java.lang.Double.TYPE, java.lang.Double::class.java -> return (value as Number).toDouble()
            java.lang.Float.TYPE, java.lang.Float::class.java -> return (value as Number).toFloat()
            java.lang.Boolean.TYPE, java.lang.Boolean::class.java -> return value as Boolean
            Any::class.java, java.lang.Object::class.java -> return value
        }
        if (List::class.java.isAssignableFrom(cls) || MutableList::class.java.isAssignableFrom(cls)) {
            val elem = (generic as? java.lang.reflect.ParameterizedType)
                ?.actualTypeArguments?.getOrNull(0) as? Class<*> ?: Any::class.java
            return (value as List<*>).map { coerce(it, elem, null) }
        }
        if (cls.isRecord) {
            @Suppress("UNCHECKED_CAST")
            val map = value as Map<String, Any?>
            val comps = cls.recordComponents
            val argTypes = comps.map { it.type }.toTypedArray()
            val args = comps.map { coerce(map[camelToSnake(it.name)], it.type, it.genericType) }.toTypedArray()
            val ctor = cls.getDeclaredConstructor(*argTypes)
            ctor.isAccessible = true
            return ctor.newInstance(*args)
        }
        throw IllegalArgumentException(
            "cannot map JSON into ${cls.name}: use a record / @JvmRecord data class, or a supported primitive")
    }

    private class Parser(val s: String) {
        var i = 0

        fun atEnd() = i >= s.length

        fun skipWs() {
            while (i < s.length && s[i].let { it == ' ' || it == '\t' || it == '\n' || it == '\r' }) i++
        }

        fun parseValue(): Any? {
            skipWs()
            if (i >= s.length) throw IllegalArgumentException("unexpected end of JSON")
            return when (s[i]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                else -> when {
                    s.startsWith("true", i) -> { i += 4; true }
                    s.startsWith("false", i) -> { i += 5; false }
                    s.startsWith("null", i) -> { i += 4; null }
                    else -> parseNumber()
                }
            }
        }

        fun parseObject(): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            i++ // '{'
            skipWs()
            if (i < s.length && s[i] == '}') { i++; return out }
            while (true) {
                skipWs()
                val key = parseString()
                skipWs()
                if (i >= s.length || s[i] != ':') throw IllegalArgumentException("expected ':' at $i")
                i++
                out[key] = parseValue()
                skipWs()
                if (i < s.length && s[i] == ',') { i++; continue }
                if (i >= s.length || s[i] != '}') throw IllegalArgumentException("expected '}' at $i")
                i++
                return out
            }
        }

        fun parseArray(): List<Any?> {
            val out = ArrayList<Any?>()
            i++ // '['
            skipWs()
            if (i < s.length && s[i] == ']') { i++; return out }
            while (true) {
                out.add(parseValue())
                skipWs()
                if (i < s.length && s[i] == ',') { i++; continue }
                if (i >= s.length || s[i] != ']') throw IllegalArgumentException("expected ']' at $i")
                i++
                return out
            }
        }

        fun parseString(): String {
            if (i >= s.length || s[i] != '"') throw IllegalArgumentException("expected string at $i")
            i++
            val sb = StringBuilder()
            while (true) {
                if (i >= s.length) throw IllegalArgumentException("unterminated string")
                when (val c = s[i]) {
                    '"' -> { i++; return sb.toString() }
                    '\\' -> {
                        i++
                        if (i >= s.length) throw IllegalArgumentException("unterminated escape")
                        when (val e = s[i]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                val hex = s.substring(i + 1, i + 5)
                                sb.append(hex.toInt(16).toChar())
                                i += 4
                            }
                            else -> throw IllegalArgumentException("bad escape \\$e")
                        }
                        i++
                    }
                    else -> { sb.append(c); i++ }
                }
            }
        }

        fun parseNumber(): Any {
            val start = i
            if (i < s.length && (s[i] == '-' || s[i] == '+')) i++
            while (i < s.length && s[i].isDigit()) i++
            var isFloat = false
            if (i < s.length && s[i] == '.') {
                isFloat = true
                i++
                while (i < s.length && s[i].isDigit()) i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                isFloat = true
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                while (i < s.length && s[i].isDigit()) i++
            }
            val tok = s.substring(start, i)
            if (tok.isEmpty() || tok == "-" || tok == "+") {
                throw IllegalArgumentException("invalid number at $start")
            }
            if (!isFloat) {
                tok.toLongOrNull()?.let { return it }
            }
            return tok.toDouble()
        }
    }
}
