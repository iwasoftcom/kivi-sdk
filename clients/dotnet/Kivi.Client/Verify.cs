// Client-side verification (K3) — the untrusting client, .NET edition.
//
// Byte-fidelity strategy (same as the JVM SDK): the server sends CANONICAL
// JSON; the canonical CORE is recovered by SPLICING the raw bytes (a tiny
// span scanner drops the top-level "sig" and "hash" members). What gets
// hashed is byte-identical to what the writer hashed — no re-serialization,
// no number-formatting battles.
//
// Ed25519 is a self-contained pure-C# VERIFIER (RFC 8032, verify-only — no
// signing, no key handling). Chosen over a NuGet dependency by the SDK
// constitution (runtime deps: gRPC only); its correctness is proven by the
// conformance seal-tamper trap against Go-stdlib signatures.
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Kivi;

public class VerificationException(string message) : KiviException(message);

internal sealed class TopLevel
{
    public readonly byte[] Raw;
    public readonly Dictionary<string, (int From, int To)> Spans = new(); // [From, To)

    public TopLevel(byte[] raw)
    {
        Raw = raw;
        if (raw.Length == 0 || raw[0] != (byte)'{') throw Bad("no object");
        var i = 1;
        while (i < raw.Length && raw[i] != (byte)'}')
        {
            var memberStart = i - 1; // '{' or ','
            if (raw[i] != (byte)'"') throw Bad($"expected key at {i}");
            var keyEnd = ScanString(i);
            var key = Encoding.UTF8.GetString(raw, i + 1, keyEnd - i - 2);
            i = keyEnd;
            if (raw[i] != (byte)':') throw Bad($"expected ':' at {i}");
            i++;
            i = ScanValue(i);
            Spans[key] = (memberStart, i);
            if (i < raw.Length && raw[i] == (byte)',') i++;
        }
    }

    private static VerificationException Bad(string m) => new($"malformed record: {m}");

    private int ScanString(int from)
    {
        var i = from + 1;
        while (i < Raw.Length)
        {
            if (Raw[i] == (byte)'\\') i += 2;
            else if (Raw[i] == (byte)'"') return i + 1;
            else i++;
        }
        throw Bad("unterminated string");
    }

    private int ScanValue(int from)
    {
        var i = from;
        switch ((char)Raw[i])
        {
            case '"': return ScanString(i);
            case '{':
            case '[':
                var depth = 0;
                while (i < Raw.Length)
                {
                    var c = (char)Raw[i];
                    if (c == '"') { i = ScanString(i); continue; }
                    if (c is '{' or '[') depth++;
                    else if (c is '}' or ']') { depth--; if (depth == 0) return i + 1; }
                    i++;
                }
                throw Bad("unterminated container");
            default:
                while (i < Raw.Length && Raw[i] != (byte)',' && Raw[i] != (byte)'}') i++;
                return i;
        }
    }

    public byte[] CoreBytes()
    {
        if (!Spans.TryGetValue("sig", out var im) || !Spans.TryGetValue("hash", out var oz))
            throw Bad("missing sig/hash member");
        var drops = new[] { im, oz }.OrderBy(s => s.From).ToArray();
        using var ms = new MemoryStream(Raw.Length);
        var pos = 0;
        foreach (var (from, to) in drops)
        {
            ms.Write(Raw, pos, from - pos);
            pos = to;
        }
        ms.Write(Raw, pos, Raw.Length - pos);
        return ms.ToArray();
    }

    public string? StringField(string key)
    {
        if (!Spans.TryGetValue(key, out var s)) return null;
        var text = Encoding.UTF8.GetString(Raw, s.From, s.To - s.From);
        var v = text[(text.IndexOf(':') + 1)..];
        return v.StartsWith('"') ? v[1..^1] : v;
    }

    public long? LongField(string key) =>
        long.TryParse(StringField(key), out var v) ? v : null;
}

/// <summary>Shared by ChainChecker and RecordIntegrityChecker: one record's
/// OWN hash (and Ed25519 seal signature, for kivi.seal records), regardless
/// of whether gaps between records are expected. Returns the record's
/// number.</summary>
internal static class RecordIntegrity
{
    public static long Check(TopLevel top, bool checkSeals)
    {
        var no = top.LongField("no")
                 ?? throw new VerificationException("record without a number");
        var digest = Convert.ToHexStringLower(SHA256.HashData(top.CoreBytes()));
        if (digest != top.StringField("hash"))
            throw new VerificationException($"record {no}: hash mismatch — content altered");
        if (checkSeals && top.StringField("type") == "kivi.seal")
        {
            var body = top.Spans.TryGetValue("body", out var g)
                ? Encoding.UTF8.GetString(top.Raw, g.From, g.To - g.From)
                : throw new VerificationException($"seal {no}: no body");
            var m = System.Text.RegularExpressions.Regex.Match(body, "\"pk\":\"([0-9a-f]{64})\"");
            var sig = top.StringField("sig");
            if (!m.Success || sig is null or "null" ||
                !Ed25519.Verify(Convert.FromHexString(sig),
                    top.CoreBytes(), Convert.FromHexString(m.Groups[1].Value)))
                throw new VerificationException($"seal {no}: Ed25519 signature invalid");
        }
        return no;
    }
}

/// <summary>Verifies a replay stream record by record: hash, gapless
/// numbering, chain linkage and (optionally) Ed25519 seals.</summary>
public sealed class ChainChecker(bool checkSeals = true)
{
    private string? _prevHash;
    private long? _nextNo;

    public void Check(string recordJson)
    {
        var top = new TopLevel(Encoding.UTF8.GetBytes(recordJson));
        var no = RecordIntegrity.Check(top, checkSeals);
        if (_nextNo is { } want && no != want)
            throw new VerificationException($"numbering broken: expected {want}, got {no}");
        if (_prevHash is { } prev && top.StringField("prev_hash") != prev)
            throw new VerificationException($"record {no}: chain linkage broken");
        _prevHash = top.StringField("hash");
        _nextNo = no + 1;
    }
}

/// <summary>Subscribe's checker (G14): each record's OWN hash/signature is
/// verified, but — unlike ChainChecker — numbering gaps and prev_hash
/// discontinuities are EXPECTED (server-side type filtering causes them by
/// design) and are never treated as tampering.</summary>
public sealed class RecordIntegrityChecker(bool checkSeals = true)
{
    public void Check(string recordJson) =>
        RecordIntegrity.Check(new TopLevel(Encoding.UTF8.GetBytes(recordJson)), checkSeals);
}

/// <summary>Pure-C# Ed25519 verify (RFC 8032, verify-only).</summary>
public static class Ed25519
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger D =
        Mod(-121665 * Inv(121666));
    private static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);
    private static readonly (BigInteger, BigInteger, BigInteger, BigInteger) B;

    static Ed25519()
    {
        var by = Mod(4 * Inv(5));
        var bx = XRecover(by);
        B = (bx, by, 1, Mod(bx * by));
    }

    private static BigInteger Mod(BigInteger x) { var r = x % P; return r < 0 ? r + P : r; }
    private static BigInteger Inv(BigInteger x) => BigInteger.ModPow(Mod(x), P - 2, P);

    private static BigInteger XRecover(BigInteger y)
    {
        var xx = Mod((y * y - 1) * Inv(D * y * y + 1));
        var x = BigInteger.ModPow(xx, (P + 3) / 8, P);
        if (Mod(x * x - xx) != 0) x = Mod(x * I);
        if (Mod(x * x - xx) != 0) throw new VerificationException("not on curve");
        if (!x.IsEven) x = P - x;
        return x;
    }

    private static (BigInteger, BigInteger, BigInteger, BigInteger) Add(
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) p,
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) q)
    {
        var a = Mod((p.Y - p.X) * (q.Y - q.X));
        var b = Mod((p.Y + p.X) * (q.Y + q.X));
        var c = Mod(2 * p.T * q.T * D);
        var dd = Mod(2 * p.Z * q.Z);
        var (e, f, g, h) = (b - a, dd - c, dd + c, b + a);
        return (Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static (BigInteger, BigInteger, BigInteger, BigInteger) Mul(
        (BigInteger, BigInteger, BigInteger, BigInteger) p, BigInteger e)
    {
        var q = (BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        while (e > 0)
        {
            if (!e.IsEven) q = Add(q, p);
            p = Add(p, p);
            e >>= 1;
        }
        return q;
    }

    private static bool OnCurve(BigInteger x, BigInteger y) =>
        Mod(-x * x + y * y - 1 - D * x * x * y * y) == 0;

    private static (BigInteger, BigInteger, BigInteger, BigInteger) Decompress(byte[] s)
    {
        var y = new BigInteger(s, isUnsigned: true, isBigEndian: false) & ((BigInteger.One << 255) - 1);
        var sign = s[31] >> 7;
        y = Mod(y);
        var x = XRecover(y);
        if ((int)(x & 1) != sign) x = P - x;
        if (!OnCurve(x, y)) throw new VerificationException("point not on curve");
        return (x, y, 1, Mod(x * y));
    }

    private static byte[] Compress((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) p)
    {
        var zi = Inv(p.Z);
        var (x, y) = (Mod(p.X * zi), Mod(p.Y * zi));
        var enc = y | ((x & 1) << 255);
        var raw = enc.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Resize(ref raw, 32);
        return raw;
    }

    public static bool Verify(byte[] sig, byte[] msg, byte[] pk)
    {
        if (sig.Length != 64 || pk.Length != 32) return false;
        try
        {
            var a = Decompress(pk);
            var rEnc = sig[..32];
            _ = Decompress(rEnc);
            var s = new BigInteger(sig[32..], isUnsigned: true, isBigEndian: false);
            if (s >= L) return false;
            var kHash = SHA512.HashData([.. rEnc, .. pk, .. msg]);
            var k = new BigInteger(kHash, isUnsigned: true, isBigEndian: false) % L;
            var sb = Mul(B, s);
            var rka = Add(Decompress(rEnc), Mul(a, k));
            return Compress(sb).SequenceEqual(Compress(rka));
        }
        catch (VerificationException)
        {
            return false;
        }
    }
}
