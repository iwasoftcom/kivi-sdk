// kivi .NET SDK conformance runner (G3.0 scenarios S1–S10 + the parity
// scenarios S12–S14: identity/login, semantic similar, head + as-of).
// S10 = Task parity: .NET's async idiom, exercised concurrently, plus the sync facade.
using Kivi;

var pass = 0;
var total = 0;
const string BIG = "9007199254740993"; // 2^53+1 — dies in any double conversion

void Step(string name, Action body)
{
    total++;
    try
    {
        body();
        pass++;
        Console.WriteLine($"  {name}: ok");
    }
    catch (Exception e)
    {
        Console.WriteLine($"  {name}: FAIL — {e.GetType().Name}: {e.Message}");
    }
}

if (args.Length != 5)
{
    Console.Error.WriteLine("usage: runner <clean> <tamper-record> <tamper-seal> <token> <auth>");
    return 2;
}
var (cleanAddr, trAddr, tsAddr, token, authAddr) =
    (args[0], args[1], args[2], args[3], args[4]);
using var c = new KiviClient(cleanAddr, token);
Console.WriteLine("kivi .NET SDK conformance:");

Step("S1 receipt", () =>
{
    var r = c.Append("property", """{"subject":"dog","attribute":"sound","value":"bark"}""");
    if (r.No != 0 || r.Hash.Length != 64) throw new Exception($"{r}");
    var r2 = c.Append("property", """{"subject":"dog","attribute":"sound","value":"woof"}""");
    if (r2.No != 1 || r2.Offset <= r.Offset) throw new Exception($"{r2}");
});

Step("S2 int64 fidelity", () =>
{
    c.Append("property", $$$"""{"subject":"num","attribute":"big","value":{{{BIG}}}}""");
    var a = c.Table("num", "big");
    if (a.ValueJson != BIG) throw new Exception($"int64 mangled: {a.ValueJson}");
});

Step("S3 traced answers, honest refusals", () =>
{
    var a = c.Table("dog", "sound");
    if (a.Trace.Count == 0 || a.Scope <= 0 || a.ValueJson != "\"woof\"")
        throw new Exception($"{a}");
    try { c.Table("ghost", "attr"); throw new Exception("missing cell did not raise"); }
    catch (NotFoundException) { }
    try
    {
        _ = new TracedAnswer("1", [], 1);
        throw new Exception("a traceless answer was constructable");
    }
    catch (ArgumentException) { }
});

Step("S4 why", () =>
{
    var a = c.Table("num", "big");
    var recs = c.Why(a.Trace);
    if (recs.Count != 1 || !recs[0].Contains($"\"value\":{BIG}"))
        throw new Exception(string.Join("|", recs));
});

Step("S5 verified replay (clean)", () =>
{
    c.SealAsync().GetAwaiter().GetResult();
    var want = c.VerifyLedger().Records;
    var got = c.ReplayAll(verify: true).Count;
    if (got != want) throw new Exception($"replayed {got}, ledger holds {want}");
});

Step("S6 tamper trap (record)", () =>
{
    using var t = new KiviClient(trAddr);
    t.Append("note", """{"k":"tamper-me"}""");
    try { t.ReplayAll(verify: true); throw new Exception("corrupted record sailed through"); }
    catch (VerificationException) { }
});

Step("S7 tamper trap (seal)", () =>
{
    using var s = new KiviClient(tsAddr);
    s.Append("note", """{"k":1}""");
    s.SealAsync().GetAwaiter().GetResult();
    try { s.ReplayAll(verify: true); throw new Exception("forged seal sailed through"); }
    catch (VerificationException) { }
});

Step("S8 auth", () =>
{
    using var bare = new KiviClient(cleanAddr);
    try { bare.VerifyLedger(); throw new Exception("tokenless call accepted"); }
    catch (UnauthenticatedException) { }
    using var wrong = new KiviClient(cleanAddr, "wrong");
    try { wrong.VerifyLedger(); throw new Exception("wrong token accepted"); }
    catch (UnauthenticatedException) { }
    _ = c.VerifyLedger();
});

Step("S9 erase flow", () =>
{
    var r = c.AppendPrivate("note", new { v = "top-secret" });  // typed object overload
    var rec = c.GetRecordAsync(r.No, unseal: true).GetAwaiter().GetResult();
    if (!rec.Contains("top-secret")) throw new Exception(rec);
    c.EraseAsync(r.No, "conformance").GetAwaiter().GetResult();
    try
    {
        c.EraseAsync(r.No, "again").GetAwaiter().GetResult();
        throw new Exception("second erase did not fail");
    }
    catch (PreconditionException) { }
    var rec2 = c.GetRecordAsync(r.No, unseal: true).GetAwaiter().GetResult();
    if (rec2.Contains("top-secret") || !rec2.Contains("kivi.sealed")) throw new Exception(rec2);
});

Step("S10 Task parity (.NET async)", () =>
{
    var tasks = Enumerable.Range(0, 8).Select(g =>
        c.AppendAsync("metric", $$$"""{"series":"conc","value":{{{g}}}}""")).ToArray();
    Task.WhenAll(tasks).GetAwaiter().GetResult();
    var rep = c.VerifyLedgerAsync().GetAwaiter().GetResult();
    if (!rep.Ok) throw new Exception($"{rep}");
    var n = 0;
    var e = c.ReplayAsync(verify: true).GetAsyncEnumerator();
    while (e.MoveNextAsync().AsTask().GetAwaiter().GetResult()) n++;
    if (n != rep.Records) throw new Exception($"async replay {n} != {rep.Records}");
});

Step("S12 identity (login + per-call bearer)", () =>
{
    using var u = new KiviClient(authAddr);
    try { u.Login("conf-writer", "wrong-pass"); throw new Exception("wrong password accepted"); }
    catch (UnauthenticatedException) { }
    var sess = u.Login("conf-writer", "conf-pass-123");
    if (sess.Role != "writer" || sess.Token.Length == 0) throw new Exception($"{sess}");
    u.Append("note", """{"who":"conf-writer"}"""); // the session identity writes
    using var bare = new KiviClient(authAddr);
    try { bare.VerifyLedger(); throw new Exception("anonymous call accepted"); }
    catch (UnauthenticatedException) { }
    // per-call bearer: the same channel, another identity — stateless frontends
    _ = bare.WithBearer(sess.Token).VerifyLedger();
});

Step("S13 similar (traced semantic search)", () =>
{
    using var u = new KiviClient(authAddr, token);
    var r = u.Append("note", """{"text":"the zebra escaped the painting exhibition"}""");
    u.Append("note", """{"text":"database replication lag is boring"}""");
    var a = u.Similar("zebra exhibition painting", 3);
    if (a.Hits.Count == 0 || a.Hits[0].No != r.No)
        throw new Exception($"top hit is not the zebra record: {a.Hits.Count}");
    if (a.Model.Length == 0 || a.Scope < r.No || a.Hits[0].RecordJson.Length == 0)
        throw new Exception($"untraced similarity answer: {a}");
});

Step("S14 head + as-of (time travel)", () =>
{
    var (headNo, headHash) = c.Head();
    if (headNo != c.VerifyLedger().Records - 1 || headHash.Length != 64)
        throw new Exception($"head disagrees with verify: {headNo}");
    // record 0 was dog.sound=bark, later overwritten by woof (S1)
    var a = c.Table("dog", "sound", asOf: 0);
    if (a.ValueJson != "\"bark\"" || a.Scope != 0 ||
        a.Trace.Count != 1 || a.Trace[0] != 0) throw new Exception($"as-of 0: {a}");
    if (c.Table("dog", "sound").ValueJson != "\"woof\"")
        throw new Exception("time travel changed the present");
});

Step("S16 paged view reads (keyset + snapshot pinning)", () =>
{
    foreach (var s in new[] { "pgA", "pgB", "pgC" })
        c.Append("property", $$$"""{"subject":"{{{s}}}","attribute":"a","value":"{{{s}}}"}""");
    var p1 = c.ViewPage("table", afterKey: "pg", limit: 2);
    if (p1.Entries.Count != 2 || p1.Entries[0].Key != "pgA" || p1.Entries[1].Key != "pgB"
        || p1.NextKey != "pgB" || p1.Hash.Length != 64)
        throw new Exception($"page 1: {p1.NextKey} {p1.Entries.Count}");
    // a write lands BETWEEN pages — the pinned walk must not see it
    c.Append("property", """{"subject":"pgD","attribute":"a","value":4}""");
    var p2 = c.ViewPage("table", afterKey: p1.NextKey, limit: 10, asOf: p1.Scope);
    if (p2.Entries.Count != 1 || p2.Entries[0].Key != "pgC" || p2.NextKey != ""
        || p2.Hash != p1.Hash || p2.Scope != p1.Scope)
        throw new Exception("pinned page drifted");
    // an unpinned page tells today's truth
    var now = c.ViewPage("table", afterKey: "pg", limit: 10);
    if (now.Entries.Count != 4 || now.Hash == p1.Hash)
        throw new Exception($"unpinned page: {now.Entries.Count}");
});

Step("S17 Subscribe (type-filtered feed)", () =>
{
    c.Append("sub-other", """{"i":1}""");
    c.Append("sub-wanted", """{"i":2}""");
    var got = c.SubscribeAll(types: new[] { "sub-wanted" });
    if (got.Count != 1 || !got[0].Contains("\"type\":\"sub-wanted\""))
        throw new Exception($"type filter leaked or missed a record: {got.Count}");
});

Step("S18 QuerySubject (whole-row read)", () =>
{
    c.Append("property", """{"subject":"subj-whole","attribute":"a","value":1}""");
    c.Append("property", """{"subject":"subj-whole","attribute":"b","value":2}""");
    var a = c.Subject("subj-whole");
    if (a.ValueJson != """{"a":1,"b":2}""" || a.Trace.Count != 2)
        throw new Exception($"whole row wrong: {a.ValueJson}");
});

Step("S19 Json.Parse (System.Text.Json, int64-safe)", () =>
{
    var obj = (Dictionary<string, object?>)Json.Parse(
        $$"""{"policy_id":"POL1111","limit":{{BIG}},"tags":["a","b"],"active":true,"note":null}""")!;
    if ((string)obj["policy_id"]! != "POL1111")
        throw new Exception($"string field: {obj["policy_id"]}");
    if ((long)obj["limit"]! != long.Parse(BIG))
        throw new Exception($"int64 fidelity lost: {obj["limit"]}");
    var tags = (List<object?>)obj["tags"]!;
    if (tags.Count != 2 || (string)tags[0]! != "a")
        throw new Exception($"array: {string.Join(",", tags)}");
    if ((bool)obj["active"]! != true)
        throw new Exception($"bool: {obj["active"]}");
    if (!obj.ContainsKey("note") || obj["note"] != null)
        throw new Exception("null field wrong");

    // round-trip against a REAL record from the server
    var jr = c.Append("property", """{"subject":"json-rt","attribute":"a","value":9007199254740993}""");
    var recJson = c.GetRecordAsync(jr.No).GetAwaiter().GetResult();
    var rec = (Dictionary<string, object?>)Json.Parse(recJson)!;
    var body = (Dictionary<string, object?>)rec["body"]!;
    if (rec["no"] is not long || (long)body["value"]! != long.Parse(BIG))
        throw new Exception($"record round-trip: {body["value"]}");
});

Step("S20 typed entity round-trip (entity in, entity out)", () =>
{
    var r = c.Append("widget", new Widget("cog", long.Parse(BIG), new Size(3, 4)));
    var outw = c.GetRecordBodyAs<Widget>(r.No);
    if (outw.Name != "cog" || outw.WeightG != long.Parse(BIG))
        throw new Exception($"typed round-trip: {outw.Name}/{outw.WeightG}");
    if (outw.Size.W != 3 || outw.Size.H != 4)
        throw new Exception($"nested: {outw.Size}");
});

var verdict = pass == total ? "PASS" : "FAIL";
Console.WriteLine($"CONFORMANCE {verdict} {pass}/{total}");
return pass == total ? 0 : 1;

record Size(long W, long H);
record Widget(string Name, long WeightG, Size Size);
