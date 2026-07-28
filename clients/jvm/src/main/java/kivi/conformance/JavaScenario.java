// S15 — the pure-Java client's parity proof. Written in JAVA on purpose:
// compiling and running this file IS the claim ("full Java support" is not a
// facade note, it is an examined surface). Called by the JVM conformance
// runner after S1–S14 have populated the servers.
package kivi.conformance;

import kivi.Json;
import kivi.KiviJavaClient;
import kivi.NotFoundException;
import kivi.Receipt;
import kivi.Session;
import kivi.SimilarAnswer;
import kivi.TracedAnswer;
import kivi.UnauthenticatedException;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class JavaScenario {
    private JavaScenario() {}

    public static void run(String cleanAddr, String token, String authAddr) {
        // ---- the read contract, against the clean server ----------------------
        try (KiviJavaClient c = new KiviJavaClient(cleanAddr, token)) {
            TracedAnswer a = c.table("dog", "sound");
            check("\"woof\"".equals(a.getValueJson()) && !a.getTrace().isEmpty(),
                    "traced read: " + a.getValueJson());

            // time travel: record 0 was bark, overwritten later by woof (S1)
            TracedAnswer past = c.table("dog", "sound", 0L);
            check("\"bark\"".equals(past.getValueJson()) && past.getScope() == 0,
                    "as-of 0: " + past.getValueJson() + " scope=" + past.getScope());

            List<String> receipts = c.why(a.getTrace());
            check(receipts.size() == 1 && receipts.get(0).contains("\"type\":\"property\""),
                    "why fetched " + receipts.size() + " receipts");

            KiviJavaClient.Head head = c.head();
            check(head.no() == c.verifyLedger().getRecords() - 1
                            && head.hash().length() == 64,
                    "head disagrees with verify: " + head.no());

            try {
                c.table("ghost", "attr");
                throw new AssertionError("missing cell did not refuse");
            } catch (NotFoundException e) { /* honest refusal, never a null */ }

            // verified replay: count must match the audit's record count
            int n = 0;
            Iterator<String> it = c.replay(0, false);
            while (it.hasNext()) { it.next(); n++; }
            check(n == c.verifyLedger().getRecords(), "verified replay count " + n);

            // Subscribe (G14): server-side type filter, pure-Java client
            c.append("java-sub-other", "{\"i\":1}");
            c.append("java-sub-wanted", "{\"i\":2}");
            List<String> got = new java.util.ArrayList<>();
            Iterator<String> subIt = c.subscribe(0, false, List.of("java-sub-wanted"));
            while (subIt.hasNext()) got.add(subIt.next());
            check(got.size() == 1 && got.get(0).contains("\"type\":\"java-sub-wanted\""),
                    "java subscribe type filter: " + got);

            // QuerySubject (G15): whole-row traced read, pure-Java client
            c.append("property", "{\"subject\":\"java-subj-whole\",\"attribute\":\"a\",\"value\":1}");
            c.append("property", "{\"subject\":\"java-subj-whole\",\"attribute\":\"b\",\"value\":2}");
            TracedAnswer whole = c.subject("java-subj-whole");
            check("{\"a\":1,\"b\":2}".equals(whole.getValueJson()) && whole.getTrace().size() == 2,
                    "java subject whole row: " + whole.getValueJson());

            // Json.parse: dependency-free structured access, called from pure Java —
            // no Jackson/Gson, just the record turned into real Map/List/String/Long
            @SuppressWarnings("unchecked")
            Map<String, Object> parsedWhole = (Map<String, Object>) Json.parse(whole.getValueJson());
            check(Long.valueOf(1L).equals(parsedWhole.get("a")) && Long.valueOf(2L).equals(parsedWhole.get("b")),
                    "java Json.parse whole row: " + parsedWhole);

            Receipt jr = c.append("property",
                    "{\"subject\":\"json-rt-java\",\"attribute\":\"a\",\"value\":9007199254740993}");
            String recJson = c.getRecord(jr.getNo(), false);
            @SuppressWarnings("unchecked")
            Map<String, Object> rec = (Map<String, Object>) Json.parse(recJson);
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) rec.get("body");
            check(rec.get("no") instanceof Long && body.get("value").equals(9007199254740993L),
                    "java Json.parse int64 fidelity: " + body.get("value"));

            // typed entity round-trip, pure Java: give a record, get a record —
            // no hand-written JSON, int64 survives the typed path
            Receipt wr = c.append("widget", new Widget("cog", 9007199254740993L, new Size(3, 4)));
            Widget outW = c.getRecordBodyAs(wr.getNo(), false, Widget.class);
            check("cog".equals(outW.name()) && outW.weightG() == 9007199254740993L
                            && outW.size().w() == 3 && outW.size().h() == 4,
                    "java typed round-trip: " + outW.name() + "/" + outW.weightG());
        }

        // ---- identity + write + semantic, against the auth server -------------
        try (KiviJavaClient u = new KiviJavaClient(authAddr)) {
            try {
                u.login("conf-writer", "wrong-pass");
                throw new AssertionError("wrong password accepted");
            } catch (UnauthenticatedException e) { /* refused, honestly */ }

            Session sess = u.login("conf-writer", "conf-pass-123");
            check("writer".equals(sess.getRole()), "login role: " + sess.getRole());

            Receipt r = u.append("note", "{\"who\":\"java-client\"}");
            check(r.getNo() >= 0 && r.getHash().length() == 64,
                    "append via session: " + r.getNo());

            // per-call bearer over the same channel + traced similarity
            SimilarAnswer ans = u.withBearer(sess.getToken())
                    .similar("zebra exhibition painting", 3);
            check(!ans.getHits().isEmpty() && !ans.getModel().isEmpty()
                            && ans.getHits().get(0).getRecordJson().length() > 0,
                    "traced similar: " + ans.getHits().size() + " hits");

            // paged view reads: keyset walk pinned to one snapshot
            u.append("property", "{\"subject\":\"jvpgA\",\"attribute\":\"a\",\"value\":1}");
            u.append("property", "{\"subject\":\"jvpgB\",\"attribute\":\"a\",\"value\":2}");
            kivi.ViewPage p1 = u.viewPage("table", "jvpg", 1);
            check(p1.getEntries().size() == 1
                            && "jvpgA".equals(p1.getEntries().get(0).getKey())
                            && "jvpgA".equals(p1.getNextKey()),
                    "java page 1: " + p1.getNextKey());
            kivi.ViewPage p2 = u.viewPage("table", p1.getNextKey(), 10, p1.getScope());
            check(p2.getEntries().size() == 1
                            && "jvpgB".equals(p2.getEntries().get(0).getKey())
                            && p2.getHash().equals(p1.getHash()),
                    "java pinned page drifted");
        }
    }

    private static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    // typed entities for the round-trip proof (S20's Java face)
    record Size(long w, long h) {}
    record Widget(String name, long weightG, Size size) {}
}
