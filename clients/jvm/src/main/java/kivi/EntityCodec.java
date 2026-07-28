// kivi JVM SDK — the pluggable body (de)serializer seam.
//
// kivi's typed layer ("entity in, entity out") turns your record/POJO into the
// event body JSON and back. By DEFAULT it uses kivi's own zero-dependency
// mapper (Json) — the core artifact imports and pins NO JSON framework.
//
// If you'd rather map with Jackson, Gson, or kotlinx.serialization, implement
// this interface with your own library and hand it to withCodec(...). Your JSON
// stack, your version — the kivi core never sees it. Example with Jackson:
//
//   final class JacksonCodec implements EntityCodec {
//       final ObjectMapper om = new ObjectMapper();
//       public String toJson(Object e) {
//           try { return om.writeValueAsString(e); }
//           catch (Exception x) { throw new RuntimeException(x); }
//       }
//       public <T> T fromJson(String json, Class<T> cls) {
//           try { return om.readValue(json, cls); }
//           catch (Exception x) { throw new RuntimeException(x); }
//       }
//   }
//   var c = new KiviJavaClient(addr, token).withCodec(new JacksonCodec());
//
// The server re-canonicalizes every body on write (keys sorted), so whatever
// order your codec emits fields in never affects the stored bytes or the hash.
// int64 fidelity is your entity's business: a `long` field survives; an
// `Object`/`double` field dies at 2^53 — same rule for every codec.
package kivi;

/** A pluggable entity &lt;-&gt; JSON codec. The default is kivi's built-in,
 *  dependency-free {@link Json} mapper; bring your own via
 *  {@code KiviJavaClient.withCodec(...)} / {@code KiviClient.withCodec(...)}. */
public interface EntityCodec {

    /** Serialize an entity (record/POJO/Map/List) to a JSON body string. */
    String toJson(Object entity);

    /** Map a JSON body string into an entity of type {@code cls}. */
    <T> T fromJson(String json, Class<T> cls);

    /** kivi's built-in codec: reflection over records, zero dependencies. */
    EntityCodec DEFAULT = new EntityCodec() {
        @Override public String toJson(Object entity) { return Json.encode(entity); }
        @Override public <T> T fromJson(String json, Class<T> cls) { return Json.mapTo(json, cls); }
    };
}
