// Json.Parse — structured access via System.Text.Json, which ships IN THE
// .NET RUNTIME ITSELF (base class library since .NET Core 3.0 — no NuGet
// package, unlike Newtonsoft.Json/Json.NET). This is not a hand-rolled
// parser like the JVM SDK's kivi.Json or the Node.js SDK's parseJson —
// .NET's own BCL already has a safe one; this is a thin, ergonomic wrapper
// around it (object -> Dictionary, array -> List, and int64 kept as `long`,
// never silently widened through a `double` the way naive parsing would).
using System.Text.Json;

namespace Kivi;

public static class Json
{
    public static object? Parse(string text)
    {
        using var doc = JsonDocument.Parse(text);
        return Convert(doc.RootElement);
    }

    private static object? Convert(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.Object => ConvertObject(el),
        JsonValueKind.Array => ConvertArray(el),
        JsonValueKind.String => el.GetString(),
        JsonValueKind.Number => ConvertNumber(el),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => throw new ArgumentException($"unexpected JSON token: {el.ValueKind}"),
    };

    private static Dictionary<string, object?> ConvertObject(JsonElement el)
    {
        var d = new Dictionary<string, object?>();
        foreach (var prop in el.EnumerateObject()) d[prop.Name] = Convert(prop.Value);
        return d;
    }

    private static List<object?> ConvertArray(JsonElement el)
    {
        var list = new List<object?>();
        foreach (var item in el.EnumerateArray()) list.Add(Convert(item));
        return list;
    }

    /// <summary>Integers that fit in a `long` parse as a `long` (int64-safe,
    /// conformance S2's exact concern); anything else (fractional, or too
    /// large for a long) falls back to `double` — never silently truncated
    /// the way naive double-only parsing would.</summary>
    private static object ConvertNumber(JsonElement el)
    {
        if (el.TryGetInt64(out var l)) return l;
        return el.GetDouble();
    }
}
