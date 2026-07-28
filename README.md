# Kivi client SDKs

The MIT-licensed client SDKs for [Kivi](https://iwasoft.com) — an event-ledger
database in which only events are durable, representations are compiled, and no
answer comes without a trace. The Kivi server and core are a separate,
proprietary product; this repository is only the open clients + the wire
contract (`api/kivi.proto`).

## Install

| Language | Registry | Install |
|---|---|---|
| Rust | crates.io | `cargo add kivi-sdk` (import as `use kivi::…`) |
| Python | PyPI | `pip install kivi-sdk` (import as `import kivi`) |
| Node.js | npm | `npm install @iwasoft/kivi` |
| Java / Kotlin | Maven Central | `com.iwasoft:kivi:1.1.0` |
| .NET | NuGet | `dotnet add package Iwasoft.Kivi` |

Publishing is automated (`.github/workflows/build.yml`, NuGet Trusted
Publishing / OIDC). See `clients/PUBLISHING.md`.
