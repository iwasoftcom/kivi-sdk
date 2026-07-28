# Publishing the kivi client SDKs

The six client SDKs are **MIT-licensed** and published to public registries. The
kivi **server and core stay proprietary** — only the client libraries are open.

One command publishes them, version-synced:

```bash
DRY_RUN=1 ./scripts/publish-sdks.sh 1.1.0     # build/pack everything, push nothing
./scripts/publish-sdks.sh 1.1.0               # the real thing (credentials required)
ONLY=rust,node ./scripts/publish-sdks.sh 1.1.0 # a subset
```

Registry pushes are **irreversible** — a published version cannot be replaced
(crates.io/PyPI/npm/Maven Central forbid re-publishing the same version). Always
run `DRY_RUN=1` first.

## Registry map

| SDK | Registry | Coordinates | Credential (env) |
|---|---|---|---|
| Rust | crates.io | `kivi-sdk` (imported as `kivi`) | `CARGO_REGISTRY_TOKEN` |
| Python | PyPI | `kivi-sdk` (imported as `kivi`) | `TWINE_USERNAME=__token__` `TWINE_PASSWORD=pypi-…` |
| Node | npm | `@iwasoft/kivi` | `NODE_AUTH_TOKEN` (or `npm login`) |
| Java/Kotlin | Maven Central | `com.iwasoft:kivi` | Central Portal token + GPG (below) |
| .NET | NuGet | `Iwasoft.Kivi` | `NUGET_API_KEY` |

## One-time setup (per registry — YOU do this once)

1. **crates.io** — log in with GitHub at crates.io, create an API token
   (Account → API Tokens). The crate publishes as `kivi-sdk` (crates.io `kivi` is taken) but is
   imported as `use kivi` via `[lib] name`. Rust consumers need `protoc` on PATH to build
   (the wire contract is compiled from the bundled proto).

2. **PyPI** — create an account, then an API token (Account → API tokens). The distribution is `kivi-sdk` (PyPI `kivi` is taken); the import stays `import kivi`.

3. **npm** — create the free **`@iwasoft` org** (npmjs.com → Add Organization),
   then a granular access token. Scoped packages avoid name collisions; the
   script already passes `--access public`.

4. **NuGet** — create a nuget.org account and an API key scoped to push new
   packages. `Iwasoft.Kivi` should be free; if a prefix reservation blocks it,
   pick another `PackageId`.

5. **Maven Central** — the heaviest, three parts:
   - **Account + namespace.** Register at central.sonatype.com (Central Portal).
     Claim the namespace **`com.iwasoft`** — Central verifies it by a DNS **TXT
     record on iwasoft.com** (you own the domain). Generate a **user token**
     (Portal → Account) and export it:
     ```bash
     export ORG_GRADLE_PROJECT_mavenCentralUsername=<token-user>
     export ORG_GRADLE_PROJECT_mavenCentralPassword=<token-pass>
     ```
   - **GPG signing key** (Central requires signed artifacts):
     ```bash
     gpg --quick-generate-key "iwasoft <you@iwasoft.com>" rsa4096
     gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>   # publish the public key
     export ORG_GRADLE_PROJECT_signingInMemoryKey="$(gpg --armor --export-secret-keys <KEY_ID>)"
     export ORG_GRADLE_PROJECT_signingInMemoryKeyPassword=<passphrase>
     ```
   - The build produces the jar + sources + javadoc jars automatically and
     uploads to the Central Portal (`publishAndReleaseToMavenCentral`).

## What the script does for you

- Verifies every manifest is on the same version before pushing anything.
- Refreshes the vendored proto copies (`clients/rust/kivi/proto`,
  `clients/nodejs/kivi.proto`) from the single source `api/kivi.proto`, so a
  published package never drifts from the contract.
- Builds/packs each SDK, then pushes (unless `DRY_RUN=1`).

## Bumping a version

Change it in all five manifests (the script checks they agree):
`clients/rust/kivi/Cargo.toml`, `clients/python/pyproject.toml`,
`clients/nodejs/package.json`, `clients/dotnet/Kivi.Client/Kivi.Client.csproj`,
`clients/jvm/build.gradle.kts`. These track the product version but are an
independent SemVer line for the SDK surface.
