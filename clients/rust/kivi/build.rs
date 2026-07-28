// Codegen at build time from the contract in proto/kivi.proto — a vendored copy
// of the canonical api/kivi.proto so the published crate builds standalone
// (the publish script refreshes it from the source of truth). Needs a `protoc`
// on PATH or PROTOC set (see clients/rust/README.md).
fn main() {
    tonic_build::configure()
        .build_server(false) // this crate is a CLIENT only
        .compile_protos(&["proto/kivi.proto"], &["proto"])
        .expect("failed to compile kivi.proto — is protoc on PATH? (set PROTOC=/path/to/protoc)");
    println!("cargo:rerun-if-changed=proto/kivi.proto");
}
