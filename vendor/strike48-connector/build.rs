fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = std::process::Command::new(&rustc)
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // "rustc 1.82.0 (f6e511eec 2024-10-15)" -> "1.82.0"
    let version = output
        .split_whitespace()
        .nth(1)
        .unwrap_or("unknown")
        .to_string();

    println!("cargo:rustc-env=SDK_RUSTC_VERSION={version}");

    let target = std::env::var("TARGET").expect("TARGET is always set by Cargo");
    println!("cargo:rustc-env=SDK_TARGET={target}");

    // Compile server-side gRPC stubs for the in-process mock matrix server
    // used by `tests/common/mock_grpc_server.rs`. The production code path
    // pulls only client stubs from `strike48-proto`; this generates the
    // server trait/scaffolding into the connector crate's own `OUT_DIR` so
    // the integration test can include them without taking on a
    // path-dependency to a separate fixture crate.
    //
    // The proto file lives outside the crate (`../proto/proto/...`) and is
    // therefore NOT included in the published tarball. When this build
    // script runs inside crates.io's publish-verify (which extracts the
    // tarball and runs `cargo build` in isolation), the path does not
    // exist. `cargo build` does not compile `tests/`, so the mock-server
    // stubs are unused in that context — skip generation when the proto
    // is unreachable.
    let proto = "../proto/proto/connector_service.proto";
    let proto_dir = "../proto/proto";
    println!("cargo:rerun-if-changed={proto}");

    if std::path::Path::new(proto).exists() {
        tonic_build::configure()
            .build_server(true)
            .build_client(false)
            .protoc_arg("--experimental_allow_proto3_optional")
            .compile_protos(&[proto], &[proto_dir])
            .expect("compile mock-server proto stubs");
    } else {
        println!(
            "cargo:warning=skipping mock-server proto stubs: {proto} not present \
             (expected in publish-verify or out-of-workspace builds; integration \
             tests in tests/ are not compiled in this context)"
        );
    }
}
