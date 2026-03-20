#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! pentest-tools = { path = "crates/tools" }
//! pentest-core = { path = "crates/core" }
//! tokio = { version = "1", features = ["full"] }
//! serde_json = "1"
//! tracing-subscriber = "0.3"
//! ```

use pentest_core::tools::{ToolContext, Platform};
use pentest_tools::create_tool_registry;
use serde_json::json;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("🧪 Testing autopwn_webapp against DVWA");
    println!();

    // Create registry
    let registry = create_tool_registry();

    // Get the webapp toolchain tool
    let tool = registry.get("autopwn_webapp")
        .expect("autopwn_webapp should be registered");

    // Create parameters
    let params = json!({
        "target": "http://localhost:8080",
        "execution_mode": "autonomous",
        "attack_profile": "normal",
        "session_id": "dvwa_test"
    });

    // Create context
    let ctx = ToolContext {
        platform: Platform::Desktop,
        metadata: std::collections::HashMap::new(),
        workspace_path: None,
    };

    println!("▶ Executing toolchain...");
    println!();

    // Execute
    match tool.execute(params, &ctx).await {
        Ok(result) => {
            println!();
            println!("✅ Toolchain execution completed!");
            println!();
            println!("Result:");
            println!("{}", serde_json::to_string_pretty(&result.data).unwrap());
        }
        Err(e) => {
            eprintln!();
            eprintln!("❌ Toolchain execution failed: {}", e);
            std::process::exit(1);
        }
    }
}
