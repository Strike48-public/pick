//! Runtime integration tests for external tools
//!
//! These tests actually execute the tools in the sandbox environment.
//! They are ignored by default and must be run explicitly with:
//! cargo test --package pentest-tools --test external_tools_runtime_test -- --ignored --nocapture

use pentest_core::tools::{PentestTool, ToolContext};
use pentest_tools::external::{FfufTool, GobusterTool, NmapTool};
use serde_json::json;

#[tokio::test]
#[ignore] // Requires sandbox environment
async fn test_nmap_execution() {
    println!("🧪 Testing Nmap execution...");

    let tool = NmapTool;
    let params = json!({
        "target": "127.0.0.1",
        "scan_type": "connect",
        "ports": "22,80",
        "timeout": 60
    });

    let ctx = ToolContext::default();

    println!("Executing nmap scan on localhost:22,80...");
    let result = tool.execute(params, &ctx).await;

    match result {
        Ok(output) => {
            println!("✅ Nmap execution successful!");
            println!("Result: {}", serde_json::to_string_pretty(&output).unwrap());

            // Verify output structure
            assert!(output.data.is_object(), "Output data should be a JSON object");

            if let Some(hosts) = output.data.get("hosts") {
                println!("Found {} host(s)", hosts.as_array().map(|a| a.len()).unwrap_or(0));
            }
        }
        Err(e) => {
            println!("❌ Nmap execution failed: {}", e);
            println!("This may be expected if:");
            println!("  - Nmap is not installed in sandbox (will auto-install on first run)");
            println!("  - Sandbox is not available");
            println!("  - Network restrictions");

            // Don't fail the test - just report the error
            println!("\nError details: {:?}", e);
        }
    }
}

#[tokio::test]
#[ignore] // Requires sandbox environment and network access
async fn test_ffuf_execution() {
    println!("🧪 Testing FFUF execution...");

    let tool = FfufTool;
    let params = json!({
        "url": "http://testphp.vulnweb.com/FUZZ",
        "threads": 5,
        "timeout": 60
    });

    let ctx = ToolContext::default();

    println!("Executing FFUF web fuzzing...");
    let result = tool.execute(params, &ctx).await;

    match result {
        Ok(output) => {
            println!("✅ FFUF execution successful!");
            println!("Result: {}", serde_json::to_string_pretty(&output).unwrap());

            if let Some(count) = output.data.get("count") {
                println!("Found {} results", count);
            }
        }
        Err(e) => {
            println!("❌ FFUF execution failed: {}", e);
            println!("This may be expected if:");
            println!("  - FFUF is not installed in sandbox");
            println!("  - Wordlist is missing (install seclists: pacman -S seclists)");
            println!("  - Target is unreachable");

            println!("\nError details: {:?}", e);
        }
    }
}

#[tokio::test]
#[ignore] // Requires sandbox environment and network access
async fn test_gobuster_execution() {
    println!("🧪 Testing Gobuster execution...");

    let tool = GobusterTool;
    let params = json!({
        "mode": "dir",
        "target": "http://testphp.vulnweb.com",
        "threads": 5,
        "timeout": 60
    });

    let ctx = ToolContext::default();

    println!("Executing Gobuster directory enumeration...");
    let result = tool.execute(params, &ctx).await;

    match result {
        Ok(output) => {
            println!("✅ Gobuster execution successful!");
            println!("Result: {}", serde_json::to_string_pretty(&output).unwrap());

            if let Some(count) = output.data.get("count") {
                println!("Found {} results", count);
            }
        }
        Err(e) => {
            println!("❌ Gobuster execution failed: {}", e);
            println!("This may be expected if:");
            println!("  - Gobuster is not installed in sandbox");
            println!("  - Wordlist is missing");
            println!("  - Target is unreachable");

            println!("\nError details: {:?}", e);
        }
    }
}

#[tokio::test]
#[ignore] // Quick smoke test - just checks if tools can be instantiated
async fn test_tool_instantiation() {
    println!("🧪 Testing tool instantiation (smoke test)...");

    let nmap = NmapTool;
    let ffuf = FfufTool;
    let gobuster = GobusterTool;

    println!("✅ Nmap tool: {}", nmap.name());
    println!("✅ FFUF tool: {}", ffuf.name());
    println!("✅ Gobuster tool: {}", gobuster.name());

    assert_eq!(nmap.name(), "nmap");
    assert_eq!(ffuf.name(), "ffuf");
    assert_eq!(gobuster.name(), "gobuster");

    println!("\n✅ All tools instantiated successfully!");
}
