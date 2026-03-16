//! Runtime test for RustScan

use pentest_core::tools::{PentestTool, ToolContext};
use pentest_tools::external::RustScanTool;
use serde_json::json;

#[tokio::test]
#[ignore] // Requires sandbox environment
async fn test_rustscan_on_target() {
    println!("🎯 Testing RustScan on 10.10.2.169");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("");

    let tool = RustScanTool;
    let params = json!({
        "target": "10.10.2.169",
        "ports": "1-1000",
        "batch_size": 4500,
        "timeout": 1500,
        "accessible": true
    });

    let ctx = ToolContext::default();

    println!("📡 Executing RustScan...");
    println!("Target: 10.10.2.169");
    println!("Ports: 1-1000");
    println!("Mode: Fast scan (batch_size: 4500)");
    println!("");

    match tool.execute(params, &ctx).await {
        Ok(result) => {
            println!("✅ RustScan execution completed!");
            println!("");
            println!("📊 Full Results:");
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            println!("");

            if result.success {
                println!("✨ Scan successful!");
                println!("Duration: {} ms", result.duration_ms);

                if let Some(count) = result.data.get("count") {
                    println!("Open ports found: {}", count);
                }

                if let Some(ports) = result.data.get("open_ports").and_then(|v| v.as_array()) {
                    println!("");
                    println!("🔓 Open Ports:");
                    for port in ports {
                        if let Some(port_num) = port.get("port") {
                            println!("  - Port {}/tcp - OPEN", port_num);
                        }
                    }
                }
            } else {
                println!("⚠️ Scan completed with issues");
                if let Some(error) = &result.error {
                    println!("Error: {}", error);
                }
            }

            println!("");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
        Err(e) => {
            println!("❌ Error executing RustScan: {}", e);
            println!("");
            println!("This may be because:");
            println!("  1. RustScan is not installed (will auto-install on first run)");
            println!("  2. Sandbox permissions issue (bwrap needs user namespaces)");
            println!("  3. Target host unreachable");
            println!("  4. Network restrictions");
            println!("");
            println!("Error details: {:?}", e);
            println!("");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
    }
}
