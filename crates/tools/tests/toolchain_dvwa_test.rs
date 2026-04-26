//! Live test of toolchain against DVWA
//! Run with: cargo test --test toolchain_dvwa_test -- --nocapture --ignored

use pentest_core::tools::ToolContext;
use pentest_tools::create_tool_registry;
use serde_json::json;

#[tokio::test]
#[ignore] // Run explicitly with --ignored flag
async fn test_autopwn_webapp_dvwa() {
    eprintln!("\n🧪 Starting DVWA Toolchain Test\n");

    // Check if DVWA is accessible
    let response = reqwest::get("http://localhost:8080")
        .await
        .expect("DVWA should be running on localhost:8080");

    assert!(
        response.status().is_success() || response.status().is_redirection(),
        "DVWA should respond with 2xx or 3xx status"
    );

    println!("✓ DVWA is accessible at http://localhost:8080");
    println!();

    // Create registry
    let registry = create_tool_registry();

    // Get the webapp toolchain
    let tool = registry
        .get("autopwn_webapp")
        .expect("autopwn_webapp should be registered");

    // Prepare parameters
    let params = json!({
        "target": "http://localhost:8080",
        "execution_mode": "autonomous",
        "attack_profile": "normal",
        "session_id": "dvwa_live_test"
    });

    // Create context
    let ctx = ToolContext::default();

    println!("═══════════════════════════════════════════════════");
    println!("🎯 Starting autopwn_webapp Live Test");
    println!("═══════════════════════════════════════════════════");
    println!();

    // Execute the toolchain
    let result = tool
        .execute(params, &ctx)
        .await
        .expect("Toolchain execution should succeed");

    println!();
    println!("═══════════════════════════════════════════════════");
    println!("✅ Toolchain Execution Complete");
    println!("═══════════════════════════════════════════════════");
    println!();

    // Verify result structure
    assert!(result.success, "Toolchain should complete successfully");

    let data = &result.data;
    assert!(data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
    assert_eq!(
        data.get("target").and_then(|v| v.as_str()),
        Some("http://localhost:8080")
    );

    // Print report
    if let Some(report) = data.get("report") {
        println!("📊 Execution Report:");
        println!("{}", serde_json::to_string_pretty(report).unwrap());
        println!();

        // Verify report structure
        assert!(
            report.get("progress").is_some(),
            "Report should have progress"
        );
        assert!(
            report.get("findings").is_some(),
            "Report should have findings"
        );
        assert!(
            report.get("tools_executed").is_some(),
            "Report should have tools_executed"
        );
    }

    println!("✅ All assertions passed!");
}
