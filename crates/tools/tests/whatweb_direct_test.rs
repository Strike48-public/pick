//! Direct test of whatweb tool
//! Run with: cargo test --test whatweb_direct_test -- --nocapture --ignored

use pentest_core::tools::ToolContext;
use pentest_tools::create_tool_registry;
use serde_json::json;

#[tokio::test]
#[ignore]
async fn test_whatweb_direct() {
    eprintln!("\n🧪 Testing whatweb tool directly against DVWA\n");

    let registry = create_tool_registry();
    let tool = registry
        .get("whatweb")
        .expect("whatweb should be registered");

    let params = json!({
        "url": "http://localhost:8080"
    });

    let ctx = ToolContext::default();

    eprintln!("▶ Executing whatweb...\n");

    let result = tool.execute(params, &ctx).await;

    match &result {
        Ok(r) => {
            eprintln!("✅ Success: {}", r.success);
            eprintln!("Duration: {}ms", r.duration_ms);
            eprintln!("\nData:");
            eprintln!("{}", serde_json::to_string_pretty(&r.data).unwrap());

            if let Some(error) = &r.error {
                eprintln!("\nError: {}", error);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed: {}", e);
        }
    }

    assert!(result.is_ok(), "whatweb should execute successfully");
    let r = result.unwrap();
    assert!(r.success, "whatweb should return success=true");

    eprintln!("\n✅ Test passed!");
}
