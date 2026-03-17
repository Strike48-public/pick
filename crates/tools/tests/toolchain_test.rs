//! Integration tests for toolchain execution

use pentest_tools::create_tool_registry;

#[test]
fn test_webapp_toolchain_registered() {
    let registry = create_tool_registry();
    let tool_names = registry.names();

    assert!(
        tool_names.contains(&"autopwn_webapp"),
        "WebApp toolchain should be registered"
    );

    println!("✅ autopwn_webapp tool is registered!");
}

#[test]
fn test_webapp_toolchain_schema() {
    let registry = create_tool_registry();
    let tool = registry
        .get("autopwn_webapp")
        .expect("WebApp toolchain should be in registry");

    let schema = tool.schema();
    assert_eq!(schema.name, "autopwn_webapp");
    assert!(!schema.description.is_empty());

    // Check required parameters
    let target_param = schema
        .params
        .iter()
        .find(|p| p.name == "target")
        .expect("target parameter should exist");
    assert!(target_param.required, "target should be required");

    println!("✅ autopwn_webapp schema valid: {} params", schema.params.len());
}

#[test]
fn test_total_tool_count() {
    let registry = create_tool_registry();
    let count = registry.names().len();

    // Should have 100 external tools + autopwn_webapp + other built-in tools
    println!("✅ Total tools registered: {}", count);
    assert!(count >= 101, "Expected at least 101 tools (100 external + webapp toolchain), got {}", count);
}
