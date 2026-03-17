//! Integration tests for external tools

use pentest_tools::create_tool_registry;

#[test]
fn test_external_tools_registered() {
    let registry = create_tool_registry();
    let tool_names = registry.names();

    println!("Registered tools ({}):", tool_names.len());
    for name in &tool_names {
        println!("  - {}", name);
    }

    // Phase 1 tools
    assert!(tool_names.contains(&"ffuf"), "FFUF tool should be registered");
    assert!(tool_names.contains(&"gobuster"), "Gobuster tool should be registered");
    assert!(tool_names.contains(&"nmap"), "Nmap tool should be registered");

    // Phase 2 tools
    assert!(tool_names.contains(&"rustscan"), "RustScan tool should be registered");
    assert!(tool_names.contains(&"masscan"), "Masscan tool should be registered");
    assert!(tool_names.contains(&"nikto"), "Nikto tool should be registered");
    assert!(tool_names.contains(&"dirb"), "Dirb tool should be registered");
    assert!(tool_names.contains(&"enum4linux"), "Enum4linux tool should be registered");
    assert!(tool_names.contains(&"hydra"), "Hydra tool should be registered");
    assert!(tool_names.contains(&"john"), "John tool should be registered");

    println!("✅ All 10 external tools are registered!");
}

#[test]
fn test_ffuf_schema() {
    let registry = create_tool_registry();
    let tool = registry
        .get("ffuf")
        .expect("FFUF tool should be in registry");

    let schema = tool.schema();
    assert_eq!(schema.name, "ffuf");
    assert!(!schema.description.is_empty());
    assert!(!schema.params.is_empty());

    // Check required parameters
    let url_param = schema
        .params
        .iter()
        .find(|p| p.name == "url")
        .expect("url parameter should exist");
    assert!(url_param.required, "url should be required");

    println!("✅ FFUF schema valid: {} params", schema.params.len());
}

#[test]
fn test_gobuster_schema() {
    let registry = create_tool_registry();
    let tool = registry
        .get("gobuster")
        .expect("Gobuster tool should be in registry");

    let schema = tool.schema();
    assert_eq!(schema.name, "gobuster");
    assert!(!schema.description.is_empty());

    // Check required parameters
    let mode_param = schema
        .params
        .iter()
        .find(|p| p.name == "mode")
        .expect("mode parameter should exist");
    assert!(mode_param.required, "mode should be required");

    let target_param = schema
        .params
        .iter()
        .find(|p| p.name == "target")
        .expect("target parameter should exist");
    assert!(target_param.required, "target should be required");

    println!("✅ Gobuster schema valid: {} params", schema.params.len());
}

#[test]
fn test_nmap_schema() {
    let registry = create_tool_registry();
    let tool = registry
        .get("nmap")
        .expect("Nmap tool should be in registry");

    let schema = tool.schema();
    assert_eq!(schema.name, "nmap");
    assert!(!schema.description.is_empty());

    // Check required parameters
    let target_param = schema
        .params
        .iter()
        .find(|p| p.name == "target")
        .expect("target parameter should exist");
    assert!(target_param.required, "target should be required");

    // Check optional parameters exist
    let scan_type_param = schema
        .params
        .iter()
        .find(|p| p.name == "scan_type")
        .expect("scan_type parameter should exist");
    assert!(
        !scan_type_param.required,
        "scan_type should be optional"
    );

    println!("✅ Nmap schema valid: {} params", schema.params.len());
}

#[test]
fn test_tool_count_increased() {
    let registry = create_tool_registry();
    let count = registry.names().len();

    // Before external tools: ~20 tools (varies based on pcap availability)
    // Phase 1: +3 tools (nmap, ffuf, gobuster)
    // Phase 2: +7 tools (rustscan, masscan, nikto, dirb, enum4linux, hydra, john)
    // Phase 3: +14 tools (web security tools)
    // Phase 4: +9 tools (post-exploitation)
    // Phase 5+: +12 tools (network, forensics, wireless, specialized)
    // Total: 62+ tools
    println!("✅ Tool count: {}", count);
    assert!(
        count >= 60,
        "Expected at least 60 tools, got {}",
        count
    );
}
