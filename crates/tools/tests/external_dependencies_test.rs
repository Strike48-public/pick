//! Test external dependency metadata

use pentest_tools::create_tool_registry;

#[test]
fn test_external_tools_declare_dependencies() {
    let registry = create_tool_registry();

    // External tools that should have dependencies
    let external_tools = vec![
        "nmap", "ffuf", "gobuster", "rustscan", "masscan",
        "nikto", "dirb", "enum4linux", "hydra", "john"
    ];

    for tool_name in &external_tools {
        let tool = registry.get(tool_name)
            .unwrap_or_else(|| panic!("{} tool should be registered", tool_name));

        let schema = tool.schema();

        assert!(
            schema.has_external_dependencies(),
            "{} should declare external dependencies",
            tool_name
        );

        assert!(
            !schema.external_dependencies.is_empty(),
            "{} should have at least one external dependency",
            tool_name
        );

        // Verify the dependency has the expected binary name
        let dep = &schema.external_dependencies[0];
        assert_eq!(
            dep.binary_name, *tool_name,
            "{} should have binary_name matching tool name",
            tool_name
        );
        assert_eq!(
            dep.package_name, *tool_name,
            "{} should have package_name matching tool name",
            tool_name
        );
        assert!(
            !dep.description.is_empty(),
            "{} dependency should have a description",
            tool_name
        );

        println!("✅ {} declares dependency: {} ({})", tool_name, dep.binary_name, dep.description);
    }

    println!("\n✅ All {} external tools properly declare their dependencies!", external_tools.len());
}

#[test]
fn test_native_tools_no_external_dependencies() {
    let registry = create_tool_registry();

    // Sample native tools that should NOT have external dependencies
    let native_tools = vec!["port_scan", "web_vuln_scan", "smb_enum"];

    for tool_name in &native_tools {
        if let Some(tool) = registry.get(tool_name) {
            let schema = tool.schema();
            assert!(
                !schema.has_external_dependencies(),
                "{} is a native tool and should not declare external dependencies",
                tool_name
            );
        }
    }

    println!("✅ Native tools correctly have no external dependencies");
}

#[test]
fn test_dependency_json_serialization() {
    let registry = create_tool_registry();
    let tool = registry.get("nmap").expect("nmap should be registered");

    let schema = tool.schema();
    let json_schema = schema.to_json_schema();

    // Check that external_dependencies is included in JSON output
    assert!(
        json_schema.get("external_dependencies").is_some(),
        "JSON schema should include external_dependencies field"
    );

    let deps = json_schema["external_dependencies"].as_array()
        .expect("external_dependencies should be an array");

    assert!(!deps.is_empty(), "nmap should have at least one dependency");

    let dep = &deps[0];
    assert_eq!(dep["binary_name"].as_str().unwrap(), "nmap");
    assert_eq!(dep["package_name"].as_str().unwrap(), "nmap");
    assert!(!dep["description"].as_str().unwrap().is_empty());

    println!("✅ External dependencies properly serialize to JSON");
    println!("JSON output: {}", serde_json::to_string_pretty(&json_schema).unwrap());
}
