//! Integration tests for the Webwright tool pipeline.
//!
//! These tests exercise the full flow:
//! - Execute mode with a Python script that creates artifacts
//! - Workspace creation, artifact collection, and evidence ingestion
//! - Verifies screenshots, scripts, findings all flow through correctly
//!
//! Run with: `DISABLE_SANDBOX=true cargo test -p pentest-tools --test webwright_integration`
//! (Sandbox must be disabled for Python to execute directly on the host)

use pentest_core::tools::{PentestTool, ToolContext};
use pentest_tools::evidence_producer::drain_pending_evidence;
use pentest_tools::webwright::evidence::{ingest_webwright_evidence, ingest_webwright_findings};
use pentest_tools::webwright::workspace::WebwrightWorkspace;
use pentest_tools::WebwrightTool;
use serde_json::json;

/// Test that execute mode runs a Python script and captures output.
#[tokio::test]
#[ignore = "Requires bwrap-capable sandbox to auto-install webwright - unavailable on GitHub Actions runners"]
async fn execute_mode_runs_script_and_captures_output() {
    let tool = WebwrightTool;
    let ctx = ToolContext::default();

    let script = r##"
import json
result = {"status": "complete", "findings": 0, "pages_visited": 3}
print(json.dumps(result))
"##;

    let params = json!({
        "mode": "execute",
        "start_url": "https://example.com",
        "script": script,
        "timeout": 30,
    });

    let result = tool.execute(params, &ctx).await.unwrap();

    assert!(result.success, "Tool should succeed: {:?}", result.error);
    assert!(result.provenance.is_some(), "Should have provenance");

    let data = &result.data;
    assert_eq!(data["mode"], "execute");
    assert_eq!(data["start_url"], "https://example.com");
    assert_eq!(data["exit_code"], 0);

    let stdout = data["stdout"].as_str().unwrap();
    assert!(
        stdout.contains("complete"),
        "Should capture script stdout: {}",
        stdout
    );

    let prov = result.provenance.unwrap();
    assert_eq!(prov.underlying_tool, "webwright");
    assert_eq!(prov.tool_version, "0.1.0");
}

/// Test that execute mode script can create artifacts that get collected.
#[tokio::test]
#[ignore = "Requires bwrap-capable sandbox to auto-install webwright - unavailable on GitHub Actions runners"]
async fn execute_mode_collects_script_artifacts() {
    let tool = WebwrightTool;
    let ctx = ToolContext::default();

    // Script that creates artifacts in its workspace directory.
    // Uses __file__ to locate workspace (same dir as the script).
    let script = r##"
import os, json

workspace = os.path.dirname(os.path.abspath(__file__))

# Create a generated exploit script
with open(os.path.join(workspace, "exploit_xss.py"), "w") as f:
    f.write("from playwright.sync_api import sync_playwright\n")

# Create a fake screenshot
with open(os.path.join(workspace, "screenshot_login.png"), "wb") as f:
    f.write(b"\x89PNG fake screenshot data here")

# Create a findings.json
findings = [
    {
        "title": "Reflected XSS in search parameter",
        "description": "The search parameter reflects user input without encoding",
        "severity": "high",
        "type": "xss",
        "url": "https://example.com/search?q=<script>alert(1)</script>"
    },
    {
        "title": "Missing CSRF token on form",
        "description": "Login form does not include CSRF protection",
        "severity": "medium",
        "type": "csrf",
        "url": "https://example.com/login"
    }
]
with open(os.path.join(workspace, "findings.json"), "w") as f:
    json.dump(findings, f)

# Create a network log
with open(os.path.join(workspace, "network_log.json"), "w") as f:
    json.dump({"requests": [{"url": "https://example.com/login", "status": 200}]}, f)

# Create a DOM snapshot
with open(os.path.join(workspace, "dom_snapshot_login.html"), "w") as f:
    f.write("<html><body><form action='/login'><input name='user'></form></body></html>")

# Create agent reasoning log
with open(os.path.join(workspace, "agent_reasoning.log"), "w") as f:
    f.write("Step 1: Navigated to login page\nStep 2: Identified form inputs\n")

print(json.dumps({"status": "complete", "artifacts_created": 6}))
"##;

    let params = json!({
        "mode": "execute",
        "start_url": "https://example.com",
        "script": script,
        "timeout": 30,
    });

    // Drain any pre-existing evidence
    let _ = drain_pending_evidence();

    let result = tool.execute(params, &ctx).await.unwrap();

    assert!(result.success, "Tool should succeed: {:?}", result.error);

    let data = &result.data;
    let artifacts = &data["artifacts"];

    // Verify artifacts were collected by category
    let scripts = artifacts["scripts"].as_array().unwrap();
    assert!(
        scripts
            .iter()
            .any(|s| s.as_str().unwrap().contains("exploit_xss.py")),
        "Should find exploit script in artifacts: {:?}",
        scripts
    );

    let screenshots = artifacts["screenshots"].as_array().unwrap();
    assert!(
        screenshots
            .iter()
            .any(|s| s.as_str().unwrap().contains("screenshot_login.png")),
        "Should find screenshot in artifacts: {:?}",
        screenshots
    );

    let logs = artifacts["logs"].as_array().unwrap();
    assert!(
        logs.iter()
            .any(|s| s.as_str().unwrap().contains("findings.json")),
        "Should find findings.json in logs: {:?}",
        logs
    );
    assert!(
        logs.iter()
            .any(|s| s.as_str().unwrap().contains("network_log.json")),
        "Should find network_log in logs: {:?}",
        logs
    );
    assert!(
        logs.iter()
            .any(|s| s.as_str().unwrap().contains("agent_reasoning.log")),
        "Should find agent reasoning log: {:?}",
        logs
    );

    let snapshots = artifacts["dom_snapshots"].as_array().unwrap();
    assert!(
        snapshots
            .iter()
            .any(|s| s.as_str().unwrap().contains("dom_snapshot_login.html")),
        "Should find DOM snapshot in artifacts: {:?}",
        snapshots
    );

    // Verify evidence was ingested
    let evidence = drain_pending_evidence();
    assert!(
        !evidence.is_empty(),
        "Should have produced evidence nodes, got 0"
    );

    // Check for specific evidence types
    let script_evidence: Vec<_> = evidence
        .iter()
        .filter(|e| e.node_type == "browser_exploit_script")
        .collect();
    assert!(
        !script_evidence.is_empty(),
        "Should have exploit script evidence"
    );

    let screenshot_evidence: Vec<_> = evidence
        .iter()
        .filter(|e| e.node_type == "browser_screenshot")
        .collect();
    assert!(
        !screenshot_evidence.is_empty(),
        "Should have screenshot evidence"
    );

    let finding_evidence: Vec<_> = evidence
        .iter()
        .filter(|e| e.node_type == "browser_finding")
        .collect();
    assert!(
        !finding_evidence.is_empty(),
        "Should have browser finding evidence from findings.json"
    );

    // Verify finding details
    let xss_finding = finding_evidence
        .iter()
        .find(|e| e.title.contains("XSS"))
        .expect("Should have XSS finding");
    assert_eq!(
        xss_finding.current_severity(),
        pentest_core::export::Severity::High,
        "XSS finding should be High severity"
    );
    assert!(
        xss_finding.provenance.is_some(),
        "Finding should have provenance"
    );

    let csrf_finding = finding_evidence
        .iter()
        .find(|e| e.title.contains("CSRF"))
        .expect("Should have CSRF finding");
    assert_eq!(
        csrf_finding.current_severity(),
        pentest_core::export::Severity::Medium,
        "CSRF finding should be Medium severity"
    );
}

/// Test that explore mode rejects missing task parameter.
#[tokio::test]
async fn explore_mode_requires_task_parameter() {
    let tool = WebwrightTool;
    let ctx = ToolContext::default();

    let params = json!({
        "mode": "explore",
        "start_url": "https://example.com",
    });

    let result = tool.execute(params, &ctx).await.unwrap();
    assert!(!result.success);
    assert!(result
        .error
        .as_ref()
        .unwrap()
        .contains("task parameter is required"));
}

/// Test that execute mode rejects missing script parameter.
#[tokio::test]
async fn execute_mode_requires_script_parameter() {
    let tool = WebwrightTool;
    let ctx = ToolContext::default();

    let params = json!({
        "mode": "execute",
        "start_url": "https://example.com",
    });

    let result = tool.execute(params, &ctx).await.unwrap();
    assert!(!result.success);
    assert!(result
        .error
        .as_ref()
        .unwrap()
        .contains("script parameter is required"));
}

/// Test that invalid mode is rejected.
#[tokio::test]
async fn invalid_mode_rejected() {
    let tool = WebwrightTool;
    let ctx = ToolContext::default();

    let params = json!({
        "mode": "invalid",
        "start_url": "https://example.com",
    });

    let result = tool.execute(params, &ctx).await.unwrap();
    assert!(!result.success);
    assert!(result.error.as_ref().unwrap().contains("mode must be"));
}

/// Test that missing start_url is rejected.
#[tokio::test]
async fn missing_start_url_rejected() {
    let tool = WebwrightTool;
    let ctx = ToolContext::default();

    let params = json!({
        "mode": "explore",
        "task": "test XSS",
    });

    let result = tool.execute(params, &ctx).await.unwrap();
    assert!(!result.success);
    assert!(result.error.as_ref().unwrap().contains("start_url"));
}

/// Test workspace creation and artifact collection with real filesystem.
#[tokio::test]
#[ignore = "Asserts on sandbox /tmp/webwright path; workspace only populates the rootfs host path - requires mounted sandbox"]
async fn workspace_creates_and_collects_artifacts() {
    let platform = pentest_platform::get_platform();

    let workspace = WebwrightWorkspace::create(&platform, None).await.unwrap();
    let ws_path = workspace.path();

    assert!(
        std::path::Path::new(&ws_path).exists(),
        "Workspace dir should exist: {}",
        ws_path
    );

    // Write config
    workspace
        .write_config(9100, "strike48-default")
        .await
        .unwrap();
    assert!(std::path::Path::new(&workspace.config_path()).exists());

    let config_content = std::fs::read_to_string(workspace.config_path()).unwrap();
    assert!(config_content.contains("provider: openai"));
    assert!(config_content.contains("127.0.0.1:9100"));
    assert!(config_content.contains("strike48-default"));

    // Write script
    workspace
        .write_script("print('hello world')")
        .await
        .unwrap();
    assert!(std::path::Path::new(&workspace.script_path()).exists());

    // Create fake artifacts
    std::fs::write(
        format!("{}/exploit_auth_bypass.py", ws_path),
        "# Auth bypass exploit",
    )
    .unwrap();
    std::fs::write(
        format!("{}/screenshot_dashboard.png", ws_path),
        "fake png data",
    )
    .unwrap();
    std::fs::write(
        format!("{}/network_log.json", ws_path),
        r#"{"requests": []}"#,
    )
    .unwrap();

    // Collect artifacts
    let artifacts = workspace.collect_artifacts(&platform).await.unwrap();

    let scripts = artifacts["scripts"].as_array().unwrap();
    assert_eq!(
        scripts.len(),
        1,
        "Should find 1 script (not counting script.py)"
    );
    assert!(scripts[0]
        .as_str()
        .unwrap()
        .contains("exploit_auth_bypass.py"));

    let screenshots = artifacts["screenshots"].as_array().unwrap();
    assert_eq!(screenshots.len(), 1);

    let logs = artifacts["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 1);

    // Cleanup
    workspace.cleanup(&platform).await.unwrap();
    assert!(
        !std::path::Path::new(&ws_path).exists(),
        "Workspace should be cleaned up"
    );
}

/// Test evidence ingestion produces correctly typed nodes with metadata.
#[test]
fn evidence_ingestion_produces_typed_nodes() {
    use pentest_core::provenance::ProbeCommand;

    let _ = drain_pending_evidence();

    let artifacts = json!({
        "workspace": "/tmp/webwright/test-evidence",
        "task_id": "test-task-001",
        "scripts": [
            "/tmp/webwright/test-evidence/exploit_sqli.py",
            "/tmp/webwright/test-evidence/exploit_xss.py"
        ],
        "screenshots": [
            "/tmp/webwright/test-evidence/screenshot_login.png",
            "/tmp/webwright/test-evidence/screenshot_admin.png"
        ],
        "logs": [
            "/tmp/webwright/test-evidence/network_log.json",
            "/tmp/webwright/test-evidence/console_output.log",
            "/tmp/webwright/test-evidence/agent_reasoning.log"
        ],
        "dom_snapshots": [
            "/tmp/webwright/test-evidence/dom_snapshot_login.html"
        ],
        "other": [],
        "total_files": 8
    });

    let provenance = pentest_core::provenance::Provenance::new(
        "webwright",
        "0.1.0",
        ProbeCommand::from_exact("webwright explore --start-url https://target.com"),
        "scan complete",
    );

    ingest_webwright_evidence(
        &artifacts,
        "https://target.com",
        "test-task-001",
        &provenance,
    );

    let evidence = drain_pending_evidence();

    // 2 scripts + 2 screenshots + 3 logs + 1 snapshot = 8 nodes
    assert_eq!(
        evidence.len(),
        8,
        "Should produce 8 evidence nodes, got {}",
        evidence.len()
    );

    // Check script nodes
    let scripts: Vec<_> = evidence
        .iter()
        .filter(|e| e.node_type == "browser_exploit_script")
        .collect();
    assert_eq!(scripts.len(), 2);
    assert!(scripts[0].metadata.contains_key("file_path"));
    assert_eq!(scripts[0].metadata["task_id"], "test-task-001");
    assert_eq!(scripts[0].affected_target, "https://target.com");

    // Check log nodes are correctly sub-typed
    let network_logs: Vec<_> = evidence
        .iter()
        .filter(|e| e.node_type == "network_log")
        .collect();
    assert_eq!(network_logs.len(), 1);

    let console_logs: Vec<_> = evidence
        .iter()
        .filter(|e| e.node_type == "console_log")
        .collect();
    assert_eq!(console_logs.len(), 1);

    let reasoning_logs: Vec<_> = evidence
        .iter()
        .filter(|e| e.node_type == "agent_reasoning")
        .collect();
    assert_eq!(reasoning_logs.len(), 1);

    // All nodes should have provenance
    for node in &evidence {
        assert!(node.provenance.is_some());
        let prov = node.provenance.as_ref().unwrap();
        assert_eq!(prov.underlying_tool, "webwright");
    }
}

/// Test findings ingestion handles all severity levels.
#[test]
fn findings_ingestion_maps_all_severity_levels() {
    use pentest_core::export::Severity;
    use pentest_core::provenance::ProbeCommand;

    let _ = drain_pending_evidence();

    let findings = json!([
        {"title": "RCE via deserialization", "severity": "critical", "type": "rce", "description": "Remote code execution", "url": "https://target.com/api"},
        {"title": "SQL Injection", "severity": "high", "type": "sqli", "description": "SQL injection in login", "url": "https://target.com/login"},
        {"title": "CSRF on settings", "severity": "medium", "type": "csrf", "description": "Missing CSRF token"},
        {"title": "Cookie without secure flag", "severity": "low", "type": "cookie", "description": "Missing Secure attribute"},
        {"title": "Server version disclosed", "severity": "info", "type": "info_disclosure", "description": "Server header reveals version"}
    ]);

    let provenance = pentest_core::provenance::Provenance::new(
        "webwright",
        "0.1.0",
        ProbeCommand::from_exact("webwright explore"),
        "output",
    );

    ingest_webwright_findings(
        &findings,
        "https://target.com",
        "task-sev-test",
        &provenance,
    );

    let evidence = drain_pending_evidence();
    assert_eq!(evidence.len(), 5);

    let rce = evidence.iter().find(|e| e.title.contains("RCE")).unwrap();
    assert_eq!(rce.current_severity(), Severity::Critical);

    let sqli = evidence.iter().find(|e| e.title.contains("SQL")).unwrap();
    assert_eq!(sqli.current_severity(), Severity::High);
    assert_eq!(sqli.metadata["vuln_type"], "sqli");

    let csrf = evidence.iter().find(|e| e.title.contains("CSRF")).unwrap();
    assert_eq!(csrf.current_severity(), Severity::Medium);

    let cookie = evidence
        .iter()
        .find(|e| e.title.contains("Cookie"))
        .unwrap();
    assert_eq!(cookie.current_severity(), Severity::Low);

    let info = evidence
        .iter()
        .find(|e| e.title.contains("Server"))
        .unwrap();
    assert_eq!(info.current_severity(), Severity::Info);
}

/// End-to-end: Python script simulates full Webwright run, evidence flows through.
#[tokio::test]
#[ignore = "Requires bwrap-capable sandbox to auto-install webwright - unavailable on GitHub Actions runners"]
async fn end_to_end_simulated_webwright_run() {
    let tool = WebwrightTool;
    let ctx = ToolContext::default();
    let _ = drain_pending_evidence();

    let script = r##"
import os, json, sys

workspace = os.path.dirname(os.path.abspath(__file__))

# Step 1: Screenshot of login page
with open(os.path.join(workspace, "screenshot_step1_login.png"), "wb") as f:
    f.write(b"\x89PNG\r\n\x1a\n" + b"fake login page screenshot" * 10)

# Step 2: Generate exploit script
with open(os.path.join(workspace, "exploit_reflected_xss.py"), "w") as f:
    f.write("from playwright.sync_api import sync_playwright\n")
    f.write("def test_xss():\n")
    f.write("    with sync_playwright() as p:\n")
    f.write("        browser = p.chromium.launch(headless=True)\n")
    f.write("        page = browser.new_page()\n")
    f.write("        page.goto('https://example.com/search?q=<script>alert(1)</script>')\n")
    f.write("        browser.close()\n")

# Step 3: Screenshot showing XSS triggered
with open(os.path.join(workspace, "screenshot_step2_xss.png"), "wb") as f:
    f.write(b"\x89PNG\r\n\x1a\n" + b"alert box showing on page" * 10)

# Step 4: DOM snapshot of login form
with open(os.path.join(workspace, "dom_snapshot_login_form.html"), "w") as f:
    f.write("<html><body><form action='/api/auth/login' method='POST'>")
    f.write("<input type='text' name='username'>")
    f.write("<input type='password' name='password'>")
    f.write("<button type='submit'>Login</button></form></body></html>")

# Network log
network_log = {
    "requests": [
        {"method": "GET", "url": "https://example.com/", "status": 200},
        {"method": "GET", "url": "https://example.com/search?q=test", "status": 200},
        {"method": "GET", "url": "https://example.com/login", "status": 200},
    ]
}
with open(os.path.join(workspace, "network_log.json"), "w") as f:
    json.dump(network_log, f, indent=2)

# Console output
with open(os.path.join(workspace, "console_output.log"), "w") as f:
    f.write("[WARN] Mixed content detected\n")
    f.write("[ERROR] Uncaught TypeError\n")

# Agent reasoning log
with open(os.path.join(workspace, "agent_reasoning.log"), "w") as f:
    f.write("Step 1: Navigated to target - found search and login\n")
    f.write("Step 2: Testing search for XSS - injecting payload\n")
    f.write("Step 3: XSS CONFIRMED - script executed\n")
    f.write("Step 4: Checking login for CSRF - no token found\n")

# Findings
findings = [
    {
        "title": "Reflected XSS in search parameter",
        "description": "The /search endpoint reflects user input from the q parameter without HTML encoding.",
        "severity": "high",
        "type": "xss",
        "url": "https://example.com/search?q=<script>alert(1)</script>"
    },
    {
        "title": "Missing CSRF protection on login form",
        "description": "The login form does not include a CSRF token.",
        "severity": "medium",
        "type": "csrf",
        "url": "https://example.com/login"
    }
]
with open(os.path.join(workspace, "findings.json"), "w") as f:
    json.dump(findings, f, indent=2)

# Print summary
summary = {
    "status": "complete",
    "steps_taken": 4,
    "pages_visited": 3,
    "findings_count": 2,
    "scripts_generated": 1,
    "screenshots_taken": 2
}
print(json.dumps(summary))
"##;

    let params = json!({
        "mode": "execute",
        "start_url": "https://example.com",
        "script": script,
        "timeout": 30,
    });

    let result = tool.execute(params, &ctx).await.unwrap();

    // --- Verify tool result ---
    assert!(result.success, "Tool should succeed: {:?}", result.error);
    assert!(result.provenance.is_some());

    let data = &result.data;
    assert_eq!(data["exit_code"], 0);

    let stdout = data["stdout"].as_str().unwrap();
    assert!(stdout.contains("complete"));

    // --- Verify artifacts ---
    let artifacts = &data["artifacts"];
    let scripts = artifacts["scripts"].as_array().unwrap();
    let screenshots = artifacts["screenshots"].as_array().unwrap();
    let logs = artifacts["logs"].as_array().unwrap();
    let snapshots = artifacts["dom_snapshots"].as_array().unwrap();

    assert_eq!(scripts.len(), 1, "Should have 1 exploit script");
    assert_eq!(screenshots.len(), 2, "Should have 2 screenshots");
    assert!(
        logs.len() >= 3,
        "Should have at least 3 logs, got {}",
        logs.len()
    );
    assert_eq!(snapshots.len(), 1, "Should have 1 DOM snapshot");

    // --- Verify evidence pipeline ---
    let evidence = drain_pending_evidence();

    let by_type = |t: &str| -> Vec<_> { evidence.iter().filter(|e| e.node_type == t).collect() };

    let exploit_scripts = by_type("browser_exploit_script");
    let browser_screenshots = by_type("browser_screenshot");
    let browser_findings = by_type("browser_finding");
    let network_logs = by_type("network_log");
    let console_logs = by_type("console_log");
    let reasoning_logs = by_type("agent_reasoning");
    let dom_snaps = by_type("dom_snapshot");

    assert_eq!(exploit_scripts.len(), 1, "1 exploit script evidence");
    assert_eq!(browser_screenshots.len(), 2, "2 screenshot evidence");
    assert_eq!(browser_findings.len(), 2, "2 findings from findings.json");
    assert_eq!(network_logs.len(), 1, "1 network log evidence");
    assert_eq!(console_logs.len(), 1, "1 console log evidence");
    assert_eq!(reasoning_logs.len(), 1, "1 reasoning log evidence");
    assert_eq!(dom_snaps.len(), 1, "1 DOM snapshot evidence");

    // --- Verify finding details ---
    let xss = browser_findings
        .iter()
        .find(|e| e.title.contains("XSS"))
        .expect("Should find XSS evidence");
    assert_eq!(xss.current_severity(), pentest_core::export::Severity::High);
    assert_eq!(xss.affected_target, "https://example.com");
    assert_eq!(xss.metadata["vuln_type"], "xss");

    let csrf = browser_findings
        .iter()
        .find(|e| e.title.contains("CSRF"))
        .expect("Should find CSRF evidence");
    assert_eq!(
        csrf.current_severity(),
        pentest_core::export::Severity::Medium
    );

    // --- Verify provenance on all nodes ---
    for node in &evidence {
        let prov = node.provenance.as_ref().expect("All nodes need provenance");
        assert_eq!(prov.underlying_tool, "webwright");
        assert_eq!(prov.tool_version, "0.1.0");
    }

    println!("\n=== End-to-End Test Summary ===");
    println!("Total evidence nodes produced: {}", evidence.len());
    println!("  Exploit scripts: {}", exploit_scripts.len());
    println!("  Screenshots: {}", browser_screenshots.len());
    println!("  Findings: {}", browser_findings.len());
    println!("  Network logs: {}", network_logs.len());
    println!("  Console logs: {}", console_logs.len());
    println!("  Agent reasoning: {}", reasoning_logs.len());
    println!("  DOM snapshots: {}", dom_snaps.len());
    println!("===============================\n");
}

/// Test that parallel webwright tasks maintain independent progress state.
#[tokio::test]
async fn parallel_tasks_have_independent_progress() {
    use pentest_tools::webwright::live_state;

    // Start two tasks
    live_state::start("task-a");
    live_state::start("task-b");

    // Update them independently
    live_state::update(
        "task-a",
        live_state::WebwrightProgress {
            step: 5,
            action: "task A step 5".to_string(),
            running: true,
            task_id: "task-a".to_string(),
            ..Default::default()
        },
    );

    live_state::update(
        "task-b",
        live_state::WebwrightProgress {
            step: 3,
            action: "task B step 3".to_string(),
            running: true,
            task_id: "task-b".to_string(),
            ..Default::default()
        },
    );

    // Verify they're independent
    let a = live_state::peek("task-a");
    let b = live_state::peek("task-b");

    assert_eq!(a.step, 5);
    assert_eq!(a.action, "task A step 5");
    assert_eq!(a.task_id, "task-a");

    assert_eq!(b.step, 3);
    assert_eq!(b.action, "task B step 3");
    assert_eq!(b.task_id, "task-b");

    // Both should be running
    assert!(a.running);
    assert!(b.running);
    assert_eq!(live_state::running_tasks().len(), 2);

    // Complete one — the other stays running
    live_state::complete("task-a");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let a_done = live_state::peek("task-a");
    let b_still = live_state::peek("task-b");

    assert!(!a_done.running);
    assert!(b_still.running);
    assert_eq!(b_still.step, 3);

    // Clean up
    live_state::complete("task-b");
}
