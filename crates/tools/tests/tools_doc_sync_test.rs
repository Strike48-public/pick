//! Guard against drift between `docs/TOOLS.md` and the live tool registry.
//!
//! Regression guard for pick#362: the static catalog silently desynced from
//! `create_tool_registry()` in three ways at once - registered tools with no
//! catalog row, catalog rows whose name did not match the registered `name()`,
//! and catalog rows for tools that were never registered. A hand-maintained
//! count could not catch any of that (and its own arithmetic had drifted too).
//!
//! These tests derive the source of truth from the registry - not from a
//! hand-kept total - and fail on drift in either direction. The tool name a
//! catalog row must use is the exact string returned by that tool's `name()`,
//! which is what an operator or the model invokes; a row whose first backticked
//! token is not a real `name()` is a landmine, not documentation.

use std::collections::BTreeSet;
use std::path::PathBuf;

use pentest_tools::create_tool_registry;

/// Tools whose registration is conditional on a build feature or a runtime
/// capability. They may be absent from the registry when this test runs, yet
/// are still legitimately listed in the catalog, so they are exempt from the
/// "documented but not registered" direction only:
///
/// - `traffic_capture` is registered only when packet capture (libpcap on
///   Linux, Npcap on Windows) is available at runtime
///   (`pentest_platform::is_pcap_available()`).
/// - `inject_test_evidence` is gated behind the opt-in `inject-test-evidence`
///   feature and is never registered in release builds (pick#184).
const CONDITIONAL_TOOLS: &[&str] = &["traffic_capture", "inject_test_evidence"];

/// The first backticked token of every Markdown table row in `docs/TOOLS.md`.
/// Tool rows look like ``| `nmap` | External | ... |``; header, separator, and
/// category-summary rows do not start with `` | ` `` and are ignored.
fn documented_tool_names() -> BTreeSet<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/TOOLS.md");
    let doc = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

    doc.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("| `")?;
            let end = rest.find('`')?;
            Some(rest[..end].to_string())
        })
        .collect()
}

fn registered_tool_names() -> BTreeSet<String> {
    let registry = create_tool_registry();
    registry.names().into_iter().map(String::from).collect()
}

#[test]
fn every_registered_tool_is_documented() {
    let documented = documented_tool_names();
    let registered = registered_tool_names();

    let undocumented: Vec<&String> = registered
        .iter()
        .filter(|name| !documented.contains(*name))
        .collect();

    assert!(
        undocumented.is_empty(),
        "docs/TOOLS.md is missing {} registered tool(s): {undocumented:?}\n\
         Add a catalog row for each, using the exact registered name (pick#362).",
        undocumented.len(),
    );
}

#[test]
fn every_documented_tool_is_real() {
    let documented = documented_tool_names();
    let registered = registered_tool_names();

    let phantom: Vec<&String> = documented
        .iter()
        .filter(|name| !registered.contains(*name) && !CONDITIONAL_TOOLS.contains(&name.as_str()))
        .collect();

    assert!(
        phantom.is_empty(),
        "docs/TOOLS.md lists {} tool(s) not in the registry: {phantom:?}\n\
         Remove the row, fix the name to match the tool's `name()`, or add it to \
         CONDITIONAL_TOOLS if it is feature/runtime gated (pick#362).",
        phantom.len(),
    );
}
