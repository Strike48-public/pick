//! Registration guards: tools that must (or must not) be in the runtime registry.
//!
//! `all_tools_registered` (crates/core) checks registry -> capabilities, and the
//! `tools_doc_sync` guard checks registry -> docs. Neither catches a tool whose
//! `impl PentestTool` exists but whose `registry.register(...)` line was dropped,
//! for example silently lost in a merge resolution. These tests pin the two
//! known cases so the regression cannot recur unnoticed.

use pentest_tools::create_tool_registry;

/// `autopwn_detect` and `autopwn_network_plan` were registered when introduced,
/// then silently lost their `register()` lines in the 3-way merge f280c01
/// (pick#406). A shipped dashboard quick-action prompt directs the agent at
/// `autopwn_network_plan`, so leaving them unregistered is a live unknown-tool
/// bug, not just dead code. Guard against the regression recurring.
#[test]
fn autopwn_orchestration_tools_are_registered() {
    let registry = create_tool_registry();
    let names = registry.names();
    for tool in ["autopwn_detect", "autopwn_network_plan"] {
        assert!(
            names.contains(&tool),
            "tool '{tool}' is implemented but not registered in create_tool_registry() \
             (pick#406) - its register() line was likely dropped in a merge again. \
             Registered: {names:?}"
        );
    }
}

/// `credential_harvest` and `lateral_movement` are implemented but deliberately
/// NOT registered, pending a security decision (pick#405): credential_harvest
/// harvests the operator's own host credentials as written, and lateral_movement
/// is an auto-Pass-the-Hash orchestrator. This is a tripwire, not an oversight -
/// if you register either, resolve pick#405 first (rework/scope it) and remove
/// the corresponding entry here.
#[test]
fn security_gated_tools_remain_unregistered() {
    let registry = create_tool_registry();
    let names = registry.names();
    for tool in ["credential_harvest", "lateral_movement"] {
        assert!(
            !names.contains(&tool),
            "tool '{tool}' is registered, but it is intentionally gated pending a security \
             decision (pick#405). Resolve that issue before wiring it up, then update this test."
        );
    }
}
