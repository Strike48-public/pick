//! Burp Suite - interactive web proxy (MANUAL use only)
//!
//! Burp Suite Community has NO REST API and Burp Pro's API is license-gated, so
//! Pick deliberately does NOT automate Burp. This tool is informational: when
//! invoked it never tries to drive Burp. Instead it detects whether Burp is
//! installed and returns structured guidance on using Burp manually for the
//! given target, pointing the agent at the `zap` tool for automated DAST.
//!
//! Keeping this tool "manual / informational" stops the agent from
//! hallucinating Burp automation that the product cannot actually perform.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, Platform, ToolCategory, ToolContext,
    ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::runner::param_str_opt;

/// Candidate binary names for a Burp Suite install across packagings.
const BURP_BINARIES: &[&str] = &["burpsuite", "BurpSuiteCommunity"];

pub struct BurpSuiteTool;

#[async_trait]
impl PentestTool for BurpSuiteTool {
    fn name(&self) -> &str {
        "burpsuite"
    }

    fn description(&self) -> &str {
        "Burp Suite interactive web proxy (MANUAL use only). Burp Community has no REST API and \
         Burp Pro's API is license-gated, so Pick cannot drive Burp programmatically. Invoking \
         this tool returns guidance on using Burp by hand for a target; for automated DAST use \
         the 'zap' tool instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new(
                    "burpsuite",
                    "burpsuite",
                    "Burp Suite - interactive web proxy (manual use; Community has no REST API)",
                )
                .manual(
                    "Burp Suite Community has no automation API. Install from \
                     https://portswigger.net/burp/communitydownload and run it interactively. \
                     For automated scanning use the 'zap' tool. Burp Pro REST API requires a \
                     paid license.",
                    Some("https://portswigger.net/burp/communitydownload".to_string()),
                )
                .category(ToolCategory::Web)
                .recommended(false),
            )
            .param(ToolParam::optional(
                "target",
                ParamType::String,
                "Target URL the operator wants to test manually (echoed back into the guidance)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds for the install probe (default: 5). This tool runs no scan.",
                json!(5),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Only the presence/absence of Burp matters; this tool never drives it.
            let installed = detect_burp(&platform).await;

            // An empty target string means "no target supplied".
            let target = param_str_opt(&params, "target").filter(|t| !t.trim().is_empty());

            Ok(build_guidance(target.as_deref(), installed))
        })
        .await
    }
}

/// Detect whether a Burp Suite binary is on PATH (`burpsuite` or
/// `BurpSuiteCommunity`). Returns `false` rather than erroring when absent —
/// a missing Burp is a normal, reportable state, not a tool failure.
async fn detect_burp<P: CommandExec>(platform: &P) -> bool {
    for name in BURP_BINARIES {
        let found = platform
            .execute_command("which", &[name], Duration::from_secs(5))
            .await
            .map(|r| r.exit_code == 0)
            .unwrap_or(false);
        if found {
            return true;
        }
    }
    false
}

/// Build the structured, informational result for a Burp invocation.
///
/// Pure and binary-free so it can be unit-tested directly: it echoes the
/// target (or `null` when absent), reflects the `installed` state, and always
/// steers the agent toward the `zap` tool for automated DAST.
fn build_guidance(target: Option<&str>, installed: bool) -> Value {
    let target_value = match target {
        Some(t) => Value::String(t.to_string()),
        None => Value::Null,
    };

    let target_line = match target {
        Some(t) => format!("Target to test manually: {t}"),
        None => "No target supplied; open Burp against whatever scope you are authorized to test."
            .to_string(),
    };

    let install_line = if installed {
        "Burp Suite is installed on this host. Launch it interactively to begin."
    } else {
        "Burp Suite is not installed. Download Burp Suite Community from \
         https://portswigger.net/burp/communitydownload and run it interactively."
    };

    let guidance = format!(
        "{install_line}\n\
         {target_line}\n\
         \n\
         Burp Suite is a MANUAL, interactive web proxy. Pick cannot automate it: Burp \
         Community has no REST API, and Burp Pro's API is license-gated.\n\
         \n\
         To use Burp by hand:\n\
         1. Start Burp Suite and note its proxy listener (default 127.0.0.1:8080).\n\
         2. Configure your browser (or the target client) to route through that proxy.\n\
         3. Install Burp's CA certificate in the browser to intercept HTTPS.\n\
         4. Browse the target to populate the site map, then use Proxy/Repeater/Intruder \
         to inspect and manipulate requests.\n\
         \n\
         For automated dynamic application security testing (DAST), use the 'zap' tool \
         instead - it runs headless and is fully agent-drivable."
    );

    json!({
        "installed": installed,
        "target": target_value,
        "guidance": guidance,
        "recommended_alternative": "zap",
        "reason": "Burp Community has no REST API; Pick cannot automate it.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_reflects_installed_true() {
        let v = build_guidance(Some("https://app.example.com"), true);
        assert_eq!(v["installed"], true);
        assert!(v["guidance"].as_str().unwrap().contains("is installed"));
    }

    #[test]
    fn guidance_reflects_installed_false() {
        let v = build_guidance(Some("https://app.example.com"), false);
        assert_eq!(v["installed"], false);
        assert!(v["guidance"].as_str().unwrap().contains("is not installed"));
    }

    #[test]
    fn guidance_echoes_target_when_present() {
        let v = build_guidance(Some("https://app.example.com"), false);
        assert_eq!(v["target"], "https://app.example.com");
        assert!(v["guidance"]
            .as_str()
            .unwrap()
            .contains("https://app.example.com"));
    }

    #[test]
    fn guidance_target_is_null_when_absent() {
        let v = build_guidance(None, true);
        assert_eq!(v["target"], Value::Null);
    }

    #[test]
    fn guidance_recommends_zap() {
        let v = build_guidance(None, true);
        assert_eq!(v["recommended_alternative"], "zap");
        assert_eq!(
            v["reason"],
            "Burp Community has no REST API; Pick cannot automate it."
        );
    }
}
