//! Screenshot capture tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{execute_timed, PentestTool, Platform, ToolContext, ToolResult};
use pentest_platform::{get_platform, CaptureOps};
use serde_json::{json, Value};

/// Screenshot tool
pub struct ScreenshotTool;

#[async_trait]
impl PentestTool for ScreenshotTool {
    fn name(&self) -> &str {
        "screenshot"
    }

    fn description(&self) -> &str {
        "Capture a screenshot of the screen and return it as base64-encoded PNG"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let platform = get_platform();
            let data = platform.capture_screenshot().await?;
            let base64_data =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
            Ok(json!({
                "format": "png",
                "size_bytes": data.len(),
                "data": base64_data,
            }))
        })
        .await
    }
}
