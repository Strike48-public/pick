//! Read file tool — reads a file from the workspace

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::workspace;
use serde_json::{json, Value};

/// Tool that reads a file from the workspace
pub struct ReadFileTool;

#[async_trait]
impl PentestTool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "Read a file from the workspace directory"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "path",
                ParamType::String,
                "File path relative to the workspace directory",
            ))
            .param(ToolParam::optional(
                "encoding",
                ParamType::String,
                "Output encoding: \"utf8\" (default) or \"base64\"",
                json!("utf8"),
            ))
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let workspace_path = ctx.workspace_path.clone();

        execute_timed(|| async move {
            let workspace = workspace_path.as_ref().ok_or_else(|| {
                pentest_core::error::Error::ToolExecution(
                    "No workspace configured for this session".into(),
                )
            })?;

            let path = params.get("path").and_then(|v| v.as_str()).ok_or_else(|| {
                pentest_core::error::Error::InvalidParams("path parameter is required".into())
            })?;

            let encoding = params
                .get("encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8");

            let resolved = workspace::resolve_path(workspace, path)?;

            if !resolved.is_file() {
                return Err(pentest_core::error::Error::ToolExecution(format!(
                    "Not a file: {}",
                    path
                )));
            }

            match encoding {
                "base64" => {
                    let bytes = tokio::fs::read(&resolved).await?;
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    Ok(json!({
                        "path": path,
                        "encoding": "base64",
                        "content": encoded,
                        "size_bytes": bytes.len(),
                    }))
                }
                _ => {
                    let content = tokio::fs::read_to_string(&resolved).await?;
                    let size = content.len();
                    Ok(json!({
                        "path": path,
                        "encoding": "utf8",
                        "content": content,
                        "size_bytes": size,
                    }))
                }
            }
        })
        .await
    }
}
