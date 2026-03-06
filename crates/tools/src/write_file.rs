//! Write file tool — writes a file to the workspace

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::workspace;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::util::{param_bool, param_str};

/// Tool that writes a file to the workspace
pub struct WriteFileTool;

#[async_trait]
impl PentestTool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "Write a file to the workspace directory"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "path",
                ParamType::String,
                "File path relative to the workspace directory",
            ))
            .param(ToolParam::required(
                "content",
                ParamType::String,
                "Content to write to the file",
            ))
            .param(ToolParam::optional(
                "encoding",
                ParamType::String,
                "Input encoding: \"utf8\" (default) or \"base64\"",
                json!("utf8"),
            ))
            .param(ToolParam::optional(
                "append",
                ParamType::Boolean,
                "Append to existing file instead of overwriting",
                json!(false),
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

            let content = params
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams(
                        "content parameter is required".into(),
                    )
                })?;

            let encoding_raw = param_str(&params, "encoding");
            let encoding = if encoding_raw.is_empty() {
                "utf8"
            } else {
                &encoding_raw
            };

            let append = param_bool(&params, "append", false);

            let resolved = workspace::resolve_path(workspace, path)?;

            // Create parent directories
            if let Some(parent) = resolved.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    pentest_core::error::Error::ToolExecution(format!(
                        "Failed to create parent directories: {}",
                        e
                    ))
                })?;
            }

            let bytes = match encoding {
                "base64" => {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(content)
                        .map_err(|e| {
                            pentest_core::error::Error::InvalidParams(format!(
                                "Invalid base64: {}",
                                e
                            ))
                        })?
                }
                _ => content.as_bytes().to_vec(),
            };

            if append {
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&resolved)
                    .await?;
                file.write_all(&bytes).await?;
            } else {
                tokio::fs::write(&resolved, &bytes).await?;
            }

            Ok(json!({
                "path": path,
                "size_bytes": bytes.len(),
                "appended": append,
            }))
        })
        .await
    }
}
