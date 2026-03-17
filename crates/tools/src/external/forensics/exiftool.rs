//! ExifTool - Metadata extraction tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::install::ensure_tool_installed;
use crate::external::runner::{param_str_or, CommandBuilder};

pub struct ExiftoolTool;

#[async_trait]
impl PentestTool for ExiftoolTool {
    fn name(&self) -> &str {
        "exiftool"
    }

    fn description(&self) -> &str {
        "Read and write meta information in files (supports 100+ file formats)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "exiftool",
                "perl-image-exiftool",
                "Metadata extraction tool (Perl-based)",
            ))
            .param(ToolParam::required(
                "file_path",
                ParamType::String,
                "Path to file or directory",
            ))
            .param(ToolParam::optional(
                "recursive",
                ParamType::Boolean,
                "Process directories recursively (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 60)",
                json!(60),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "exiftool", "perl-image-exiftool").await?;

            let file_path = param_str_or(&params, "file_path", "");
            if file_path.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "file_path parameter is required".into(),
                ));
            }

            let recursive = crate::util::param_bool(&params, "recursive", false);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            let mut builder = CommandBuilder::new().flag("-json").positional(&file_path);

            if recursive {
                builder = builder.flag("-r");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("exiftool", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // Try to parse JSON output
            if let Ok(metadata) = serde_json::from_str::<Value>(&result.stdout) {
                return Ok(metadata);
            }

            Ok(json!({
                "file_path": file_path,
                "metadata": {},
                "raw_output": result.stdout,
            }))
        })
        .await
    }
}
