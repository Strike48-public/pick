//! Arbitrary HTTP request tool.
//!
//! A pure-`reqwest` tool — no fork/exec, no external binary, no sandbox — so it
//! runs natively on EVERY platform including iOS, where the agent otherwise has
//! no way to probe a discovered web service (it can't shell out to curl/nmap).
//! Give it a method + URL (+ optional headers/body) and it returns the status,
//! response headers, and a bounded body excerpt.
//!
//! SSRF-guarded: the URL is validated via the connector's
//! `target_validation_mode()` (same gate the other network tools use), so it
//! can't be turned into a request against the platform's own internals in
//! production while still reaching LAN targets in the in-cluster/dev modes.

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::provenance::{truncate_excerpt, ProbeCommand, Provenance};
use pentest_core::tools::{
    execute_timed_with_provenance, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_core::url_validation::{target_validation_mode, validate_url};
use serde_json::{json, Value};
use std::time::Duration;

use crate::util::{param_str, param_u64};

/// Max response body bytes we read + return, so a huge download can't blow up
/// memory or the chat transcript. The excerpt is truncated for display.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Arbitrary HTTP request tool.
pub struct HttpRequestTool;

/// Allowed HTTP methods. Restricting to a known set keeps the tool from being
/// coerced into exotic verbs and gives a clear error on typos.
const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

#[async_trait]
impl PentestTool for HttpRequestTool {
    fn name(&self) -> &str {
        "http_request"
    }

    fn description(&self) -> &str {
        "Send an HTTP request to a URL and return the status, response headers, and body. \
         Use this to probe or interact with web services (fetch a page, hit an API, check a \
         header). Native networking — available on all platforms including mobile."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL, e.g. 'http://10.10.0.14/' or 'https://host:8443/api/status'",
            ))
            .param(ToolParam::optional(
                "method",
                ParamType::String,
                "HTTP method (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS). Default GET.",
                json!("GET"),
            ))
            .param(ToolParam::optional(
                "headers",
                ParamType::Object,
                "Request headers as a JSON object of name -> value, e.g. {\"Accept\": \"application/json\"}",
                json!({}),
            ))
            .param(ToolParam::optional(
                "body",
                ParamType::String,
                "Request body (for POST/PUT/PATCH). Sent as-is; set a Content-Type header if needed.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Request timeout in milliseconds (default 15000).",
                json!(15000),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        // Pure networking — no sandbox/exec needed, so every platform including iOS.
        vec![
            Platform::Desktop,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async {
            let url = param_str(&params, "url");
            if url.is_empty() {
                return Err(Error::InvalidParams("url parameter is required".into()));
            }

            // SSRF guard — same gate the other network tools use.
            let url = validate_url(&url, target_validation_mode(), None)?;

            let method = param_str(&params, "method");
            let method = if method.is_empty() {
                "GET".to_string()
            } else {
                method.to_uppercase()
            };
            if !ALLOWED_METHODS.contains(&method.as_str()) {
                return Err(Error::InvalidParams(format!(
                    "unsupported method '{method}' (allowed: {})",
                    ALLOWED_METHODS.join(", ")
                )));
            }
            let http_method = reqwest::Method::from_bytes(method.as_bytes())
                .map_err(|e| Error::InvalidParams(format!("invalid method: {e}")))?;

            let timeout_ms = param_u64(&params, "timeout_ms", 15_000);

            let client = reqwest::Client::builder()
                .timeout(Duration::from_millis(timeout_ms))
                // Accept self-signed certs on target services — this is a
                // pentest probe, not a trust decision (matches the connector's
                // other outbound scanners against *.test / lab hosts).
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| Error::ToolExecution(format!("HTTP client build failed: {e}")))?;

            let mut req = client.request(http_method, &url);

            // Optional headers object.
            if let Some(obj) = params.get("headers").and_then(|h| h.as_object()) {
                for (k, v) in obj {
                    if let Some(val) = v.as_str() {
                        req = req.header(k.as_str(), val);
                    }
                }
            }

            // Optional body.
            let body = param_str(&params, "body");
            if !body.is_empty() {
                req = req.body(body.clone());
            }

            tracing::info!("http_request: {method} {url}");

            let resp = req
                .send()
                .await
                .map_err(|e| Error::ToolExecution(format!("request failed: {e}")))?;

            let status = resp.status();
            let status_code = status.as_u16();
            let final_url = resp.url().to_string();

            // Collect response headers as a JSON object.
            let mut headers = serde_json::Map::new();
            for (name, value) in resp.headers() {
                headers.insert(
                    name.to_string(),
                    json!(value.to_str().unwrap_or("<non-utf8>")),
                );
            }

            // Read a bounded body.
            let full = resp
                .bytes()
                .await
                .map_err(|e| Error::ToolExecution(format!("reading body failed: {e}")))?;
            let truncated = full.len() > MAX_BODY_BYTES;
            let slice = &full[..full.len().min(MAX_BODY_BYTES)];
            let body_text = String::from_utf8_lossy(slice).into_owned();

            // Provenance: the curl a reviewer can run to reproduce this exact call.
            let curl = ProbeCommand::from_exact(format!("curl -sS -k -X {method} {final_url}"))
                .with_description("HTTP request");
            let provenance = Provenance::multi_step(
                "http_request",
                env!("CARGO_PKG_VERSION"),
                vec![curl],
                truncate_excerpt(&body_text),
            );

            let data = json!({
                "url": final_url,
                "method": method,
                "status": status_code,
                "ok": status.is_success(),
                "headers": headers,
                "body": truncate_excerpt(&body_text),
                "body_bytes": full.len(),
                "body_truncated": truncated,
            });

            // Promote the response as a grounding anchor (pick#52). http_request
            // is a primitive, so this is a single Info node the Validator can
            // drop; its value is carrying the reproducible curl in provenance.
            for node in
                crate::evidence_producer::evidence_from_http_request(&data, provenance.clone())
            {
                let _ = crate::evidence_producer::push_evidence(node);
            }

            Ok((data, provenance))
        })
        .await
    }
}
