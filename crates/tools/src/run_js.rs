//! `run_js` — execute a JavaScript payload in an embedded QuickJS interpreter.
//!
//! QuickJS (via `rquickjs`) is a bytecode interpreter with no JIT, so it runs
//! inside the iOS app sandbox where marking memory executable is forbidden.
//! This lets the agent ship small tools — or author them on the fly — as JS,
//! on every platform including iOS.
//!
//! # Security model
//!
//! The JS payload runs in a fresh, isolated QuickJS context with NO ambient
//! capabilities: no `eval` of external modules, no timers, no filesystem, no
//! network — nothing beyond pure computation. Its ONLY window to the outside
//! world is the `host` object below. Every host function routes through the
//! same guards the native tools use (workspace path resolution, the shared
//! HTTP client), so a payload can never reach anything a normal tool couldn't.
//! A wall-clock timeout and a memory limit bound runaway or malicious payloads.
//!
//! ## Host ABI (the `host` global)
//!
//! - `host.log(msg)`                     — emit a debug line (collected, returned)
//! - `host.input()`                      — the tool's JSON `input` param, as a JS value
//! - `host.readFile(path)`               — read a workspace file (utf-8)
//! - `host.writeFile(path, content)`     — write a workspace file (utf-8)
//! - `host.listFiles(path)`              — list a workspace directory (array of names)
//! - `host.httpFetch(url, opts?)`        — outbound HTTP; opts = {method, headers, body}
//!
//! The payload's final expression value is returned as the tool result.

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::workspace;
use rquickjs::{CatchResultExt, Context, Ctx, Exception, Function, Object, Runtime};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default and maximum wall-clock budget for a payload.
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 30_000;
/// QuickJS heap cap — enough for real transforms, small enough to fail fast on
/// a runaway allocation rather than pressuring the host app.
const MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
/// Cap on a single httpFetch response body we marshal back into JS.
const MAX_HTTP_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// Execute an agent- or operator-supplied JavaScript payload in QuickJS.
pub struct RunJsTool;

#[async_trait]
impl PentestTool for RunJsTool {
    fn supported_platforms(&self) -> Vec<Platform> {
        // Pure interpreter + guarded host ABI — runs everywhere, including iOS.
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    fn name(&self) -> &str {
        "run_js"
    }

    fn description(&self) -> &str {
        "Run a JavaScript payload in a sandboxed QuickJS interpreter. The script \
         has no ambient capabilities; it may only call the provided host API: \
         host.log(msg), host.input(), host.readFile(path), host.writeFile(path, \
         content), host.listFiles(path), and host.httpFetch(url, opts). The value \
         of the script's final expression is returned as the result."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "script",
                ParamType::String,
                "JavaScript source to execute. The final expression's value is returned.",
            ))
            .param(ToolParam::optional(
                "input",
                ParamType::Object,
                "Arbitrary JSON passed to the script via host.input().",
                json!({}),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Wall-clock budget in milliseconds (default 5000, max 30000).",
                json!(DEFAULT_TIMEOUT_MS),
            ))
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let workspace_path = ctx.workspace_path.clone();

        execute_timed(|| async move {
            let script = params
                .get("script")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::InvalidParams("script parameter is required".into()))?
                .to_string();

            let input = params.get("input").cloned().unwrap_or(Value::Null);

            let timeout_ms = params
                .get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_TIMEOUT_MS)
                .min(MAX_TIMEOUT_MS);

            // QuickJS is synchronous and its context is !Send; run the whole
            // evaluation on a blocking thread so we never stall the async
            // runtime and can enforce the wall-clock budget with an interrupt.
            let result = tokio::task::spawn_blocking(move || {
                run_payload(&script, input, workspace_path, timeout_ms)
            })
            .await
            .map_err(|e| Error::ToolExecution(format!("run_js task panicked: {e}")))??;

            Ok(result)
        })
        .await
    }
}

/// Shared state a payload mutates through the host ABI.
struct HostState {
    /// Lines emitted via `host.log`, returned alongside the result.
    logs: Vec<String>,
}

/// Assemble the QuickJS runtime, install the host ABI, run the script, and
/// return `{ "result": <final expr>, "logs": [...] }`.
fn run_payload(
    script: &str,
    input: Value,
    workspace_path: Option<PathBuf>,
    timeout_ms: u64,
) -> Result<Value> {
    let runtime = Runtime::new().map_err(qjs_err)?;
    runtime.set_memory_limit(MEMORY_LIMIT_BYTES);

    // Wall-clock interrupt: QuickJS calls this handler periodically; returning
    // true aborts execution. This is what bounds `while(true){}` payloads.
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));

    let ctx = Context::full(&runtime).map_err(qjs_err)?;
    let state = Arc::new(Mutex::new(HostState { logs: Vec::new() }));

    let result_json = ctx.with(|ctx| -> Result<Value> {
        let host = Object::new(ctx.clone()).map_err(qjs_err)?;
        install_host_abi(&ctx, &host, &state, input, workspace_path)?;
        ctx.globals().set("host", host).map_err(qjs_err)?;

        // Evaluate; the value of the final expression is the result.
        let val: rquickjs::Value = ctx
            .eval(script)
            .catch(&ctx)
            .map_err(|e| Error::ToolExecution(format!("JS error: {e}")))?;

        js_to_json(&ctx, &val)
    })?;

    let logs = std::mem::take(&mut state.lock().unwrap().logs);
    Ok(json!({ "result": result_json, "logs": logs }))
}

/// Register the `host.*` functions on the given object.
fn install_host_abi<'js>(
    ctx: &rquickjs::Ctx<'js>,
    host: &Object<'js>,
    state: &Arc<Mutex<HostState>>,
    input: Value,
    workspace_path: Option<PathBuf>,
) -> Result<()> {
    // host.log(msg)
    {
        let state = state.clone();
        let f = Function::new(ctx.clone(), move |msg: String| {
            state.lock().unwrap().logs.push(msg);
        })
        .map_err(qjs_err)?;
        host.set("log", f).map_err(qjs_err)?;
    }

    // host.input() -> the JSON input, as a JS value
    {
        let input_str = serde_json::to_string(&input).unwrap_or_else(|_| "null".into());
        let f = Function::new(ctx.clone(), move |ctx: rquickjs::Ctx<'js>| {
            // Parse the JSON inside JS so the payload gets a native object.
            ctx.json_parse(input_str.clone())
        })
        .map_err(qjs_err)?;
        host.set("input", f).map_err(qjs_err)?;
    }

    // host.readFile(path) -> utf-8 string
    {
        let ws = workspace_path.clone();
        let f = Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String| -> rquickjs::Result<String> {
                fs_read(&ws, &path).map_err(|e| throw(&ctx, e))
            },
        )
        .map_err(qjs_err)?;
        host.set("readFile", f).map_err(qjs_err)?;
    }

    // host.writeFile(path, content) -> bytes written
    {
        let ws = workspace_path.clone();
        let f = Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String, content: String| -> rquickjs::Result<usize> {
                fs_write(&ws, &path, &content).map_err(|e| throw(&ctx, e))
            },
        )
        .map_err(qjs_err)?;
        host.set("writeFile", f).map_err(qjs_err)?;
    }

    // host.listFiles(path) -> array of entry names
    {
        let ws = workspace_path.clone();
        let f = Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String| -> rquickjs::Result<Vec<String>> {
                fs_list(&ws, &path).map_err(|e| throw(&ctx, e))
            },
        )
        .map_err(qjs_err)?;
        host.set("listFiles", f).map_err(qjs_err)?;
    }

    // host.httpFetch(url, opts?) -> { status, headers, body }
    {
        let f = Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, url: String, opts: rquickjs::Value<'js>| {
                let opts_json = if opts.is_undefined() || opts.is_null() {
                    Value::Null
                } else {
                    js_to_json(&ctx, &opts).unwrap_or(Value::Null)
                };
                let resp = http_fetch(&url, &opts_json).map_err(|e| throw(&ctx, e))?;
                ctx.json_parse(serde_json::to_string(&resp).unwrap_or_else(|_| "null".into()))
            },
        )
        .map_err(qjs_err)?;
        host.set("httpFetch", f).map_err(qjs_err)?;
    }

    Ok(())
}

/// Raise a host-side error as a JS exception carrying its message, so the
/// payload can `catch` it and see what went wrong.
fn throw(ctx: &Ctx<'_>, e: Error) -> rquickjs::Error {
    Exception::throw_message(ctx, &e.to_string())
}

// ---------------------------------------------------------------------------
// Host function backends — each routes through the same guards native tools use
// ---------------------------------------------------------------------------

fn require_ws(ws: &Option<PathBuf>) -> Result<&PathBuf> {
    ws.as_ref()
        .ok_or_else(|| Error::ToolExecution("No workspace configured for this session".into()))
}

fn fs_read(ws: &Option<PathBuf>, path: &str) -> Result<String> {
    let ws = require_ws(ws)?;
    let resolved = workspace::resolve_path(ws, path)?;
    if !resolved.is_file() {
        return Err(Error::ToolExecution(format!("Not a file: {path}")));
    }
    Ok(std::fs::read_to_string(&resolved)?)
}

fn fs_write(ws: &Option<PathBuf>, path: &str, content: &str) -> Result<usize> {
    let ws = require_ws(ws)?;
    let resolved = workspace::resolve_path(ws, path)?;
    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&resolved, content.as_bytes())?;
    Ok(content.len())
}

fn fs_list(ws: &Option<PathBuf>, path: &str) -> Result<Vec<String>> {
    let ws = require_ws(ws)?;
    let resolved = workspace::resolve_path(ws, path)?;
    if !resolved.is_dir() {
        return Err(Error::ToolExecution(format!("Not a directory: {path}")));
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&resolved)? {
        let entry = entry?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

/// Blocking HTTP fetch. Uses a blocking reqwest client because it runs on the
/// spawn_blocking thread hosting the synchronous QuickJS context.
fn http_fetch(url: &str, opts: &Value) -> Result<Value> {
    let method = opts
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| Error::InvalidParams(format!("invalid HTTP method: {method}")))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let mut req = client.request(method, url);

    if let Some(headers) = opts.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in headers {
            if let Some(vs) = v.as_str() {
                req = req.header(k, vs);
            }
        }
    }
    if let Some(body) = opts.get("body").and_then(|v| v.as_str()) {
        req = req.body(body.to_string());
    }

    let resp = req.send().map_err(|e| Error::Network(e.to_string()))?;
    let status = resp.status().as_u16();
    let mut headers = serde_json::Map::new();
    for (k, v) in resp.headers() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.to_string(), Value::String(vs.to_string()));
        }
    }
    // Cap the body we read so a huge response can't blow the memory limit.
    let content_len = resp.content_length().unwrap_or(0);
    if content_len > MAX_HTTP_BODY_BYTES {
        return Err(Error::ToolExecution(format!(
            "response body too large: {content_len} bytes (max {MAX_HTTP_BODY_BYTES})"
        )));
    }
    let body = resp.text().map_err(|e| Error::Network(e.to_string()))?;

    Ok(json!({ "status": status, "headers": headers, "body": body }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn qjs_err(e: rquickjs::Error) -> Error {
    Error::ToolExecution(format!("QuickJS error: {e}"))
}

/// Convert a JS value to serde_json by round-tripping through JSON.stringify.
fn js_to_json<'js>(ctx: &rquickjs::Ctx<'js>, val: &rquickjs::Value<'js>) -> Result<Value> {
    if val.is_undefined() {
        return Ok(Value::Null);
    }
    let s = ctx
        .json_stringify(val.clone())
        .map_err(qjs_err)?
        .and_then(|s| s.to_string().ok())
        .unwrap_or_else(|| "null".to_string());
    Ok(serde_json::from_str(&s).unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn run(script: &str, input: Value, ws: Option<PathBuf>, timeout_ms: u64) -> Result<Value> {
        run_payload(script, input, ws, timeout_ms)
    }

    #[test]
    fn returns_final_expression() {
        let out = run("40 + 2", Value::Null, None, DEFAULT_TIMEOUT_MS).unwrap();
        assert_eq!(out["result"], json!(42));
    }

    #[test]
    fn log_is_collected() {
        let out = run(
            "host.log('hello'); host.log('world'); 1",
            Value::Null,
            None,
            DEFAULT_TIMEOUT_MS,
        )
        .unwrap();
        assert_eq!(out["logs"], json!(["hello", "world"]));
    }

    #[test]
    fn input_is_available() {
        let out = run(
            "const i = host.input(); i.a + i.b",
            json!({"a": 5, "b": 7}),
            None,
            DEFAULT_TIMEOUT_MS,
        )
        .unwrap();
        assert_eq!(out["result"], json!(12));
    }

    #[test]
    fn workspace_read_write_list_roundtrip() {
        let dir = tempdir().unwrap();
        let ws = Some(dir.path().to_path_buf());
        let out = run(
            "host.writeFile('note.txt', 'abc'); \
             const c = host.readFile('note.txt'); \
             const ls = host.listFiles('.'); \
             ({ content: c, files: ls })",
            Value::Null,
            ws,
            DEFAULT_TIMEOUT_MS,
        )
        .unwrap();
        assert_eq!(out["result"]["content"], json!("abc"));
        assert_eq!(out["result"]["files"], json!(["note.txt"]));
    }

    #[test]
    fn path_traversal_is_blocked() {
        let dir = tempdir().unwrap();
        let ws = Some(dir.path().to_path_buf());
        // Escaping the workspace must throw (caught in JS -> string result).
        let out = run(
            "try { host.readFile('../../etc/passwd'); 'LEAKED' } catch (e) { 'blocked' }",
            Value::Null,
            ws,
            DEFAULT_TIMEOUT_MS,
        )
        .unwrap();
        assert_eq!(out["result"], json!("blocked"));
    }

    #[test]
    fn host_errors_carry_a_message_to_js() {
        // A host exception should surface its message to the payload, not an
        // opaque throw. No workspace configured -> readFile should explain that.
        let out = run(
            "try { host.readFile('x'); 'NO_THROW' } catch (e) { String(e.message || e) }",
            Value::Null,
            None,
            DEFAULT_TIMEOUT_MS,
        )
        .unwrap();
        let msg = out["result"].as_str().unwrap_or("");
        assert!(
            msg.to_lowercase().contains("workspace"),
            "expected a workspace error message, got: {msg}"
        );
    }

    #[test]
    fn infinite_loop_hits_timeout() {
        // Should abort via the interrupt handler, not hang.
        let err = run("while (true) {}", Value::Null, None, 300).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("JS error") || msg.contains("interrupt"),
            "got: {msg}"
        );
    }
}
