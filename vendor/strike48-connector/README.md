# Strike48 Connector SDK for Rust

Build connectors for the Strike48 platform in a few dozen lines of Rust.
Tool connectors (LLM-callable functions), request/response handlers,
static or dynamic web apps, or several of the above running in one
process sharing a single transport.

## Features

- **Tool connectors** — declarative `ToolConnector` schemas + `ToolAdapter`
  bridge to the gRPC stream.
- **Request/response connectors** — implement one `handle` method on
  `SimpleConnector`.
- **App connectors** — serve static directories or dynamic handlers
  inside Strike48 Studio.
- **Multiple connectors per process** — `MultiConnectorRunner` shares a
  single TCP+TLS connection (gRPC: one HTTP/2 channel, N streams).
- **Auto-reconnection** with exponential backoff and jitter.
- **OTT / direct-auth** flows via `OttProvider`, including K8s
  cert-manager integration.
- **Multiple payload encodings** — JSON (default), raw bytes, JSON lines,
  Arrow IPC, Protobuf, MessagePack, Parquet.

## Install

```toml
[dependencies]
strike48-connector = "0.3.5"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
serde_json = "1"
```

Until the crate is published to crates.io, depend on it directly from GitHub:

```toml
[dependencies]
strike48-connector = { git = "https://github.com/Strike48/sdk-rs", tag = "v0.3.5" }
```

For a specific branch (e.g. `develop`):

```toml
[dependencies]
strike48-connector = { git = "https://github.com/Strike48/sdk-rs", branch = "develop" }
```

For local development against a checkout:

```toml
[dependencies]
strike48-connector = { path = "../sdk-rs/crates/connector" }
```

### Private repo authentication

Cargo uses your Git credentials. The simplest options are SSH (Cargo
picks up `ssh-agent` automatically) or a Personal Access Token via
`~/.netrc`:

```bash
cat >> ~/.netrc << EOF
machine github.com
login YOUR_GITHUB_USERNAME
password YOUR_GITHUB_TOKEN
EOF
chmod 600 ~/.netrc
```

Then point at the SSH remote if you prefer:

```toml
[dependencies]
strike48-connector = { git = "ssh://git@github.com/Strike48/sdk-rs", tag = "v0.3.5" }
```

## Quick start

### A tool connector (the common case)

```rust
use async_trait::async_trait;
use serde_json::{Value, json};
use strike48_connector::*;

struct Calculator;

#[async_trait]
impl ToolConnector for Calculator {
    fn tools(&self) -> Vec<ToolSchema> {
        vec![ToolSchema::new("add", "Add two numbers")
            .param("a", ParamType::Number, "First operand", true)
            .param("b", ParamType::Number, "Second operand", true)]
    }
    async fn execute(&self, _tool: &str, p: Value) -> ToolResult {
        let a = p["a"].as_f64().unwrap_or(0.0);
        let b = p["b"].as_f64().unwrap_or(0.0);
        ToolResult::success(json!({ "result": a + b }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    simple::run_tool(
        ToolAdapter::new("calculator", Calculator)
            .with_version("1.0.0")
            .with_category("math"),
    ).await
}
```

`simple::run_tool` reads connection config from the environment, wires
Ctrl-C to a graceful shutdown, and runs a single `ConnectorRunner` to
completion.

### A request/response connector

```rust
use strike48_connector::prelude::*;

struct Echo;

#[async_trait]
impl SimpleConnector for Echo {
    fn name(&self) -> &str { "echo" }
    fn version(&self) -> &str { "1.0.0" }
    async fn handle(&self, request: Value) -> Result<Value> {
        Ok(json!({ "echo": request }))
    }
}

#[tokio::main]
async fn main() -> Result<()> { Echo.run().await }
```

### Multiple connectors per process

`MultiConnectorRunner` runs `N` independently-approvable registrations
over a shared transport. Over gRPC this is a single TCP+TLS connection
with one HTTP/2 stream per registration; the runner lazily opens an
additional channel when `max_streams_per_channel` is hit. Over
WebSocket (HTTP/1.1, no native multiplexing) the API is identical but
each registration uses its own WS connection.

From the Strike48 server's point of view, each registration is a
normal `Connect` RPC — there are no server-side changes. See
`examples/mixed_connectors.rs` for three distinct tool connectors
running together, and `examples/multi_connector.rs` for an A/B
benchmark of shared-channel vs independent-runner mode.

## Configuration

All entry points read configuration from environment variables via
`ConnectorConfig::from_env`. Only the variables actually consulted by
the SDK are documented here — anything else is ignored.

### Server / identity

| Variable | Description | Default |
|---|---|---|
| `STRIKE48_URL` | Server URL with scheme (e.g. `grpc://host:50061`, `ws://host:4000`). Auto-detects transport and TLS. Highest priority. | unset |
| `STRIKE48_HOST` | Host:port (e.g. `localhost:50061`) when not using a scheme'd URL. Also accepts a URL — auto-detects transport. | `localhost:50061` |
| `MATRIX_HOST` | Legacy fallback for `STRIKE48_URL`. Honored if `STRIKE48_URL` is unset. | unset |
| `TENANT_ID` | Tenant identifier. | `default` |
| `INSTANCE_ID` | Stable connector instance ID — required for credential reuse on restart. | `<connector_type>-<unix_ms>` |
| `AUTH_TOKEN` | Pre-issued JWT (skips the OTT approval flow). | empty |
| `USE_TLS` | `true`/`false`. Used only when the host string is not a scheme'd URL. | `false` |

### Display & metadata

| Variable | Description |
|---|---|
| `CONNECTOR_DISPLAY_NAME` | Human-readable name for Strike48 Studio (defaults to `instance_id`). |
| `CONNECTOR_TAGS` | Comma-separated tags used for tag-based routing (e.g. `prod,us-east-1`). |

### Metrics

| Variable | Description | Default |
|---|---|---|
| `STRIKE48_METRICS_ENABLED` | `false`/`0` disables periodic metrics reporting. | enabled |
| `STRIKE48_METRICS_INTERVAL_MS` | Metrics report interval. | `30000` |

### Authentication storage

| Variable | Description | Default |
|---|---|---|
| `STRIKE48_KEYS_DIR` | Directory for generated private keys. | `~/.strike48/keys` |
| `STRIKE48_PRIVATE_KEY_PATH` | Use a pre-mounted private key (cert-manager / direct-auth modes). | unset |
| `STRIKE48_CLIENT_ID` | Auth client ID for cert-manager / direct-auth modes. | unset |
| `STRIKE48_AUTH_URL` | Auth realm URL for cert-manager / direct-auth modes. | unset |
| `STRIKE48_REGISTRATION_TOKEN` | One-Time Token (OTT) for pre-approval mode (inline value). | unset |
| `STRIKE48_REGISTRATION_TOKEN_FILE` | Path to a file containing an OTT. | unset |

### TLS

| Variable | Description |
|---|---|
| `MATRIX_TLS_INSECURE` | `true` skips TLS verification (legacy name; still honored for OTT HTTP client and gRPC/WS transports). |
| `MATRIX_TLS_CA_CERT` | Path to a custom CA bundle for the gRPC transport (legacy name; still honored). |

### Programmatic configuration

```rust
use strike48_connector::*;

let config = ConnectorConfig::from_env()
    .display_name("Production Server 1")
    .tag("prod")
    .tag("us-east-1")
    .with_metadata("location", "AWS US-East-1")
    .with_metadata("owner", "platform-team");
```

Builder methods on `ConnectorConfig`:

| Method | Description |
|---|---|
| `.display_name(name)` | Human-readable name for UI (defaults to `instance_id`). |
| `.tag(tag)` | Add a single tag for grouping. |
| `.tags([...])` | Add multiple tags at once. |
| `.with_metadata(key, value)` | Add operator metadata. |
| `.metadata_from_env(prefix)` | Load metadata from env vars with the given prefix (e.g. `metadata_from_env("CONNECTOR_")` reads `CONNECTOR_LOCATION`, `CONNECTOR_OWNER`, ...). |

## Authentication

The SDK uses asymmetric authentication (`private_key_jwt`) backed by
**EC P-256** key pairs (signed via `aws-lc-rs`). On first connection
the SDK generates a key pair, registers the public key with Strike48,
and persists the private key for future runs. Four deployment modes
are supported (see `auth/ott_provider.rs`):

1. **Pre-approval (OTT)** — admin issues a One-Time Token; the
   connector consumes it via `STRIKE48_REGISTRATION_TOKEN` (or
   `STRIKE48_REGISTRATION_TOKEN_FILE`) and registers itself.
2. **Post-approval** — the connector connects, an admin approves it
   in Strike48 Studio, and credentials are issued over the gRPC
   stream. No env vars needed.
3. **Kubernetes cert-manager** — cert-manager creates the keypair and
   mounts it at `STRIKE48_PRIVATE_KEY_PATH`; set `STRIKE48_CLIENT_ID`
   and `STRIKE48_AUTH_URL` to the operator-provisioned realm.
4. **Direct auth** — same as cert-manager but with an operator-managed
   private key file.

### Default storage locations

| Item | Location |
|---|---|
| Generated private keys | `~/.strike48/keys/{connector_type}_{instance_id}.pem` (override with `STRIKE48_KEYS_DIR`) |
| Saved credentials | `~/.strike48/credentials/` |

### Reconnection

When the connector restarts with the same `INSTANCE_ID`, the SDK loads
saved credentials, fetches a fresh JWT using the saved private key,
and reconnects without requiring re-approval. This requires the same
`INSTANCE_ID`, an existing credentials file, and an existing private
key.

## Examples

All live under `crates/connector/examples/`:

| File | What it shows |
|---|---|
| `calculator_tool.rs` | Minimal tool connector: `ToolConnector` + `ToolAdapter` + `simple::run_tool`. |
| `simple_echo.rs` | Minimal `SimpleConnector` request/response. |
| `system_command_tool.rs` | Fuller TOOL example (pre-`ToolAdapter`, kept for reference). |
| `app_connector.rs` | APP behavior using the `App::builder` fluent API. |
| `auth_app.rs` | APP behavior with custom authentication. |
| `mixed_connectors.rs` | Three distinct tool connectors in one process via `MultiConnectorRunner`. |
| `multi_connector.rs` | N copies of one connector type — A/B benchmark of shared-channel vs independent-runner. |
| `one_liner.rs` | `run_connector` / `serve_static` one-liners. |
| `echo_connector.rs` | Low-level `BaseConnector` reference (prefer `simple_echo.rs`). |
| `app_isolation_test.rs`, `async_test_connector.rs`, `connector_test.rs` | Integration test harnesses. |
| `diagnostic_idle_app.rs`, `diagnostic_idle_connector.rs`, `diagnostic_load_app.rs`, `diagnostic_load_connector.rs` | Diagnostic / load-test rigs. |

### Running examples

```bash
export STRIKE48_HOST=grpc://localhost:50061
export TENANT_ID=non-prod

cargo run -p strike48-connector --example calculator_tool --release
cargo run -p strike48-connector --example simple_echo
cargo run -p strike48-connector --example mixed_connectors --release
```

## Architecture

The SDK has two layered APIs:

- **Recommended (high-level)**:
  - `SimpleConnector` — implement one `handle(request) -> response`
    method for synchronous request/response work.
  - `ToolConnector` + `ToolAdapter` — declarative tool schemas with
    dispatch by tool name; wrap in `ToolAdapter` and hand to
    `simple::run_tool` (or any runner).
  - `simple::run_tool`, `simple::serve_static`, `simple::serve_app`,
    `simple::run_connector` — convenience entry points that read
    config from the environment, init logging, and wire signals.
  - `MultiConnectorRunner` — multiple registrations per process over
    one shared transport.
- **Advanced (low-level)**:
  - `BaseConnector` — raw trait with `execute`, `behaviors`,
    `capabilities`, `metadata`, and the WebSocket-frame callbacks.
    Implement directly when you need raw stream callbacks (e.g.
    streaming WebSocket frames in App connectors). Override
    `execute_with_context` (default delegates to `execute`) when your
    connector needs the server-supplied per-request context map —
    used by multi-tenant deployments to read keys like
    `tenant_id`. `ToolConnector` exposes a matching
    `execute_with_context` for the same use case.
  - `ConnectorRunner` — drives a `BaseConnector` over a single
    transport, owns reconnection, OTT auth, and metrics.
  - `ConnectorHandle` / `ConnectorClient` — for connectors that manage
    their own gRPC streams or send unsolicited frames from callbacks.

Behavior modules under `behaviors/` implement the gRPC-level concerns
for each connector kind: `app`, `pubsub`, `request_response`, `sink`,
`source`, `tool` (+ `tool_adapter`).

## Payload encodings

`PayloadEncoding`: `JSON` (default), `RAW_BYTES`, `JSON_LINES`,
`ARROW_IPC`, `PROTOBUF`, `MSGPACK`, `PARQUET`.

## Error handling

All operations return `Result<T, ConnectorError>`:

```rust
match runner.run().await {
    Ok(_) => println!("Connector stopped gracefully"),
    Err(e) => eprintln!("Error: {} (code: {})", e, e.code()),
}
```

## Logging

The SDK uses the `tracing` crate. Initialize the default subscriber once:

```rust
strike48_connector::init_logger();
```

Control log level via `RUST_LOG`:

```bash
RUST_LOG=debug cargo run -p strike48-connector --example calculator_tool
```

## License

See [`LICENSE`](LICENSE) at the repo root.
