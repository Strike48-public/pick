# Strike48/pick patches — strike48-connector 0.6.2

Vendored fork of the crates.io release. This fork mirrors an upstream PR branch rather than carrying local markers;
changes are documented here and traced by diff, not marked in-source with
the upstream branch, so the sources carry no in-tree `[STRIKE48-PATCH]` markers. Audit the delta by diffing against the tracked upstream — `git diff` this tree vs. crates.io `strike48-connector` 0.6.2, or vs. Strike48/sdk-rs#65 (`fix/connector-owns-callback-origin`), which this fork mirrors 1:1.

Upstream: https://github.com/Strike48/sdk-rs

## connector-owns-callback-origin

**Files:** `src/auth/ott_provider.rs`, `src/connector.rs`

**Problem.** On post-approval OTT registration the connector POSTed its public
key to whatever host the server named in `CredentialsIssued.matrix_api_url`.
`STRIKE48_API_URL` could only *veto* that value, never replace it, so the two
reachable states were:

- unset → follow the server anywhere, including `http://localhost:4001`;
- set → refuse and strand the connector.

Server-side that value comes from `ApprovalService.matrix_api_url/1`, which
derives the tenant host from the gateway-injected `X-Matrix-Studio-Host` header
and otherwise falls back to the cluster-global `MATRIX_CONNECTOR_API_URL`, then
to `http://localhost:4001`. On the WebSocket transport `realm_info` is always
`nil` (`ConnectorSocket.connect/3` discards `connect_info`), so the header path
never fires and every WS connector gets the global or the localhost marker.

A single global cannot name each tenant's host, so no server-side setting fixes
this for a multi-tenant studio.

**Change.** The connector resolves its own callback base, in order:

1. `STRIKE48_API_URL` — explicit operator override, now authoritative rather
   than validate-only.
2. The host it actually dialed (`config.host` + `config.use_tls`), normalised to
   http(s) with any `connectors-` label and default port stripped. Per-connector
   by construction, so N connectors against N tenants each call back correctly.
3. The server-supplied value, last resort only.

`creds.matrix_api_url` being empty is no longer fatal. The origin allowlist is
retained for the case where nothing but the server value is available.

Derivation mirrors `pentest_core::connector_registration::derive_api_url` so
both ends agree on the same host algebra.

**Tracking:** vendored from Strike48/sdk-rs#65 (branch `fix/connector-owns-callback-origin`, 3 commits: resolve-callback-origin, enforce-on-all-three-paths 5c88578, proto clippy 5f03137). The enforcement now covers the single-connector path AND the multi-connector registration_runner / ws_multiplex paths.

**Drop when:** the equivalent lands upstream in Strike48/sdk-rs and pick moves to
that release.

**Vendoring scope:** only what `[patch.crates-io]` actually compiles - the lib.
`tests/`, `examples/` are not vendored (they are never built through the patch).
Upstream remains the source of truth for them.

## never-blank-failure

**Files:** `src/utils.rs`, `src/connector.rs`, `src/multi/ws_multiplex.rs`,
`src/multi/registration_runner.rs`, `src/client.rs`

**Problem.** A tool result that reports failure with a blank `error` crossed
the wire as `ExecuteResponse { success: true, error: "" }`, leaving the agent
"diagnosing blind" (Strike48/matrix#4715, defect 2).

**Change.** New `utils::sanitize_failure_payload` patches the payload's `error`
with an actionable message (naming the tool) and returns it so the caller can
mirror it into the envelope's `error` field. Wired at ALL THREE `execute` hops:
`ConnectorRunner::handle_request` (`connector.rs`),
`multi::ws_multiplex::handle_execute`, and
`multi::registration_runner::handle_execute`. Successes and failures that
already carry a message pass through untouched.

**Tests.** Unit tests for the sanitizer live inline in `src/utils.rs`
(`#[cfg(test)]`); each wire hop carries a `handle_*_patches_blank_failure`
test that fails if the envelope mirror is reverted to `String::new()` or the
sanitize call is dropped. To run the vendored lib tests standalone, the
vendored `Cargo.toml` gains an empty `[workspace]` table and
`test_fixtures/legacy_rsa_key.pem` is vendored (both are upstream files; the
workspace does not compile this package's tests, only the lib through the
patch).

**Tracking:** Strike48/matrix#4715 (defect 2). No upstream PR yet; file one
against Strike48/sdk-rs when landing this there.

**Drop when:** the equivalent lands upstream in Strike48/sdk-rs and pick moves to
that release.
