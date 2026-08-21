# Strike48/pick patches — strike48-connector 0.6.2

Vendored fork of the crates.io release. Every change is marked in-source with
`[STRIKE48-PATCH <slug>]`; audit with `git grep -n STRIKE48-PATCH vendor/strike48-connector`.

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

**Vendoring scope:** only what `[patch.crates-io]` actually compiles — the lib.
`tests/`, `test_fixtures/` and `examples/` are not vendored (they are never built
through the patch, and the unit tests for this change live inline in
`src/auth/ott_provider.rs`). Upstream remains the source of truth for them.
