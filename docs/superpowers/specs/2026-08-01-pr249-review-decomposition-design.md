# PR #249 Review Decomposition & Remediation Design

**Date:** 2026-08-01
**Branch under review:** `josh/catching-up` (PR #249, DRAFT) — 365 commits, 324 files
**Trigger:** Tomek's review (9 blocking findings + should-fix/low + suggested 5-way split)

---

## Problem

PR #249 bundles too much for a single review: build tooling, a new shared-core
(crux) architecture, two native shells, a PLG OAuth-first registration flow,
telemetry, and an undisclosed arbitrary-JavaScript execution tool (`run_js`).
The reviewer confirmed the engineering is largely sound but flagged that the
findings cluster in the least-reviewed-per-line areas, and recommended
decomposing before landing.

## Decision Summary

- **Extract crux and run_js onto their own branches** (decision: "Crux + run_js
  out, rest stays #249").
- **Extract-only, defer fixes** on both carved-out branches (decision: "Extract
  only, defer fixes").
- **Snapshot-then-delete** as the split mechanism — no history rewrite (decision:
  "Snapshot new branch, delete from #249").
- **Fix everything that stays** on #249 (decision: "Everything that stays on
  #249").

## Branch Topology

Three branches result from today's single draft:

| Branch | Contents | Findings carried | Disposition |
|---|---|---|---|
| `feat/pick-crux` (new) | `crates/crux-core`, `crates/crux-ffi`, `crates/crux-middleware`, `apps/android-crux`, `apps/ios-crux` | 1, 3, 4, 5, 6, 7 | Extract-only, fixes deferred |
| `feat/run-js-tool` (new) | `crates/tools/src/run_js.rs` + registration | 8 | Extract-only, fixes deferred |
| `josh/catching-up` (#249) | Sage reskin, docs/share, PLG OAuth-first registration, telemetry, nix/dx build, Android CI | 9 + finding-2 core + all remaining should-fix/low | Fix everything that stays |

### Coupling verification (done during design)

- crux crates are referenced only by the workspace `members` list, each other,
  and `Cargo.lock`. No non-crux crate depends on them (`crates/ui`, desktop,
  headless are independent shells).
- `run_js` / `RunJsTool` has zero references outside `crates/tools/src`.
- Both delete cleanly with a `Cargo.lock` regen.

## Finding-to-Home Mapping

### Leaves with `feat/pick-crux` (deferred)

- **F1** — `OAuthManager.swift:48` logs full access-token URL to iOS system log.
- **F3** — `crux-core/src/markdown.rs:65` tables render as nothing.
- **F4** — `crux-core/src/update.rs:87` poll-across-logout repopulates cleared session.
- **F5** — `crux-ffi/src/lib.rs:427` iOS logout can't clear token (null baseAddress).
- **F6** — `crux-ffi/src/lib.rs:212` connector survives logout under prior tenant.
- **F7** — `crux-core/src/update.rs:82` failure leaves "Thinking…" animation forever.
- Plus crux-only should-fix items: `Event::Logout`/`NewChat` `tool_calls` clear
  (`update.rs:483`), crux-ffi `fake_core`/notify test gaps, delta replace-vs-extend
  test seed, `ffi_bridge.rs:19` assertion depth.

### Leaves with `feat/run-js-tool` (deferred)

- **F8** — `run_js.rs:314` `host.httpFetch` has no URL validation (SSRF to metadata service).

### Stays on #249 (fix now — "everything that stays")

**Blocking:**
- **F9** — `cargo fmt --all` fixes `crates/platform/src/ios/oauth.rs:77,113,134`.
- **F2 (core half)** — `crates/core/src/matrix/auth.rs`: generate + validate a
  `state` parameter; `deliver_native_oauth_callback` must reject callbacks with
  no matching in-flight request (fix `None`-arm-returns-`true` and
  cache-before-check ordering). Protects the still-shipping `apps/mobile` JNI shell
  (confirmed `apps/mobile/src/main.rs:146` still calls it). The
  `android:exported="true"` manifest half of F2 lives in `apps/android-crux` and
  leaves with crux.

**Security should-fix:**
- OTT written 0600 atomically via `OpenOptions.mode(0o600)` + dir 0700
  (`pre_approval.rs:65`).
- `derive_api_url` must not downgrade explicit `https://` to `http://`
  (`connector_registration.rs:23`).
- Telemetry: check `sentry::init` guard with `is_enabled()` before setting
  `ENABLED`/logging success; wire documented `flush()` on backgrounding
  (`telemetry.rs:203`).

**Correctness / robustness should-fix:**
- `documents_panel.rs:195` — surface load errors instead of silent infinite retry.
- `param_bool` string/int coercion + test (`util.rs:57`).
- mdns/ssdp silent-failure distinguishability (`mdns.rs:45`, `ssdp.rs:25/41`) —
  structured "probe skipped" result; also honor `set_read_timeout` result
  (`mdns.rs:45`) so `discover()` can't hang.

**Test-coverage should-fix (that stay):**
- `service_banner.rs` batch tests.
- `param_bool` test.
- OAuth tests feature-gating so they run in the macOS lane (`auth.rs:201`).
- OTT-perms umask test.

> Note: the `Event::Logout` `tool_calls`-clear item was originally listed for
> #249 but lives in `crux-core/src/update.rs` and therefore leaves with crux.
> Reclassified during design.

## Execution Order

1. **Snapshot branches.** `git branch feat/pick-crux` and
   `git branch feat/run-js-tool` from current `josh/catching-up` tip. Pure
   snapshots — no fixes touched, findings travel untouched. Deferred findings are
   tracked by the team out-of-band (no GitHub tracking issues opened).
2. **Delete from #249.** Remove the 5 crux paths + `run_js.rs`; drop the 3 crux
   `members` entries from `Cargo.toml`; remove `RunJsTool` mod/use/register lines
   from `crates/tools/src/lib.rs`; regen `Cargo.lock`. One cleanup commit.
3. **Confirm green before fixing.** Run the full gate and confirm #249 still
   builds/tests/lints clean *before* applying any Section-3 fixes.
4. **Apply #249 fixes** in dependency order. `cargo fmt --all` runs **last**,
   since other edits reintroduce formatting drift.

## Verification Gate (per CLAUDE.md, mandatory before ready)

```
cargo fmt --all -- --check
cargo check --all-targets
cargo test --workspace
cargo clippy --all-targets -- -D warnings
git status   # clean
```

## Out of Scope

- Opening PRs or tracking issues for `feat/pick-crux` / `feat/run-js-tool` (parked; deferred findings tracked by the team out-of-band).
- Fixing deferred crux/run_js findings.
- The "commit generated bindings 4×" maintainability item — leaves with crux.
- Product decisions (telemetry default-on consent) — flag to maintainer, not a code change here.
