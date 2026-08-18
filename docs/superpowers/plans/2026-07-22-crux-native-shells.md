# Crux Native Shells (iOS SwiftUI + Android Compose) — Implementation Plan

> **For agentic workers:** executed via subagent-driven-development. Steps use checkbox syntax.
> This is the phase AFTER Crux slice-1 (baseline crux-core + middleware + typegen). The user
> approved this direction and is AFK; the interactive brainstorm/spec-review gates are waived
> for this phase (documented deviation) — the design below encodes the user's stated constraints.

**Goal:** Two native shells (SwiftUI iOS, Jetpack Compose Android) rendering Pick's Easy Mode as a
pure function of the crux `ViewModel`, driven across crux 0.19's built-in `Bridge` FFI, iterated
until each handles Easy Mode end-to-end (sign in, Scan My Network, stream tool-calls, report via
document_write, in-app report viewer, doc sharing).

**Architecture (de-risked 2026-07-22):**
- crux 0.19 ships the ENTIRE native path: `Bridge<PickApp, BincodeFfiFormat>` (bincode
  event/request/view byte API) + facet typegen (Swift/Kotlin). **BoltFFI is NOT needed** —
  the user's tentative BoltFFI suggestion is superseded by evidence. PROVEN by
  `crates/crux-core/tests/ffi_bridge.rs` (Bridge<PickApp> compiles → EffectFFI satisfied;
  view() emits bytes; update(bincode(StartScan)) emits request bytes).
- A new `crates/crux-ffi` crate exposes the Bridge behind a stable C ABI (extern "C" byte
  buffers), built as `staticlib` (iOS) + `cdylib` (Android). Host-testable in pure Rust.
- iOS: static lib linked into an Xcode SwiftUI project; Swift wrapper calls the C ABI; effects
  (network I/O) handled shell-side OR via the PentestMiddleware pattern reimplemented in the
  bridge process. Decision: run effects IN-CORE via the middleware (the core owns a tokio
  runtime + CoreMatrixApi), so the shell only does update/resolve/view + platform capabilities
  the middleware cannot (OAuth browser, share sheet, open-url). See Effect Routing below.
- Android: cdylib (.so) loaded via JNI; Kotlin wrapper mirrors the Swift one.

**Tech stack:** Rust (crux_core 0.19, bincode 1.3.3 for FFI), SwiftUI + Xcode (Mac VM
engineering@10.10.0.8, nix develop for cargo), Jetpack Compose + Gradle/NDK 28.2 (x86_64
emulator-5554 via adb), facet-generated Swift/Kotlin types.

## Global Constraints
- Additive. crux-ffi depends only on crux-core + crux-middleware + pentest-core + strike48 SDK;
  never on crates/ui.
- The shells are PURE views of the ViewModel — no business logic in Swift/Kotlin.
- Effect routing: the FFI layer owns a tokio runtime + PentestMiddleware(CoreMatrixApi) so
  network effects resolve in-core; only genuinely-platform effects (OAuth browser present,
  OS share sheet, open URL) surface to the shell as ViewModel fields / dedicated FFI calls.
- iOS target: aarch64-apple-ios-sim (simulator on the Mac VM). Android: x86_64-linux-android
  (emulator-5554). Real-device targets are follow-ups.
- Reuse pentest-core verbatim; do NOT reimplement Matrix/auth/OAuth.
- PLG: host wss://plg.strike48.test, tenant *, MATRIX_TLS_INSECURE for self-signed. Test user
  plgdemo@example.com / PlgDemo123! (plg realm). Personal-tenant provisioning gotchas: memory
  plg-personal-tenant-realm-bug. Durable auth: memory pick-token-exchange-durable-auth.
- Commit rules: conventional; no attribution lines, no customer/tenant names, no emojis, no
  em-dashes. clippy -D warnings clean; cargo fmt clean.

## Effect Routing (the key design decision)
crux effects = { Render, Pentest(op) }. Options considered:
1. Shell handles every Pentest effect (shell talks to Matrix) — rejected: puts I/O + auth logic
   in Swift/Kotlin, violates "pure view" + duplicates pentest-core.
2. Core handles Pentest effects via PentestMiddleware; shell handles only Render (calls view())
   + a few platform capabilities — CHOSEN. The FFI crate builds a `Core` wrapped so the
   PentestMiddleware resolves Pentest ops on an owned tokio runtime; the shell's update/resolve
   loop only sees Render + any platform-only requests we model explicitly.
Platform-only actions that CANNOT live in the core: (a) OAuth sign-in browser present — model
as a ViewModel `needs_sign_in` + a shell FFI entrypoint that, after the native OAuth completes,
feeds the token back via an Event; (b) OS share sheet + open-url for a report — the ViewModel
hands the shell a share_url string; the shell invokes the native sheet. These match slice-1's
ViewModel design (open_document.share_url, needs_sign_in already exist).

## Tasks

### Task 1: `crates/crux-ffi` — C ABI over the Bridge (host-testable)
- Create crate: crate-type ["staticlib","cdylib","lib"]; deps crux-core, crux-middleware,
  pentest-core, tokio, bincode 1.3.3.
- Expose a `PickCore` handle owning `Bridge<PickApp>` + tokio runtime + PentestMiddleware.
- extern "C" API (byte buffers via pointer+len, caller-freed via a `pick_free` fn):
  `pick_core_new() -> *mut`, `pick_core_free`, `pick_view(core, out) `,
  `pick_update(core, event_ptr, event_len, out)`, `pick_resolve(core, id, resp_ptr, len, out)`.
  Use a returned owned buffer struct {ptr,len,cap} + `pick_bytes_free`.
- Wire the middleware so Pentest effects resolve in-core (spawn on the runtime, feed resolve
  back). Render + platform requests pass to the shell.
- Tests (host): new/view/update round-trip through the C ABI produces decodable ViewModel bytes;
  a StartScan drives a Pentest effect that the in-core middleware resolves (with a fake api).
- Commit.

### Task 2: Cross-compile the core libs
- iOS: on Mac VM, `cargo build -p pick-crux-ffi --target aarch64-apple-ios-sim` → libpick_crux_ffi.a
- Android: host, cargo-ndk (or direct with NDK 28.2 linker) `--target x86_64-linux-android` → .so
- Produce a C header (cbindgen) for the extern "C" API for Swift interop.
- Verify each artifact exists + `nm`/`objdump` shows the symbols. Commit build scripts (justfile
  targets), not binaries.

### Task 3: Generate + place Swift/Kotlin bindings
- Run the existing codegen bin (swift + kotlin) into the shell projects' source dirs.
- Add a decode helper mirroring the FFI byte protocol on each side.

### Task 4: SwiftUI iOS shell scaffold (builds + launches + renders Scan screen)
- Xcode project under apps/ios-crux (or reuse apps/mobile scheme). Link the static lib + header.
- Swift `Core` wrapper: bincode-decode ViewModel, encode Events, run update/resolve/view loop.
- Render the Scan screen from ViewModel. Launch on the Mac VM simulator; screenshot.

### Task 5: Compose Android shell scaffold (builds + launches + renders Scan screen)
- Gradle module under apps/android-crux. Load the .so via JNI; Kotlin `Core` wrapper.
- Render Scan screen. Install on emulator-5554; screenshot.

### Task 6+: Iterate to full Easy Mode on each (sign in → scan → stream → report → view → share)
- Wire OAuth sign-in (native browser) feeding token back as Event.
- Stream tool-calls (poll loop already modeled; wire CoreMatrixApi.poll to real GetConversation).
- Report via document_write (already in the scan prompt), in-app viewer (ViewModel.open_document),
  doc sharing (ViewModel share_url + native share sheet).
- Iterate per-platform until end-to-end on sim/emulator. Screenshot each milestone.

## Notes
- CoreMatrixApi.poll/list_conversations/load_conversation are slice-1 stubs — Task 6 wires them
  to real GraphQL (the streaming diff) since the native shells need real streaming.
- Mac VM has no `cargo`/`dx` on non-interactive SSH PATH — always `nix develop --command`.
- Android Dioxus liveview-socket-bind sandbox issue is Dioxus-specific; a native Compose shell
  loading a .so is NOT affected.
