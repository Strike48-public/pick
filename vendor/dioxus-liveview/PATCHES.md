# Strike48 patches to vendored `dioxus-liveview`

Vendored from crates.io **dioxus-liveview 0.7.9** (see `Cargo.toml.orig` for the
pristine manifest). Wired in via `[patch.crates-io]` in the repo-root `Cargo.toml`.

**How to find every local change:** `git grep -n "STRIKE48-PATCH" vendor/dioxus-liveview`
— every divergence from upstream carries a `[STRIKE48-PATCH <slug>]` marker at the
edit site. This file is the index; the markers are the source of truth.

**On upgrade:** re-vendor the new upstream version, then re-apply each patch below
by searching the new source for the described location. Delete a row here (and its
marker) if the corresponding fix has landed upstream. Check each "Upstream status"
before re-applying — some may be fixed.

| slug | file | what & why | upstream status |
|------|------|-----------|-----------------|
| `webview2-ipc` | `src/query.rs` (`dioxus.send` in `DIOXUS_CODE`, and the eval return-value `.then(...)` in `new_query`) | `dioxus.send` / eval-return send over `window.ipc`, but on **WebView2 (Windows)** wry overwrites `window.ipc` with its native bridge (`s => window.chrome.webview.postMessage(s)`). Query frames then go to WebView2's native IPC sink, which the embedded connector has no handler for, so the browser→Rust reverse channel silently dies (DOM `user_event`s survive only because the interpreter captured the ws-backed ipc at init). We route these sends over `window.interpreter.ipc` (the `IPC{ws}` wrapper) instead, falling back to `window.ipc`. On WebKitGTK the two are the same object, so it's a no-op there. **Verified via CDP:** a frame sent through `window.ipc` never reached the server; the same frame through `window.interpreter.ipc` did. | Not fixed as of 0.7.9 / 0.8.0-alpha. No matching upstream issue found (closest: DioxusLabs/dioxus #3084, #4454). |
| `form-downcast` | `src/events.rs` (`convert_form_data`) | Upstream `.downcast::<SerializedFormData>().unwrap()` aborts the whole process when the downcast is `None`. On the desktop WebView2 transport an `oninput`/`onchange` event can arrive without a `SerializedFormData` payload, so it panics on the first keystroke in a text field. We fall back to an empty form instead of crashing. | Not fixed as of 0.7.9 / 0.8.0-alpha. |

## Notes
- `src/pool.rs` is **identical to upstream** — earlier diagnostic instrumentation
  (`LV_WS_DEBUG`) was reverted once the `webview2-ipc` root cause was found.
- Keep patches minimal and marked. Do not make unmarked edits to vendored files —
  they become invisible on the next upgrade.
