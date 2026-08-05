# Strike48 patches to vendored `dioxus-asset-resolver`

Vendored from crates.io **dioxus-asset-resolver 0.7.9**. Wired in via
`[patch.crates-io]` in the repo-root `Cargo.toml`.

**How to find every local change:** `git grep -n "STRIKE48-PATCH" vendor/dioxus-asset-resolver`

**On upgrade:** re-vendor the new upstream version, re-apply each patch below by
locating the described spot in the new source, and delete a row (and its marker)
once the fix lands upstream.

| slug | file | what & why | upstream status |
|------|------|-----------|-----------------|
| `strip-prefix-panic` | `src/native.rs` (~L56, `resolve`) | Upstream does `uri_path.strip_prefix("/").unwrap()`, which panics (`StripPrefixError`) whenever the webview requests an asset path that neither exists on disk nor starts with `/` — reproducible on **Windows** when opening the expert sidebar, taking down the whole app. We replace the `unwrap` with a graceful fallback: return "not found" and log the offending path. | Not fixed as of 0.7.9. |
