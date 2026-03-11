//! Interactive shell component using restty (GPU-accelerated terminal)
//!
//! Renders a full terminal emulator inside a div using restty's xterm
//! compatibility layer (WebGPU/WebGL2), connected to the PTY shell via WebSocket.

use dioxus::prelude::*;
use pentest_core::terminal::TerminalLine;

/// Base URL for the internal LiveView server.
/// Used by the Dioxus desktop/mobile WebView where `location.origin` is not
/// `http://127.0.0.1:3030` (it's `dioxus://index.html/` or similar).
/// In real browser contexts (liveview, Strike48 Studio proxy) the JS detects
/// HTTP/HTTPS and derives URLs from `location` instead.
const LIVEVIEW_BASE: &str = "http://127.0.0.1:3030";

/// JavaScript that initializes the restty terminal (GPU-accelerated) and connects
/// it to the PTY WebSocket via restty's built-in connectPty transport.
///
/// connectPty handles all I/O routing internally:
/// - Keyboard input -> JSON `{"type":"input","data":"..."}` -> WebSocket (no local echo)
/// - WebSocket output -> terminal renderer (via internal PTY output pipeline)
/// - Terminal resize -> JSON `{"type":"resize","cols":N,"rows":N}` -> WebSocket
const SHELL_INIT_JS: &str = include_str!("../assets/shell_init.js");

/// Interactive shell component.
///
/// Renders a GPU-accelerated restty terminal connected to the PTY shell via WebSocket.
/// Pass `shell_mode` to control whether to use native shell or proot environment.
/// When `shell_mode` changes, the existing terminal is torn down and a new session
/// is started with the updated mode.
#[component]
pub fn InteractiveShell(
    /// Shell mode: "native" for host shell, "proot" for BlackArch environment
    #[props(default = "native".to_string())]
    shell_mode: String,
) -> Element {
    // Track mode in a signal so the effect re-runs when it changes.
    let mut mode = use_signal(|| shell_mode.clone());
    if *mode.read() != shell_mode {
        mode.set(shell_mode.clone());
    }

    use_effect(move || {
        let current_mode = mode.read().clone();
        let js = SHELL_INIT_JS
            .replace("__LIVEVIEW_BASE__", LIVEVIEW_BASE)
            .replace("__SHELL_MODE__", &current_mode);
        crate::liveview_server::push_terminal_line(TerminalLine::info(format!(
            "[shell] initializing (mode={})",
            current_mode
        )));
        spawn(async move {
            // Tear down any existing terminal before (re-)initializing
            let _ = document::eval(
                r#"
                var c = document.getElementById('shell-container');
                if (c && c._shellCleanup) { c._shellCleanup(); }
                var loading = document.getElementById('shell-loading');
                if (loading) loading.style.display = '';
            "#,
            )
            .await;
            match document::eval(&js).await {
                Ok(_) => {
                    crate::liveview_server::push_terminal_line(TerminalLine::success(
                        "[shell] terminal connected".to_string(),
                    ));
                }
                Err(e) => {
                    tracing::warn!("JS eval failed (shell init): {e}");
                    crate::liveview_server::push_terminal_line(TerminalLine::error(format!(
                        "[shell] init failed: {e}"
                    )));
                }
            }
        });
    });

    rsx! {
        style { {include_str!("css/shell.css")} }

        div { class: "shell-container", id: "shell-container",
            div { class: "shell-loading", id: "shell-loading",
                "Starting shell..."
            }
        }
    }
}
