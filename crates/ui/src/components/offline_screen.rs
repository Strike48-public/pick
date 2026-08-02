//! Graceful offline / auth-unavailable screen for easy mode.
//!
//! Replaces the bare sign-in overlay. The easy-mode `AuthFlow` states
//! `AwaitingGesture`, `Disconnected`, and `Failed { reauth: true, .. }` all
//! render this: a branded panel that explains the state and offers Sign in,
//! Change server, and (on failure) Retry — never a blank or dead screen.

use dioxus::prelude::*;

/// Props for [`OfflineScreen`].
#[derive(Props, Clone, PartialEq)]
pub struct OfflineScreenProps {
    #[props(default)]
    pub reason: Option<String>,
    pub on_sign_in: EventHandler<()>,
    pub on_change_server: EventHandler<()>,
    pub on_retry: EventHandler<()>,
}

/// The graceful offline screen. When `reason` is `Some`, the state came from a
/// connection/auth failure: show the reason and emphasize "Try again". When
/// `None` (a plain disconnect or a cancelled sign-in), show a neutral prompt and
/// emphasize "Sign in". "Change server" is always offered as a secondary action.
#[component]
pub fn OfflineScreen(props: OfflineScreenProps) -> Element {
    let failed = props.reason.is_some();
    rsx! {
        div { class: "easy-doc-screen easy-overlay",
            div { class: "easy-signin",
                if let Some(reason) = props.reason.clone() {
                    p { class: "easy-signin-title", "Couldn't connect to Strike48" }
                    p { class: "easy-signin-sub", "{reason}" }
                } else {
                    p { class: "easy-signin-title", "You're not connected" }
                    p { class: "easy-signin-sub", "Sign in to register this connector and start scanning. We'll open your browser to complete sign-in." }
                }
                // Primary action: Retry when we failed, Sign in otherwise.
                button {
                    class: "action-card",
                    onclick: move |_| {
                        if failed {
                            props.on_retry.call(());
                        } else {
                            props.on_sign_in.call(());
                        }
                    },
                    span { class: "action-card-label",
                        if failed { "Try again" } else { "Sign in" }
                    }
                }
                // Secondary action: change the Strike48 endpoint.
                button {
                    class: "easy-signin-secondary",
                    onclick: move |_| props.on_change_server.call(()),
                    "Change server"
                }
            }
        }
    }
}
