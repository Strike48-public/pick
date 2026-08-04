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
/// Cap the failure reason so a pathological error body (e.g. a server that
/// returns a full HTML error page) can't dominate the screen. The CSS
/// (`.easy-signin-error`) also bounds + scrolls it, but truncating here keeps
/// the DOM small and the text readable. Trims on a char boundary.
fn truncate_reason(reason: &str) -> String {
    const MAX: usize = 500;
    let trimmed = reason.trim();
    if trimmed.chars().count() <= MAX {
        return trimmed.to_string();
    }
    let cut: String = trimmed.chars().take(MAX).collect();
    format!("{cut}…")
}

#[component]
pub fn OfflineScreen(props: OfflineScreenProps) -> Element {
    let failed = props.reason.is_some();
    rsx! {
        div { class: "easy-doc-screen easy-overlay",
            div { class: "easy-signin",
                if let Some(reason) = props.reason.clone() {
                    p { class: "easy-signin-title", "Couldn't connect to Strike48" }
                    p { class: "easy-signin-error", "{truncate_reason(&reason)}" }
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

#[cfg(test)]
mod tests {
    use super::truncate_reason;

    #[test]
    fn short_reason_is_unchanged() {
        assert_eq!(truncate_reason("Login timed out"), "Login timed out");
    }

    #[test]
    fn whitespace_is_trimmed() {
        assert_eq!(truncate_reason("  boom  "), "boom");
    }

    #[test]
    fn huge_reason_is_capped_with_ellipsis() {
        // A 3KB HTML blob (like a Keycloak error page) must be bounded.
        let blob = "<!DOCTYPE html>".to_string() + &"x".repeat(3000);
        let out = truncate_reason(&blob);
        assert!(out.chars().count() <= 501, "must cap to MAX+ellipsis");
        assert!(out.ends_with('…'), "must show it was truncated");
    }

    #[test]
    fn multibyte_reason_truncates_on_char_boundary() {
        // All multibyte chars — must not panic slicing mid-codepoint.
        let s = "é".repeat(1000);
        let out = truncate_reason(&s);
        assert!(out.ends_with('…'));
        assert!(out.chars().count() <= 501);
    }
}
