//! Windows "Install WSL for better scanning" banner.
//!
//! A controlled, presentation-only component: the PARENT
//! ([`crate::connector_app`]) owns whether the banner is visible and the whole
//! install state machine (idle -> installing -> reboot-required / error). This
//! component just renders the current state and fires callbacks.
//!
//! It surfaces on Windows when Pick's sandbox finds no backend, offering a
//! guided WSL install. The actual install is a desktop-only concern; the parent
//! routes it through the `ConnectorAppConfig::run_wsl_install` hook so this
//! cross-target crate never depends on `pentest-platform`'s `wsl_install`
//! module.

use dioxus::prelude::*;

use super::button::{Button, ButtonSize, ButtonVariant};
use super::icons::{Download, Terminal, X};

/// Props for [`WslInstallBanner`].
///
/// Visibility and install state are OWNED BY THE PARENT — this is a controlled
/// component. It renders the given state and fires callbacks; it holds no state
/// of its own.
#[derive(Props, Clone, PartialEq)]
pub struct WslInstallBannerProps {
    /// True while the guided install is running. Shows a spinner + "Installing…"
    /// and disables the action buttons.
    #[props(default = false)]
    pub installing: bool,
    /// True once the install reported that a reboot is required. Shows a
    /// "Restart required" message and (if `on_restart` is set) a Restart button.
    #[props(default = false)]
    pub reboot_required: bool,
    /// A human-readable error from the last install attempt, if any.
    #[props(default)]
    pub error: Option<String>,
    /// Fired when the user dismisses the banner (the "X").
    pub on_dismiss: EventHandler<()>,
    /// Fired when the user clicks Install.
    pub on_install: EventHandler<()>,
    /// Fired when the user clicks How (opens the WSL docs). The parent calls
    /// `pentest_core::matrix::open_url_in_browser`.
    pub on_how: EventHandler<()>,
}

/// Dismissable Windows banner that offers a guided WSL install.
///
/// See [`WslInstallBannerProps`] for the controlled-component contract.
#[component]
pub fn WslInstallBanner(props: WslInstallBannerProps) -> Element {
    rsx! {
        style { {include_str!("css/wsl_install_banner.css")} }

        div { class: "wsl-banner",
            div { class: "wsl-banner-icon",
                Terminal { size: 20 }
            }

            div { class: "wsl-banner-body",
                h3 { class: "wsl-banner-title", "Install WSL for better scanning" }
                p { class: "wsl-banner-text",
                    "Pick runs its scanning tools inside an isolated Linux sandbox for "
                    "safety and consistency. On Windows that sandbox uses WSL (the "
                    "Windows Subsystem for Linux), which isn't set up yet. Install it to "
                    "unlock sandboxed scans."
                }

                div { class: "wsl-banner-actions",
                    if props.installing {
                        span { class: "wsl-banner-status",
                            span { class: "wsl-banner-spinner" }
                            "Installing…"
                        }
                    } else if props.reboot_required {
                        span { class: "wsl-banner-status is-reboot",
                            "WSL installed. Restart Windows to finish, then reopen Pick."
                        }
                    } else {
                        Button {
                            variant: ButtonVariant::Primary,
                            size: ButtonSize::Small,
                            on_click: move |_| props.on_install.call(()),
                            Download { size: 16 }
                            "Install"
                        }
                        Button {
                            variant: ButtonVariant::Outline,
                            size: ButtonSize::Small,
                            on_click: move |_| props.on_how.call(()),
                            "How"
                        }
                    }

                    // Error surfaces alongside whatever state we're in.
                    if let Some(err) = props.error.clone() {
                        span { class: "wsl-banner-status is-error", "{err}" }
                    }
                }
            }

            button {
                class: "wsl-banner-dismiss",
                title: "Dismiss",
                "aria-label": "Dismiss",
                onclick: move |_| props.on_dismiss.call(()),
                X { size: 16 }
            }
        }
    }
}
