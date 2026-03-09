//! WiFi scan warning dialog component

use dioxus::prelude::*;
use pentest_platform::WifiConnectionStatus;

use super::button::{Button, ButtonSize, ButtonVariant};

#[derive(Props, Clone, PartialEq)]
pub struct WifiWarningDialogProps {
    /// Whether the dialog is visible
    visible: bool,
    /// WiFi connection status assessment
    status: WifiConnectionStatus,
    /// Called when user proceeds anyway
    on_proceed: EventHandler<()>,
    /// Called when user cancels
    on_cancel: EventHandler<()>,
}

/// WiFi scan warning dialog - warns users about connection loss risks
#[component]
pub fn WifiWarningDialog(props: WifiWarningDialogProps) -> Element {
    if !props.visible {
        return rsx! {};
    }

    let risk_level = if props.status.safe_to_scan {
        "caution"
    } else {
        "high-risk"
    };

    let risk_text = if props.status.safe_to_scan {
        "Caution"
    } else {
        "High Risk"
    };

    rsx! {
        style { {include_str!("css/wifi_warning.css")} }

        // Backdrop - clicking it cancels
        div {
            class: "alert-dialog-backdrop",
            onclick: move |_| props.on_cancel.call(()),

            // Dialog card - stop propagation so clicking inside doesn't cancel
            div {
                class: "alert-dialog wifi-warning",
                onclick: move |evt| evt.stop_propagation(),

                // Title
                h2 { class: "alert-dialog-title",
                    "⚠️ WiFi Scan Warning"
                }

                // Content
                div { class: "wifi-warning-content",
                    // Risk badge
                    span { class: "risk-badge risk-{risk_level}",
                        "Risk Level: {risk_text}"
                    }

                    // Connection status
                    if props.status.connected_via_wifi {
                        p {
                            "You are currently connected via WiFi"
                            if let Some(ref iface) = props.status.active_interface {
                                " ({iface})"
                            }
                            "."
                        }

                        // High risk warning
                        if props.status.total_adapters == 1 {
                            div { class: "warning-consequences",
                                h4 { "Running this scan will:" }
                                ul {
                                    li { "❌ Put your WiFi adapter into monitor mode" }
                                    li { "❌ Disconnect you from the internet" }
                                    li { "❌ Disconnect Pick from Strike48 backend" }
                                    li { "❌ Likely cause the scan to fail" }
                                }
                            }
                        } else {
                            // Multiple adapters - suggest using external
                            p {
                                "✅ You have {props.status.total_adapters} WiFi adapters. "
                                "Consider using an external adapter for scanning."
                            }
                        }
                    }

                    // Adapter recommendations
                    div { class: "adapter-recommendation",
                        h4 { "💡 Recommended Solution:" }
                        p { "Use a dedicated external WiFi adapter for pentesting:" }
                        ul {
                            li {
                                strong { "Alfa AWUS036ACHM" }
                                " - Best overall (MT7610U)"
                            }
                            li {
                                strong { "Alfa AWUS036AXML" }
                                " - WiFi 6E (future-proof)"
                            }
                            li {
                                strong { "Alfa AWUS036ACS" }
                                " - Budget dual-band"
                            }
                        }
                        a {
                            href: "https://github.com/Strike48-public/pick#recommended-wifi-adapters",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            "View full adapter list in README →"
                        }
                    }
                }

                // Action buttons
                div { class: "alert-dialog-actions",
                    Button {
                        variant: ButtonVariant::Outline,
                        size: ButtonSize::Small,
                        on_click: move |_| props.on_cancel.call(()),
                        "Cancel"
                    }
                    Button {
                        variant: ButtonVariant::Destructive,
                        size: ButtonSize::Small,
                        on_click: move |_| props.on_proceed.call(()),
                        "Proceed Anyway"
                    }
                }
            }
        }
    }
}
