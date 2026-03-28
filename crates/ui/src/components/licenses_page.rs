//! Licenses page - attribution for open source dependencies

use dioxus::prelude::*;

#[component]
pub fn LicensesPage() -> Element {
    rsx! {
        style { {include_str!("css/licenses_page.css")} }

        div { class: "licenses-page",
            div { class: "licenses-header",
                h1 { "Open Source Licenses" }
                p { "Pick is built on the shoulders of giants. We use and appreciate these open source projects:" }
            }

            div { class: "licenses-content",
                // Pick itself
                LicenseCard {
                    name: "Pick Penetration Testing Connector",
                    license: "MIT License",
                    description: "This application",
                    url: "https://github.com/Strike48-public/pick"
                }

                // Major frameworks
                LicenseCard {
                    name: "Dioxus",
                    license: "MIT/Apache-2.0",
                    description: "Rust GUI framework for building cross-platform applications",
                    url: "https://dioxuslabs.com"
                }

                LicenseCard {
                    name: "Tokio",
                    license: "MIT License",
                    description: "Asynchronous runtime for Rust",
                    url: "https://tokio.rs"
                }

                // Inspired by (not using actual code)
                LicenseCard {
                    name: "CyberChef",
                    license: "Apache-2.0 License",
                    description: "CyberChef functionality inspired by the GCHQ CyberChef project (clean room implementation)",
                    url: "https://github.com/gchq/CyberChef"
                }

                // Tools/Libraries
                LicenseCard {
                    name: "Tabler Icons",
                    license: "MIT License",
                    description: "Icon set used in the UI",
                    url: "https://tabler-icons.io"
                }

                LicenseCard {
                    name: "Rust",
                    license: "MIT/Apache-2.0",
                    description: "Programming language",
                    url: "https://www.rust-lang.org"
                }

                div { class: "licenses-footer",
                    p {
                        "For a complete list of dependencies and their licenses, see "
                        code { "Cargo.lock" }
                        " in the source repository."
                    }
                    p {
                        "All trademarks are property of their respective owners."
                    }
                }
            }
        }
    }
}

#[component]
fn LicenseCard(name: String, license: String, description: String, url: String) -> Element {
    rsx! {
        div { class: "license-card",
            div { class: "license-card-header",
                h3 { "{name}" }
                span { class: "license-badge", "{license}" }
            }
            p { class: "license-description", "{description}" }
            a {
                href: "{url}",
                target: "_blank",
                class: "license-link",
                "{url}"
            }
        }
    }
}
