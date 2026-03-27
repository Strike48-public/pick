//! Konami Code easter egg detector

use dioxus::prelude::*;
use std::time::Duration;

/// Konami code sequence: ↑ ↑ ↓ ↓ ← → ← → B A
const KONAMI_SEQUENCE: &[&str] = &[
    "ArrowUp",
    "ArrowUp",
    "ArrowDown",
    "ArrowDown",
    "ArrowLeft",
    "ArrowRight",
    "ArrowLeft",
    "ArrowRight",
    "b",
    "a",
];


/// Props for the Konami code wrapper
#[derive(Props, Clone, PartialEq)]
pub struct KonamiCodeWrapperProps {
    /// Callback when Konami code is entered
    on_konami: EventHandler<()>,
    /// The wrapped content
    children: Element,
}

/// Wrapper component that detects Konami code and triggers callback
#[component]
pub fn KonamiCodeWrapper(props: KonamiCodeWrapperProps) -> Element {
    let mut sequence = use_signal(|| Vec::<String>::new());
    let mut last_key_time = use_signal(|| std::time::Instant::now());

    // Auto-focus wrapper on mount
    use_effect(move || {
        spawn(async move {
            let _ = document::eval(
                r#"
                let el = document.querySelector('[data-konami-wrapper]');
                if (el) el.focus();
                "#,
            )
            .await;
        });
    });

    rsx! {
        div {
            "data-konami-wrapper": "true",
            tabindex: 0,
            style: "display: contents; outline: none;",
            onkeydown: move |evt: Event<KeyboardData>| {
                let now = std::time::Instant::now();
                let mut seq = sequence.write();

                // Reset if more than 2 seconds since last key
                if now.duration_since(*last_key_time.read()) > Duration::from_secs(2) {
                    seq.clear();
                }
                last_key_time.set(now);

                // Add key to sequence
                let key = evt.key().to_string();
                seq.push(key.clone());

                // Debug logging
                tracing::debug!("Konami: key={}, sequence len={}", key, seq.len());

                // Keep only last 10 keys
                if seq.len() > 10 {
                    seq.remove(0);
                }

                // Check if sequence matches Konami code
                if seq.len() == KONAMI_SEQUENCE.len() {
                    let matches = seq.iter().zip(KONAMI_SEQUENCE.iter()).all(|(a, b)| {
                        let a_lower = a.to_lowercase();
                        let b_lower = b.to_lowercase();
                        a_lower == b_lower
                    });

                    tracing::debug!("Konami: checking match, matches={}", matches);

                    if matches {
                        tracing::info!("Konami code activated!");
                        seq.clear();
                        props.on_konami.call(());
                    }
                }
            },
            {props.children}
        }
    }
}
