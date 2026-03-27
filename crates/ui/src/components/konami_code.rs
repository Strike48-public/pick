//! Konami Code easter egg detector

use dioxus::prelude::*;
use pentest_core::config::Theme;
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

#[component]
pub fn KonamiCodeDetector(on_activated: EventHandler<()>) -> Element {
    let mut sequence = use_signal(|| Vec::<String>::new());
    let mut last_key_time = use_signal(|| std::time::Instant::now());

    // Global key listener
    use_effect(move || {
        spawn(async move {
            let script = r#"
                window.addEventListener('keydown', (e) => {
                    const key = e.key;
                    dioxus.send({type: 'konami_key', key: key});
                });
            "#;
            let _ = document::eval(script).await;
        });
    });

    rsx! {
        div {
            style: "display: none;",
            onmounted: move |_| {
                // Listen for konami_key events
            }
        }
    }
}

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

    rsx! {
        div {
            style: "display: contents;",
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

                    if matches {
                        seq.clear();
                        props.on_konami.call(());
                    }
                }
            },
            {props.children}
        }
    }
}
