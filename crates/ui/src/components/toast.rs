//! Toast notification component

use dioxus::prelude::*;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq)]
pub enum ToastVariant {
    Success,
    Error,
    Info,
    Warning,
}

#[component]
pub fn Toast(
    message: String,
    variant: ToastVariant,
    on_dismiss: EventHandler<()>,
    auto_dismiss_ms: Option<u64>,
) -> Element {
    let mut visible = use_signal(|| true);

    // Auto-dismiss after delay
    use_effect(move || {
        if let Some(ms) = auto_dismiss_ms {
            spawn(async move {
                async_std::task::sleep(Duration::from_millis(ms)).await;
                visible.set(false);
                // Wait for animation to complete
                async_std::task::sleep(Duration::from_millis(300)).await;
                on_dismiss.call(());
            });
        }
    });

    let (icon, bg_class) = match variant {
        ToastVariant::Success => ("✓", "toast-success"),
        ToastVariant::Error => ("✗", "toast-error"),
        ToastVariant::Info => ("i", "toast-info"),
        ToastVariant::Warning => ("⚠", "toast-warning"),
    };

    rsx! {
        div {
            class: "toast {bg_class}",
            class: if *visible.read() { "toast-enter" } else { "toast-exit" },
            onclick: move |_| {
                visible.set(false);
                spawn(async move {
                    async_std::task::sleep(Duration::from_millis(300)).await;
                    on_dismiss.call(());
                });
            },
            div { class: "toast-icon", "{icon}" }
            div { class: "toast-message", "{message}" }
        }
    }
}

#[component]
pub fn ToastContainer(children: Element) -> Element {
    rsx! {
        div { class: "toast-container",
            {children}
        }
    }
}

pub fn toast_css() -> &'static str {
    r#"
.toast-container {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 12px;
    pointer-events: none;
}

.toast {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    backdrop-filter: blur(8px);
    pointer-events: auto;
    cursor: pointer;
    min-width: 280px;
    max-width: 420px;
    border: 1px solid var(--border);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.toast-enter {
    animation: toast-slide-in 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.toast-exit {
    animation: toast-slide-out 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    opacity: 0;
    transform: translateX(100%);
}

@keyframes toast-slide-in {
    from {
        opacity: 0;
        transform: translateX(100%);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes toast-slide-out {
    from {
        opacity: 1;
        transform: translateX(0);
    }
    to {
        opacity: 0;
        transform: translateX(100%);
    }
}

.toast:hover {
    transform: scale(1.02);
}

.toast-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    font-weight: bold;
    font-size: 14px;
    flex-shrink: 0;
}

.toast-message {
    flex: 1;
    font-size: 14px;
    line-height: 1.4;
    color: var(--foreground);
}

.toast-success {
    background: oklch(from var(--primary) l c h / 0.1);
    border-color: var(--primary);
}

.toast-success .toast-icon {
    background: var(--primary);
    color: var(--primary-foreground);
}

.toast-error {
    background: oklch(from var(--destructive) l c h / 0.1);
    border-color: var(--destructive);
}

.toast-error .toast-icon {
    background: var(--destructive);
    color: var(--destructive-foreground);
}

.toast-info {
    background: oklch(from var(--accent) l c h / 0.1);
    border-color: var(--accent);
}

.toast-info .toast-icon {
    background: var(--accent);
    color: var(--accent-foreground);
}

.toast-warning {
    background: oklch(from var(--warning) l c h / 0.1);
    border-color: var(--warning);
}

.toast-warning .toast-icon {
    background: var(--warning);
    color: var(--warning-foreground);
}
"#
}
