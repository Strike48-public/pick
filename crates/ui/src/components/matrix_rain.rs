//! Matrix rain animation overlay with "Follow the White Rabbit" text

use dioxus::prelude::*;
use std::time::Duration;

#[derive(Props, Clone, PartialEq)]
pub struct MatrixRainOverlayProps {
    /// Whether the overlay is visible
    visible: bool,
    /// Callback when user dismisses the overlay
    on_dismiss: EventHandler<()>,
}

/// Matrix rain overlay component with canvas-based animation
#[component]
pub fn MatrixRainOverlay(props: MatrixRainOverlayProps) -> Element {
    let mut show_text = use_signal(|| false);

    // Start text fade-in after 1 second
    use_effect(move || {
        if props.visible {
            spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                show_text.set(true);
            });
        } else {
            show_text.set(false);
        }
    });

    if !props.visible {
        return rsx! { div {} };
    }

    rsx! {
        div {
            class: "matrix-rain-overlay",
            onclick: move |_| props.on_dismiss.call(()),
            onkeydown: move |_| props.on_dismiss.call(()),
            tabindex: 0,

            // Canvas for Matrix rain
            canvas {
                id: "matrix-rain-canvas",
                class: "matrix-rain-canvas",
            }

            // "Follow the White Rabbit" text
            if show_text() {
                div {
                    class: "matrix-rain-text matrix-text-fade-in",
                    "Follow the White Rabbit"
                }
            }
        }

        // Initialize canvas animation
        script {
            dangerous_inner_html: r#"(function() {
    const canvas = document.getElementById('matrix-rain-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    // Set canvas size
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    // Characters to display (katakana + numbers)
    const chars = 'ｦｱｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const charArray = chars.split('');

    const fontSize = 16;
    const columns = Math.floor(canvas.width / fontSize);

    // Array to track y position of each column
    const drops = [];
    for (let i = 0; i < columns; i++) {
        drops[i] = Math.floor(Math.random() * canvas.height / fontSize);
    }

    function draw() {
        // Semi-transparent black background (creates trail effect)
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Green text
        ctx.fillStyle = '#0f0';
        ctx.font = fontSize + 'px monospace';

        for (let i = 0; i < drops.length; i++) {
            // Random character
            const char = charArray[Math.floor(Math.random() * charArray.length)];

            // Draw character
            ctx.fillText(char, i * fontSize, drops[i] * fontSize);

            // Reset drop to top randomly (creates varying lengths)
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }

            drops[i]++;
        }
    }

    // Animation interval
    const interval = setInterval(draw, 50);

    // Cleanup on overlay close
    const overlay = canvas.closest('.matrix-rain-overlay');
    if (overlay) {
        const observer = new MutationObserver((mutations) => {
            if (!document.contains(canvas)) {
                clearInterval(interval);
                observer.disconnect();
            }
        });
        observer.observe(overlay.parentElement, { childList: true, subtree: true });
    }

    // Handle window resize
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
})();"#
        }
    }
}

/// CSS for Matrix rain overlay
pub fn matrix_rain_css() -> &'static str {
    r#"
.matrix-rain-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 10000;
    background: rgba(0, 0, 0, 0.7);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    outline: none;
}

.matrix-rain-canvas {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
}

.matrix-rain-text {
    position: relative;
    z-index: 10001;
    font-size: 48px;
    font-family: 'Courier New', monospace;
    font-weight: bold;
    color: white;
    text-align: center;
    text-shadow:
        0 0 10px rgba(255, 255, 255, 0.8),
        0 0 20px rgba(255, 255, 255, 0.6),
        0 0 30px rgba(255, 255, 255, 0.4),
        2px 2px 0px rgba(0, 0, 0, 0.8);
    letter-spacing: 2px;
    pointer-events: none;
    image-rendering: pixelated;
    -webkit-font-smoothing: none;
    -moz-osx-font-smoothing: grayscale;
}

.matrix-text-fade-in {
    animation: matrix-text-fade 4s ease-in-out;
}

@keyframes matrix-text-fade {
    0% {
        opacity: 0;
        transform: scale(0.9);
    }
    25% {
        opacity: 1;
        transform: scale(1);
    }
    75% {
        opacity: 1;
        transform: scale(1);
    }
    100% {
        opacity: 0;
        transform: scale(0.9);
    }
}

/* Reduce motion for accessibility */
@media (prefers-reduced-motion: reduce) {
    .matrix-text-fade-in {
        animation: none;
        opacity: 1;
    }
}
"#
}
