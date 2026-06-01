// Shared JS utility functions for Dioxus eval() calls.
// Loaded once via include_str! and injected at component mount.
(function() {
    if (window.__pentestUtilsInit) return;
    window.__pentestUtilsInit = true;

    /**
     * Scroll an element to the bottom.
     * @param {string} selector - CSS selector for the scrollable container.
     */
    window.scrollToBottom = function(selector) {
        var el = document.querySelector(selector);
        if (el) {
            el.scrollTop = el.scrollHeight;
        }
    };

    /**
     * Scroll to bottom only if the user has not scrolled up.
     * Checks the data-user-scrolled-up attribute on the element.
     * @param {string} selector - CSS selector for the scrollable container.
     */
    window.scrollToBottomIfNotScrolled = function(selector) {
        var el = document.querySelector(selector);
        if (el && el.dataset.userScrolledUp !== 'true') {
            el.scrollTop = el.scrollHeight;
        }
    };

    /**
     * Clear the value of a textarea (or input).
     * @param {string} selector - CSS selector for the textarea.
     */
    window.clearTextarea = function(selector) {
        var el = document.querySelector(selector);
        if (el) {
            el.value = '';
        }
    };

    /**
     * Programmatically submit a form.
     * @param {string} selector - CSS selector for the form element.
     */
    window.submitForm = function(selector) {
        var form = document.querySelector(selector);
        if (form) {
            form.requestSubmit();
        }
    };

    /**
     * Check if the user is near the bottom of a scrollable element.
     * @param {string} selector - CSS selector for the scrollable container.
     * @param {number} [threshold=40] - Pixel distance from bottom to consider "at bottom".
     * @returns {string} 'bottom' if near bottom, 'up' otherwise.
     */
    window.isNearBottom = function(selector, threshold) {
        if (typeof threshold === 'undefined') threshold = 40;
        var el = document.querySelector(selector);
        if (el) {
            return (el.scrollHeight - el.scrollTop - el.clientHeight) < threshold ? 'bottom' : 'up';
        }
        return 'bottom';
    };

    /**
     * Reset the scroll-up flag on an element (set data-user-scrolled-up to 'false').
     * @param {string} selector - CSS selector for the scrollable container.
     */
    window.resetScrollFlag = function(selector) {
        var el = document.querySelector(selector);
        if (el) {
            el.dataset.userScrolledUp = 'false';
        }
    };

    /**
     * Force scroll to bottom and reset the scroll-up flag.
     * @param {string} selector - CSS selector for the scrollable container.
     */
    window.forceScrollToBottom = function(selector) {
        var el = document.querySelector(selector);
        if (el) {
            el.dataset.userScrolledUp = 'false';
            el.scrollTop = el.scrollHeight;
        }
    };

    /**
     * Install scroll listeners on a chat container for auto-scroll behaviour.
     * Tracks wheel-up to mark the user as scrolled-up, and detects when they
     * scroll back to the bottom to clear the flag.
     * @param {string} selector - CSS selector for the scrollable container.
     * @param {number} [threshold=40] - Pixel distance from bottom to consider "at bottom".
     */
    window.installScrollListeners = function(selector, threshold) {
        if (typeof threshold === 'undefined') threshold = 40;
        function install() {
            var el = document.querySelector(selector);
            if (!el) { setTimeout(install, 200); return; }
            if (el.__scrollListenerInstalled) return;
            el.__scrollListenerInstalled = true;
            el.addEventListener('wheel', function(e) {
                if (e.deltaY < 0) {
                    el.dataset.userScrolledUp = 'true';
                }
            }, { passive: true });
            el.addEventListener('scroll', function() {
                var atBottom = (el.scrollHeight - el.scrollTop - el.clientHeight) < threshold;
                if (atBottom) {
                    el.dataset.userScrolledUp = 'false';
                }
            }, { passive: true });
        }
        install();
    };

    /**
     * Install document-level delegated listeners for the chat textarea:
     *  - `input` events auto-resize the textarea between 40px and 200px,
     *  - `keydown` Enter (no Shift) dispatches a send,
     *  - `click` on a `.chat-send-btn` dispatches a send.
     *
     * `sendCallback` is invoked with the textarea text on each send trigger.
     * It is wired to `dioxus.send` by Rust so submissions return over the
     * eval channel instead of through dioxus's broken `convert_form_data`
     * path (#130). The callback is overwritten on every call so a re-mounted
     * ChatInput points the listeners at the new eval's `dioxus.send`.
     *
     * Idempotent for the listener install; the callback rebind is intentional.
     */
    window.installChatSendBridge = function(sendCallback) {
        window.__chatSendDispatch = sendCallback;
        if (window.__chatSendBridgeInstalled) return;
        window.__chatSendBridgeInstalled = true;

        function fireSend() {
            var el = document.querySelector('.chat-textarea');
            if (!el || el.disabled) return;
            var text = el.value;
            if (!text || !text.trim()) return;
            if (typeof window.__chatSendDispatch === 'function') {
                window.__chatSendDispatch(text);
            }
        }

        // Auto-resize on every keystroke.
        document.addEventListener('input', function(e) {
            var t = e.target;
            if (t && t.classList && t.classList.contains('chat-textarea')) {
                t.style.height = 'auto';
                t.style.height = Math.min(Math.max(t.scrollHeight, 40), 200) + 'px';
            }
        });

        // Enter (no Shift) inside the chat textarea sends.
        document.addEventListener('keydown', function(e) {
            var t = e.target;
            if (t && t.classList && t.classList.contains('chat-textarea')
                && e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                fireSend();
            }
        });

        // Send button click sends. preventDefault stops the native form-submit
        // path (button is type="submit") so we don't trigger any dioxus
        // onsubmit listener — there shouldn't be one, but be defensive.
        document.addEventListener('click', function(e) {
            var t = e.target;
            if (t && t.classList && t.classList.contains('chat-send-btn')) {
                e.preventDefault();
                fireSend();
            }
        });
    };

    /**
     * Trigger chart post-processing (mermaid + echarts) on the next animation frame.
     * Calls window.__processChatCharts if it has been defined by chart_processor.js.
     */
    window.triggerChartPostProcess = function() {
        requestAnimationFrame(function() {
            setTimeout(function() {
                if (typeof window.__processChatCharts === 'function') {
                    window.__processChatCharts();
                }
            }, 50);
        });
    };
})();
