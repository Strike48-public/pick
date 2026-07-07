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
