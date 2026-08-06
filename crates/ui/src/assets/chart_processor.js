(function() {
    if (window.__chatChartsInit) return;
    window.__chatChartsInit = true;

    // Render an inline chart-error notice. Builds the node with textContent so
    // the browser escapes the (attacker-influenceable) error message natively —
    // never string-concatenate a `.message` into innerHTML (DOM XSS sink,
    // CodeQL js/xss-through-exception).
    function renderChartError(div, label, message) {
        div.textContent = '';
        var note = document.createElement('div');
        note.style.color = '#f38ba8';
        note.style.fontSize = '0.75rem';
        note.textContent = label + ': ' + (message == null ? '' : message);
        div.appendChild(note);
    }

    // Last-good rendered SVG per streaming viz block, keyed by the stable
    // data-viz-key that Rust stamps on an open (still-streaming) fence. While a
    // mermaid block streams in it is re-parsed every tick; the intermediate text
    // often isn't valid yet, so on a parse failure we show the last frame that
    // DID parse (from here) instead of flashing an error. Cleared when the block
    // finally renders successfully closed. Bounded so a long session can't grow
    // it without limit.
    var vizLastGood = (window.__vizLastGood = window.__vizLastGood || {});
    function rememberGood(key, svg) {
        if (!key) return;
        vizLastGood[key] = svg;
        var keys = Object.keys(vizLastGood);
        if (keys.length > 64) delete vizLastGood[keys[0]];
    }

    // Load Mermaid
    if (!window.mermaid) {
        var ms = document.createElement('script');
        ms.src = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js';
        ms.onload = function() {
            window.mermaid.initialize({ startOnLoad: false, theme: 'dark' });
            console.log('[PentestConnector] Mermaid loaded');
        };
        document.head.appendChild(ms);
    }

    // Load ECharts
    if (!window.echarts) {
        var es = document.createElement('script');
        es.src = 'https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js';
        es.onload = function() { console.log('[PentestConnector] ECharts loaded'); };
        document.head.appendChild(es);
    }

    // Lazily-built shared fullscreen overlay for expanding a diagram. Clicking a
    // rendered mermaid diagram clones its SVG into this overlay at full size;
    // clicking the backdrop / Esc / the close button dismisses it.
    function ensureVizModal() {
        var modal = document.getElementById('viz-fullscreen-modal');
        if (modal) return modal;
        modal = document.createElement('div');
        modal.id = 'viz-fullscreen-modal';
        modal.style.cssText = 'display:none;position:fixed;inset:0;z-index:99999;'
            + 'background:rgba(0,0,0,0.85);align-items:center;justify-content:center;padding:32px;box-sizing:border-box;';
        var inner = document.createElement('div');
        inner.className = 'viz-fullscreen-inner';
        // Fill the padded viewport (the modal supplies 32px padding) and center
        // the diagram, so a small diagram scales UP to the available space
        // rather than shrink-wrapping the container to its intrinsic size.
        inner.style.cssText = 'width:100%;height:100%;overflow:auto;background:#1b211e;'
            + 'border-radius:10px;padding:20px;box-sizing:border-box;'
            + 'display:flex;align-items:center;justify-content:center;';
        var close = document.createElement('button');
        close.textContent = '✕';
        close.setAttribute('aria-label', 'Close');
        close.style.cssText = 'position:fixed;top:20px;right:24px;width:40px;height:40px;border-radius:50%;'
            + 'border:none;background:rgba(255,255,255,0.12);color:#e9eeeb;font-size:18px;cursor:pointer;';
        function hide() { modal.style.display = 'none'; inner.innerHTML = ''; }
        modal.addEventListener('click', function(e) { if (e.target === modal) hide(); });
        close.addEventListener('click', hide);
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && modal.style.display !== 'none') hide();
        });
        modal.appendChild(inner);
        modal.appendChild(close);
        document.body.appendChild(modal);
        modal.__show = function(svgMarkup) {
            inner.innerHTML = svgMarkup;
            var s = inner.querySelector('svg');
            if (s) {
                // Mermaid stamps an inline `max-width:NNNpx` on the <svg> (its
                // intrinsic size), which caps `width:100%` at the small original
                // size. Clear it and let the SVG scale to the full container
                // while preserving aspect ratio via the viewBox.
                s.style.maxWidth = 'none';
                s.style.maxHeight = 'none';
                s.style.width = '100%';
                s.style.height = '100%';
                s.removeAttribute('width');
                s.removeAttribute('height');
                // With a viewBox (mermaid always sets one) this scales the SVG
                // to fill the container, letterboxing to preserve aspect ratio.
                if (!s.getAttribute('preserveAspectRatio')) {
                    s.setAttribute('preserveAspectRatio', 'xMidYMid meet');
                }
            }
            modal.style.display = 'flex';
        };
        return modal;
    }

    // Make a rendered mermaid container click-to-expand into the fullscreen modal.
    function makeExpandable(div) {
        div.style.cursor = 'zoom-in';
        div.title = 'Click to expand';
        div.addEventListener('click', function() {
            var svg = div.querySelector('svg');
            if (!svg) return;
            ensureVizModal().__show(svg.outerHTML);
        });
    }

    // Chart processor: finds unprocessed code blocks and renders them.
    // Optional `sel` overrides the default chat container so other surfaces
    // (e.g. the Easy Mode document viewer) can render mermaid/echarts too.
    window.__processChatCharts = function(sel) {
        var container = document.querySelector(sel || '.chat-messages');
        if (!container) return;

        // Mermaid
        if (window.mermaid) {
            // A block still streaming carries data-viz-open (Rust stamps it on
            // the trailing OPEN fence). We render those too — optimistically —
            // but must NOT mark them processed, so each streaming tick re-parses
            // the grown text. Closed blocks lack the marker and render once.
            var blocks = container.querySelectorAll('pre code.language-mermaid:not([data-processed])');
            blocks.forEach(function(block, idx) {
                var isOpen = block.getAttribute('data-viz-open') === 'true';
                var vizKey = block.getAttribute('data-viz-key') || '';
                var pre = block.closest('pre') || block;
                var code = block.textContent || block.innerText;

                // Only closed blocks are terminal — mark them so we don't
                // re-render. Open blocks stay unprocessed for the next tick.
                if (!isOpen) block.setAttribute('data-processed', 'true');

                var div = document.createElement('div');
                div.className = 'chat-viz-block';
                div.id = 'chat-mermaid-' + Date.now() + '-' + idx;
                div.style.cssText = 'background:rgba(0,0,0,0.3);border-radius:6px;padding:12px;margin:8px 0;overflow:auto;width:100%;box-sizing:border-box;';

                // Show the last good render immediately (if any) so an open block
                // that currently fails to parse doesn't flash — it holds the
                // previous frame until the new text parses or the fence closes.
                var prior = vizKey ? vizLastGood[vizKey] : null;
                if (prior) {
                    div.innerHTML = prior;
                    var pv = div.querySelector('svg');
                    if (pv) { pv.style.display='block'; pv.style.width='100%'; pv.style.height='auto'; pv.style.minHeight='80px'; }
                }

                function onFail(msg) {
                    if (isOpen) {
                        // Still streaming: keep the last-good frame (already in
                        // `div` if we had one). With no prior render, leave the
                        // raw code block untouched so nothing flashes — a later
                        // tick (or the closing fence) will render it. Don't mark
                        // processed; don't surface the error yet.
                        if (!prior) return; // leave <pre> in place
                        if (div.parentNode == null && pre.parentNode) pre.parentNode.replaceChild(div, pre);
                        return;
                    }
                    // Closed and still failing: this is a real error — show it.
                    renderChartError(div, 'Mermaid error', msg);
                    if (pre.parentNode) pre.parentNode.replaceChild(div, pre);
                }

                try {
                    window.mermaid.render(div.id + '-svg', code).then(function(result) {
                        div.innerHTML = result.svg;
                        var svg = div.querySelector('svg');
                        if (svg) { svg.style.display='block'; svg.style.width='100%'; svg.style.height='auto'; svg.style.minHeight='80px'; }
                        makeExpandable(div);
                        if (vizKey) rememberGood(vizKey, result.svg);
                        if (pre.parentNode) pre.parentNode.replaceChild(div, pre);
                    }).catch(function(err) {
                        onFail(err && err.message);
                    });
                } catch(e) {
                    onFail(e && e.message);
                }
            });
        }

        // ECharts
        if (window.echarts) {
            var eblocks = container.querySelectorAll('pre code.language-echarts:not([data-processed]), pre code.language-echart:not([data-processed])');
            eblocks.forEach(function(block, idx) {
                block.setAttribute('data-processed', 'true');
                var pre = block.closest('pre') || block;
                var code = block.textContent || block.innerText;
                var div = document.createElement('div');
                div.className = 'chat-viz-block chat-echarts-block';
                div.style.cssText = 'width:100%;min-height:180px;height:220px;background:rgba(0,0,0,0.3);border-radius:6px;margin:8px 0;box-sizing:border-box;';
                try {
                    var option = JSON.parse(code);
                    pre.parentNode.replaceChild(div, pre);
                    setTimeout(function() {
                        var chart = window.echarts.init(div, 'dark');
                        option.backgroundColor = option.backgroundColor || 'transparent';
                        if (!option.textStyle) option.textStyle = {};
                        option.textStyle.color = option.textStyle.color || '#cdd6f4';
                        chart.setOption(option);
                        var ro = new ResizeObserver(function() { chart.resize(); });
                        ro.observe(div);
                        var panel = document.querySelector('.chat-panel');
                        if (panel) { var po = new ResizeObserver(function() { chart.resize(); }); po.observe(panel); }
                    }, 10);
                } catch(e) {
                    div.style.height = 'auto';
                    div.style.padding = '8px';
                    renderChartError(div, 'ECharts error', e.message);
                    pre.parentNode.replaceChild(div, pre);
                }
            });
        }
    };
})();
