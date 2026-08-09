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

    // Lazily-built shared fullscreen overlay for expanding a diagram/chart into a
    // full-bleed, pinch-to-zoom viewer. Tapping a rendered mermaid diagram or
    // echarts chart shows it here filling the ENTIRE viewport (no padding —
    // padding shrank the "expanded" diagram below its inline size). Pinch (touch)
    // or wheel (desktop) zooms, one-finger drag pans, double-tap toggles zoom,
    // Esc / the ✕ button closes.
    function ensureVizModal() {
        var modal = document.getElementById('viz-fullscreen-modal');
        if (modal) return modal;
        modal = document.createElement('div');
        modal.id = 'viz-fullscreen-modal';
        modal.style.cssText = 'display:none;position:fixed;inset:0;z-index:99999;'
            + 'background:#0b0f0d;overflow:hidden;';
        // The pan/zoom surface fills the viewport. touch-action:none hands us the
        // raw touch stream so the browser's own pinch-zoom / scroll doesn't steal
        // the gesture — required for our pinch-zoom to work in WKWebView.
        var surface = document.createElement('div');
        surface.style.cssText = 'position:absolute;inset:0;overflow:hidden;'
            + 'touch-action:none;cursor:grab;';
        // Covers the surface; the media is sized to fit the viewport at scale 1.
        // User zoom/pan is a single transform on this element, anchored at 0,0 so
        // the pinch math below stays simple.
        var content = document.createElement('div');
        content.style.cssText = 'position:absolute;inset:0;transform-origin:0 0;'
            + 'will-change:transform;';
        surface.appendChild(content);
        var close = document.createElement('button');
        close.textContent = '✕';
        close.setAttribute('aria-label', 'Close');
        close.style.cssText = 'position:fixed;top:20px;right:24px;width:40px;height:40px;border-radius:50%;'
            + 'border:none;background:rgba(255,255,255,0.14);color:#e9eeeb;font-size:18px;cursor:pointer;z-index:1;';
        function hide() { modal.style.display = 'none'; content.innerHTML = ''; }
        close.addEventListener('click', hide);
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && modal.style.display !== 'none') hide();
        });
        modal.appendChild(surface);
        modal.appendChild(close);
        document.body.appendChild(modal);

        // --- pinch / pan / wheel zoom ---
        var scale = 1, tx = 0, ty = 0;
        var pointers = new Map();           // pointerId -> {x, y}
        var pinchStartDist = 0, pinchStartScale = 1, lastMid = null;
        var MIN = 1, MAX = 10;
        function apply() {
            content.style.transform = 'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';
        }
        function reset() { scale = 1; tx = 0; ty = 0; apply(); }
        // Zoom by factor `f` about surface-relative point (px,py), keeping that
        // point fixed on screen. With transform-origin 0,0: world=(p-t)/s, so to
        // keep p fixed after scaling to s', t' = p - (p - t) * (s'/s).
        function zoomAt(f, px, py) {
            var ns = Math.min(MAX, Math.max(MIN, scale * f));
            f = ns / scale;
            tx = px - (px - tx) * f;
            ty = py - (py - ty) * f;
            scale = ns;
            if (scale <= MIN + 0.001) { tx = 0; ty = 0; }  // snap back to fit
            apply();
        }
        function pts() { return Array.from(pointers.values()); }
        function midOf() { var p = pts(); return { x: (p[0].x + p[1].x) / 2, y: (p[0].y + p[1].y) / 2 }; }
        function distOf() { var p = pts(); return Math.hypot(p[0].x - p[1].x, p[0].y - p[1].y); }
        surface.addEventListener('pointerdown', function(e) {
            surface.setPointerCapture(e.pointerId);
            pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
            if (pointers.size === 2) { pinchStartDist = distOf(); pinchStartScale = scale; lastMid = midOf(); }
            surface.style.cursor = 'grabbing';
        });
        surface.addEventListener('pointermove', function(e) {
            if (!pointers.has(e.pointerId)) return;
            var prev = pointers.get(e.pointerId);
            pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
            if (pointers.size === 1) {
                tx += e.clientX - prev.x; ty += e.clientY - prev.y; apply();   // pan
            } else if (pointers.size === 2) {
                var d = distOf(), mid = midOf();
                if (pinchStartDist > 0) zoomAt((pinchStartScale * (d / pinchStartDist)) / scale, mid.x, mid.y);
                if (lastMid) { tx += mid.x - lastMid.x; ty += mid.y - lastMid.y; apply(); }  // two-finger pan
                lastMid = mid;
            }
        });
        function up(e) {
            if (pointers.has(e.pointerId)) pointers.delete(e.pointerId);
            if (pointers.size < 2) { pinchStartDist = 0; lastMid = null; }
            if (pointers.size === 0) surface.style.cursor = 'grab';
        }
        surface.addEventListener('pointerup', up);
        surface.addEventListener('pointercancel', up);
        surface.addEventListener('wheel', function(e) {
            e.preventDefault();
            zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX, e.clientY);
        }, { passive: false });
        // Double-tap / double-click: toggle between fit and 2.5x at the point.
        var lastTap = 0;
        surface.addEventListener('pointerup', function(e) {
            var now = Date.now();
            if (now - lastTap < 300 && pointers.size === 0) {
                if (scale > MIN + 0.001) reset(); else zoomAt(2.5, e.clientX, e.clientY);
            }
            lastTap = now;
        });

        // Show a media element (cloned mermaid <svg> or an echarts <img>), sized
        // to fill the viewport at scale 1. reset() clears any prior zoom/pan.
        modal.__show = function(node) {
            content.innerHTML = '';
            reset();
            if (!node) { modal.style.display = 'block'; return; }
            if (node.tagName && node.tagName.toLowerCase() === 'svg') {
                // Mermaid stamps an inline max-width (its intrinsic size); clear it
                // and let the SVG fill the viewport, letterboxed via its viewBox.
                node.style.maxWidth = 'none'; node.style.maxHeight = 'none';
                node.style.width = '100%'; node.style.height = '100%';
                node.removeAttribute('width'); node.removeAttribute('height');
                if (!node.getAttribute('preserveAspectRatio')) node.setAttribute('preserveAspectRatio', 'xMidYMid meet');
            } else {
                // Raster (echarts snapshot): fill + contain to letterbox.
                node.style.width = '100%'; node.style.height = '100%';
                node.style.objectFit = 'contain';
            }
            node.style.display = 'block';
            node.style.userSelect = 'none';
            node.style.pointerEvents = 'none';   // let the surface own all gestures
            content.appendChild(node);
            modal.style.display = 'block';
        };
        return modal;
    }

    // Make a rendered mermaid container tap-to-expand into the fullscreen viewer.
    function makeExpandable(div) {
        div.style.cursor = 'zoom-in';
        div.title = 'Tap to expand';
        div.addEventListener('click', function() {
            var svg = div.querySelector('svg');
            if (!svg) return;
            ensureVizModal().__show(svg.cloneNode(true));
        });
    }

    // Make a rendered echarts container tap-to-expand. ECharts draws to <canvas>,
    // so we snapshot it to a high-DPI image and show that in the same zoom viewer.
    function makeChartExpandable(div, chart) {
        div.style.cursor = 'zoom-in';
        div.title = 'Tap to expand';
        div.addEventListener('click', function() {
            var url;
            try { url = chart.getDataURL({ pixelRatio: 3, backgroundColor: '#1b211e' }); }
            catch (e) { var c = div.querySelector('canvas'); url = c && c.toDataURL(); }
            if (!url) return;
            var img = new Image();
            img.src = url;
            ensureVizModal().__show(img);
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
                        makeChartExpandable(div, chart);
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
