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
        // Covers the surface. Panning is a translate on this element; zoom resizes
        // the media element itself (below) rather than CSS-scaling this layer —
        // scaling a layer rasterizes the SVG once then blows up the bitmap
        // (pixelated); resizing the <svg> re-rasterizes the vector crisply.
        var content = document.createElement('div');
        content.style.cssText = 'position:absolute;inset:0;transform-origin:0 0;'
            + 'will-change:transform;';
        surface.appendChild(content);
        var close = document.createElement('button');
        close.textContent = '✕';
        close.setAttribute('aria-label', 'Close');
        // The class opts out of mobile.css's global `button { min-height:48px }`,
        // which otherwise stretches this 44x44 button into an oval. min-height
        // is also pinned inline as belt-and-suspenders.
        close.className = 'viz-fullscreen-close';
        close.style.cssText = 'position:fixed;top:20px;right:24px;width:44px;height:44px;min-height:44px;'
            + 'padding:0;border-radius:50%;line-height:1;display:flex;align-items:center;justify-content:center;'
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
        // scale drives the media element's rendered SIZE (crisp vector re-raster);
        // tx/ty pan via a translate on `content`. mediaEl is the current <svg>/<img>
        // and baseW/baseH its scale-1 (fit) pixel size, captured in __show.
        var scale = 1, tx = 0, ty = 0;
        var mediaEl = null, baseW = 0, baseH = 0;
        var pointers = new Map();           // pointerId -> {x, y}
        var pinchStartDist = 0, pinchStartScale = 1, lastMid = null;
        var MIN = 1, MAX = 10;
        function applyPan() {
            content.style.transform = 'translate(' + tx + 'px,' + ty + 'px)';
        }
        function applySize() {
            if (!mediaEl) return;
            // Resize the element so the SVG re-rasterizes at the new size (crisp).
            // Center it in the surface at fit (scale 1) via auto margins so the
            // pan math has a stable origin.
            mediaEl.style.width = (baseW * scale) + 'px';
            mediaEl.style.height = (baseH * scale) + 'px';
        }
        function reset() { scale = 1; tx = 0; ty = 0; applySize(); applyPan(); }
        // Zoom by factor `f` about surface point (px,py), keeping that point fixed.
        // The media sits centered at fit; world offset of (px,py) from the media's
        // top-left scales with `scale`, so we adjust tx/ty to hold it in place.
        function zoomAt(f, px, py) {
            var ns = Math.min(MAX, Math.max(MIN, scale * f));
            f = ns / scale;
            // origin of the media (top-left) currently on screen:
            var vw = surface.clientWidth, vh = surface.clientHeight;
            var ox = tx + (vw - baseW * scale) / 2;
            var oy = ty + (vh - baseH * scale) / 2;
            // keep (px,py) fixed: new origin' = p - (p - origin) * f
            var nox = px - (px - ox) * f;
            var noy = py - (py - oy) * f;
            scale = ns;
            // back out tx/ty from the new origin under the new centered layout
            tx = nox - (vw - baseW * scale) / 2;
            ty = noy - (vh - baseH * scale) / 2;
            if (scale <= MIN + 0.001) { tx = 0; ty = 0; }  // snap back to fit
            applySize(); applyPan();
        }
        function pts() { return Array.from(pointers.values()); }
        function midOf() { var p = pts(); return { x: (p[0].x + p[1].x) / 2, y: (p[0].y + p[1].y) / 2 }; }
        function distOf() { var p = pts(); return Math.hypot(p[0].x - p[1].x, p[0].y - p[1].y); }
        // Tap-tracking for double-tap: only a genuine single-finger tap that didn't
        // move counts. A pinch lifts two fingers ~ms apart; without this guard the
        // second lift reads as a double-tap and resets the zoom (the "snaps back
        // when I let go" bug).
        var lastTapTime = 0, downPt = null, moved = false, wasMultiTouch = false;
        surface.addEventListener('pointerdown', function(e) {
            surface.setPointerCapture(e.pointerId);
            pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
            if (pointers.size === 1) { downPt = { x: e.clientX, y: e.clientY }; moved = false; }
            if (pointers.size === 2) { pinchStartDist = distOf(); pinchStartScale = scale; lastMid = midOf(); wasMultiTouch = true; }
            surface.style.cursor = 'grabbing';
        });
        surface.addEventListener('pointermove', function(e) {
            if (!pointers.has(e.pointerId)) return;
            var prev = pointers.get(e.pointerId);
            pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
            if (pointers.size === 1) {
                if (downPt && Math.hypot(e.clientX - downPt.x, e.clientY - downPt.y) > 8) moved = true;
                tx += e.clientX - prev.x; ty += e.clientY - prev.y; applyPan();   // pan
            } else if (pointers.size === 2) {
                var d = distOf(), mid = midOf();
                if (pinchStartDist > 0) zoomAt((pinchStartScale * (d / pinchStartDist)) / scale, mid.x, mid.y);
                if (lastMid) { tx += mid.x - lastMid.x; ty += mid.y - lastMid.y; applyPan(); }  // two-finger pan
                lastMid = mid;
            }
        });
        function up(e) {
            var wasSingleCleanTap = (pointers.size === 1 && !moved && !wasMultiTouch);
            if (pointers.has(e.pointerId)) pointers.delete(e.pointerId);
            if (pointers.size < 2) { pinchStartDist = 0; lastMid = null; }
            if (pointers.size === 0) {
                surface.style.cursor = 'grab';
                if (wasSingleCleanTap) {
                    // genuine tap (not the tail of a pinch/pan): double-tap toggles zoom
                    var now = Date.now();
                    if (now - lastTapTime < 300) {
                        if (scale > MIN + 0.001) reset(); else zoomAt(2.5, e.clientX, e.clientY);
                        lastTapTime = 0;
                    } else {
                        lastTapTime = now;
                    }
                }
                wasMultiTouch = false;
            }
        }
        surface.addEventListener('pointerup', up);
        surface.addEventListener('pointercancel', up);
        surface.addEventListener('wheel', function(e) {
            e.preventDefault();
            zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX, e.clientY);
        }, { passive: false });

        // content centers the media; zoom resizes the media (crisp), pan
        // translates content. The zoomAt origin math assumes this centering.
        content.style.display = 'flex';
        content.style.alignItems = 'center';
        content.style.justifyContent = 'center';

        // Fit a source of aspect ratio w/h into the surface, preserving ratio.
        function fitSize(w, h) {
            var vw = surface.clientWidth, vh = surface.clientHeight, aspect = w / h;
            if (vw / vh > aspect) return { w: vh * aspect, h: vh };  // height-bound
            return { w: vw, h: vw / aspect };                        // width-bound
        }

        // Show a media element (cloned mermaid <svg> or an echarts <img>). The
        // media is sized to FIT the viewport at scale 1 and re-sized on zoom so
        // vectors re-rasterize crisply. reset() clears any prior zoom/pan.
        modal.__show = function(node) {
            content.innerHTML = '';
            mediaEl = node;
            node.style.display = 'block';
            node.style.maxWidth = 'none'; node.style.maxHeight = 'none';
            // content is a flex container (centers the media at fit). Without
            // flex-shrink:0 the media is a shrinkable flex item, so the browser
            // squashes it back to the container width the instant we grow it on
            // zoom — the "zoom does nothing" bug. Pin it so our explicit
            // width/height in applySize() are honored.
            node.style.flexShrink = '0';
            node.style.userSelect = 'none';
            node.style.pointerEvents = 'none';   // surface owns all gestures
            content.appendChild(node);
            modal.style.display = 'block';
            if (node.tagName && node.tagName.toLowerCase() === 'svg') {
                node.removeAttribute('width'); node.removeAttribute('height');
                if (!node.getAttribute('preserveAspectRatio')) node.setAttribute('preserveAspectRatio', 'xMidYMid meet');
                // Aspect from the viewBox (mermaid always sets one); fall back to 4:3.
                var vb = (node.getAttribute('viewBox') || '').split(/[\s,]+/).map(Number);
                var aw = (vb.length === 4 && vb[2] > 0) ? vb[2] : 4;
                var ah = (vb.length === 4 && vb[3] > 0) ? vb[3] : 3;
                var f = fitSize(aw, ah);
                baseW = f.w; baseH = f.h;
                reset();
            } else {
                // Raster (echarts snapshot): natural size known after load.
                var setFromNatural = function() {
                    var f = fitSize(node.naturalWidth || 4, node.naturalHeight || 3);
                    baseW = f.w; baseH = f.h; reset();
                };
                if (node.complete && node.naturalWidth) setFromNatural();
                else node.addEventListener('load', setFromNatural, { once: true });
            }
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
