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

    // ── Rendered-frame caches (survive the bubble's innerHTML rebuild) ──
    // The chat bubble's HTML is rebuilt on EVERY stream tick: render.rs
    // replaces the whole `dangerous_inner_html` subtree, tearing down whatever
    // the renderer produced. Without a frame that survives the rebuild, the
    // raw <pre> paints on every tick and the diagram flickers while the agent
    // generates it (the "mermaid is flickering" bug). These caches keep the
    // last rendered frame so it can be re-injected — synchronously, BEFORE
    // paint, by the MutationObserver at the bottom of this file — instead of
    // re-rendering from scratch.
    //
    //   held   — open (still-streaming) blocks, keyed by the stable
    //            data-viz-key Rust stamps on the open fence. The first parse
    //            success is held as the visible frame for the rest of the
    //            stream (render-once); released when the fence closes.
    //   closed — final renders, keyed by a hash of the diagram text. A
    //            closed fence's content never changes, so the cached frame
    //            is valid for the lifetime of the content; later bubble
    //            rebuilds restore it instead of re-rendering.
    // Both are bounded so a long session cannot grow them without limit.

    // FNV-1a 32-bit — small deterministic content hash for closed blocks.
    function fnv1a(str) {
        var h = 0x811c9dc5;
        for (var i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            h = Math.imul(h, 0x01000193) >>> 0;
        }
        return h.toString(16);
    }

    function makeVizCaches(limit) {
        var held = {}, heldOrder = [];
        var closed = {}, closedOrder = [];
        function trim(map, order) {
            while (order.length > limit) {
                delete map[order.shift()];
            }
        }
        return {
            // Open (still-streaming) frames, keyed by the stable data-viz-key.
            setHeld: function (key, svg) {
                if (!key) return;
                if (!(key in held)) heldOrder.push(key);
                held[key] = svg;
                trim(held, heldOrder);
            },
            getHeld: function (key) {
                return key ? held[key] : null;
            },
            hasHeld: function (key) {
                return !!(key && held[key]);
            },
            releaseHeld: function (key) {
                if (!key) return;
                delete held[key];
                heldOrder = heldOrder.filter(function (k) { return k !== key; });
            },
            // Closed (final) frames, keyed by content hash.
            rememberClosed: function (codeText, html) {
                var k = fnv1a(codeText);
                if (!(k in closed)) closedOrder.push(k);
                closed[k] = html;
                trim(closed, closedOrder);
            },
            lookupClosed: function (codeText) {
                return closed[fnv1a(codeText)] || null;
            }
        };
    }

    // Decision: what a processing pass does for a STILL-STREAMING (open) viz
    // block. 'hold' — a rendered frame already exists; keep showing it and do
    // NOT re-invoke the renderer (re-rendering the full diagram on every
    // stream tick was the flicker). 'render' — no frame yet; one optimistic
    // attempt at the partial content, retried on later ticks until it parses
    // or the fence closes.
    function openVizAction(hasHeldFrame) {
        return hasHeldFrame ? 'hold' : 'render';
    }

    var vizCaches = makeVizCaches(64);

    // CDN dependencies. Pinned to exact versions with Subresource Integrity so a
    // compromised or swapped CDN artifact fails closed instead of executing in the
    // app origin (#367 review, finding #5). Bump the version AND the integrity hash
    // together — recompute with:
    //   curl -sS <url> | openssl dgst -sha384 -binary | openssl base64 -A
    var MERMAID_SRC = 'https://cdn.jsdelivr.net/npm/mermaid@11.16.1/dist/mermaid.min.js';
    var MERMAID_SRI = 'sha384-aBQXj4hK6Jm05i7aQAsUV3bLdSUrHX1BGYfMB0166TtWt/RRaw+h0Eelme9OCOvy';
    var ECHARTS_SRC = 'https://cdn.jsdelivr.net/npm/echarts@5.6.0/dist/echarts.min.js';
    var ECHARTS_SRI = 'sha384-pPi0zxBAoDu6+JXW/C68UZLvBUUtU+7zonhif43rqj7pxsGyqyqzcian2Rj37Rss';

    // Load a CDN script with SRI. crossOrigin is required for the browser to
    // verify integrity on a cross-origin resource.
    function loadScript(src, integrity, onload) {
        var s = document.createElement('script');
        s.src = src;
        s.integrity = integrity;
        s.crossOrigin = 'anonymous';
        s.onload = onload;
        s.onerror = function() {
            console.error('[PentestConnector] failed to load (SRI or network): ' + src);
        };
        document.head.appendChild(s);
    }

    // ECharts renders a `formatter` (e.g. tooltip.formatter) as raw HTML, so
    // untrusted chart JSON like {"tooltip":{"formatter":"<img src=x onerror=...>"}}
    // is XSS on hover. Drop every `formatter` regardless of type — a string, or an
    // array of strings (valid multi-series syntax) — since untrusted content has no
    // business supplying one; charts still render with the default, escaped tooltip
    // content. Also drop `extraCssText`: ECharts injects it as raw inline CSS on the
    // tooltip DOM, so `background-image:url(...)` beacons on hover (#371 review).
    // And force any renderMode to the non-HTML 'richText' engine (#367 review,
    // finding #2). Note: the confirmed HTML sink is the tooltip formatter; ECharts
    // 5.6.0 has no `type:'html'` graphic element (verified against the bundle:
    // every "html" literal is the tooltip renderMode).
    function stripHtmlSinks(node) {
        if (Array.isArray(node)) {
            for (var i = 0; i < node.length; i++) stripHtmlSinks(node[i]);
        } else if (node && typeof node === 'object') {
            Object.keys(node).forEach(function(key) {
                if (key === 'formatter' || key === 'extraCssText') {
                    delete node[key];
                } else if (key === 'renderMode') {
                    node[key] = 'richText';
                } else {
                    stripHtmlSinks(node[key]);
                }
            });
        }
    }

    // Node/test bootstrap: expose the pure logic to the regression tests and
    // skip the browser wiring below. In the browser there is no CommonJS
    // `module` (Pick injects this file as a raw <script> via include_str!, no
    // bundler), so this is a no-op and rendering proceeds normally. Keeps the
    // XSS sanitizer and the streaming render-once/hold logic under test so a
    // future edit that reopens them fails CI (#371 review, flicker fix).
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            stripHtmlSinks: stripHtmlSinks,
            fnv1a: fnv1a,
            makeVizCaches: makeVizCaches,
            openVizAction: openVizAction
        };
        return;
    }

    // Load Mermaid
    if (!window.mermaid) {
        loadScript(MERMAID_SRC, MERMAID_SRI, function() {
            // securityLevel:'strict' is the mermaid default; set it explicitly so a
            // future default change cannot silently disable output sanitization.
            window.mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'strict' });
            console.log('[PentestConnector] Mermaid loaded');
        });
    }

    // Load ECharts
    if (!window.echarts) {
        loadScript(ECHARTS_SRC, ECHARTS_SRI, function() {
            console.log('[PentestConnector] ECharts loaded');
        });
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
            // A block still streaming carries data-viz-open + a stable
            // data-viz-key (Rust stamps both on the trailing OPEN fence).
            //
            // Render-once / hydrate-on-complete: an open block renders at most
            // ONCE (first parse success); while the fence stays open the held
            // frame is shown and the renderer is NOT re-invoked per stream
            // tick (the old full re-render per update made the diagram flicker
            // during generation). When the fence closes the block renders once
            // more (final) and the result is cached by content hash, so later
            // bubble rebuilds restore the frame instead of re-rendering.
            var blocks = container.querySelectorAll('pre code.language-mermaid:not([data-processed])');
            blocks.forEach(function(block, idx) {
                var isOpen = block.getAttribute('data-viz-open') === 'true';
                var vizKey = block.getAttribute('data-viz-key') || '';
                var pre = block.closest('pre') || block;
                var code = block.textContent || block.innerText;
                if (!pre.parentNode) return; // torn down by a concurrent pass/restore

                if (isOpen && openVizAction(vizCaches.hasHeld(vizKey)) === 'hold') {
                    // Held frame for this block exists. The pre-paint observer
                    // normally re-injects it already after each bubble rebuild;
                    // mount it here as the fallback (idempotent: a no-op when a
                    // frame for this content is already parked).
                    mountCachedFrame(pre, vizCaches.getHeld(vizKey), fnv1a(code));
                    return;
                }

                // Only closed blocks are terminal — mark them so we don't
                // re-render. Open blocks stay unprocessed until they close.
                if (!isOpen) {
                    block.setAttribute('data-processed', 'true');
                    // A cached frame may already be parked ahead of the pre by
                    // the pre-paint observer. When the FINAL frame is what's
                    // parked (closed-cache hit), there is nothing left to
                    // render — the block is done. A parked HELD frame (the
                    // fence just closed) is not final: the final render below
                    // still has to run and will swap it out.
                    var parked = pre.previousElementSibling;
                    if (parked && parked.classList && parked.classList.contains('chat-viz-block')
                        && vizCaches.lookupClosed(code)) {
                        return;
                    }
                }

                var div = document.createElement('div');
                div.className = 'chat-viz-block';
                div.id = 'chat-mermaid-' + Date.now() + '-' + idx;
                div.style.cssText = 'background:rgba(0,0,0,0.3);border-radius:6px;padding:12px;margin:8px 0;overflow:auto;width:100%;box-sizing:border-box;';

                function onFail(msg) {
                    if (!pre.parentNode) return; // stale: bubble rebuilt since
                    if (isOpen) {
                        // Still streaming: surface no error. A held frame (if
                        // any) stays visible — the pre-paint observer normally
                        // keeps it in place; mount it here as the fallback.
                        // With no frame yet, leave the raw code block in place
                        // so nothing flashes — a later tick (or the closing
                        // fence) renders it.
                        mountCachedFrame(pre, vizCaches.getHeld(vizKey), fnv1a(code));
                        return;
                    }
                    // Closed and still failing: this is a real error — show it.
                    // Release the held frame so the observer stops restoring
                    // the last good (now stale) diagram over the error.
                    vizCaches.releaseHeld(vizKey);
                    renderChartError(div, 'Mermaid error', msg);
                    if (pre.parentNode) {
                        clearParkedFrame(pre);
                        pre.parentNode.replaceChild(div, pre);
                    } else {
                        // The pre-paint observer may have swapped the pre for a
                        // restored held frame between our render start and this
                        // failure — swap that frame out instead so the error is
                        // still surfaced.
                        var restored = container.querySelector(
                            '.chat-viz-block[data-viz-hash="' + fnv1a(code) + '"]'
                        );
                        if (restored && restored.parentNode) {
                            restored.parentNode.replaceChild(div, restored);
                        }
                    }
                }

                try {
                    window.mermaid.render(div.id + '-svg', code).then(function(result) {
                        // result.svg is produced by mermaid in strict mode, which
                        // sanitizes its output with DOMPurify. This innerHTML sink
                        // therefore relies on that upstream sanitization; a DOMPurify
                        // bypass in mermaid would make it a sink (#367 review).
                        div.innerHTML = result.svg;
                        var svg = div.querySelector('svg');
                        if (svg) { svg.style.display='block'; svg.style.width='100%'; svg.style.height='auto'; svg.style.minHeight='80px'; }
                        makeExpandable(div);
                        div.setAttribute('data-viz-hash', fnv1a(code));
                        if (isOpen) {
                            // First good frame: hold the COMPLETE block (styled
                            // div + svg, not bare svg markup) so the pre-paint
                            // restore can re-mount it as the same kind of node.
                            vizCaches.setHeld(vizKey, div.outerHTML);
                        } else {
                            // Final render: cache it by content so later bubble
                            // rebuilds restore it, and free the streaming cache.
                            vizCaches.rememberClosed(code, div.outerHTML);
                            vizCaches.releaseHeld(vizKey);
                        }
                        // Mount: normally our <pre> is still in place (possibly
                        // hidden behind a frame the pre-paint observer parked
                        // for a just-closed block — that parked frame gets
                        // replaced by this fresh one). A genuinely torn-down
                        // bubble leaves no pre: swap out a parked occupant if
                        // one exists, otherwise this render is stale and
                        // dropped.
                        if (pre.parentNode) {
                            clearParkedFrame(pre);
                            pre.parentNode.replaceChild(div, pre);
                        } else {
                            var occupant = container.querySelector(
                                '.chat-viz-block[data-viz-hash="' + fnv1a(code) + '"]'
                            );
                            if (occupant && occupant.parentNode) {
                                occupant.parentNode.replaceChild(div, occupant);
                            }
                        }
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
                // While the fence is still streaming the JSON is incomplete:
                // parsing it on every tick flashed an error div over the raw
                // block (same flicker class as the mermaid path). Leave the raw
                // block in place until the fence closes, then render once.
                if (block.getAttribute('data-viz-open') === 'true') return;
                block.setAttribute('data-processed', 'true');
                var pre = block.closest('pre') || block;
                var code = block.textContent || block.innerText;
                var div = document.createElement('div');
                div.className = 'chat-viz-block chat-echarts-block';
                div.style.cssText = 'width:100%;min-height:180px;height:220px;background:rgba(0,0,0,0.3);border-radius:6px;margin:8px 0;box-sizing:border-box;';
                try {
                    var option = JSON.parse(code);
                    stripHtmlSinks(option);
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

    // ── Pre-paint frame restore ─────────────────────────────────────────
    // Dioxus rebuilds each bubble's innerHTML on every stream tick (render.rs
    // `dangerous_inner_html`), and the deferred __processChatCharts pass
    // (rAF + 50 ms in utils.js) runs AFTER the browser has painted the raw
    // <pre>. That raw-text paint on every tick IS the visible "mermaid is
    // flickering during generation" bug. A MutationObserver callback runs as
    // a microtask after the mutation and BEFORE the next paint, so restoring
    // the cached frame here means the raw code is never painted: the held
    // (open) or final (closed) diagram simply stays put across ticks.

    // Park a cached rendered frame in place of `pre` WITHOUT removing the
    // pre from the DOM: the deferred __processChatCharts pass still needs the
    // <code> element to find the block and (for a just-closed fence) to start
    // the final render. The raw code is hidden, so the user never sees it.
    // `hashTag` (fnv1a of the block's current text) is recorded on the frame
    // so render/error paths can find and swap out a parked frame. Returns the
    // mounted div (or the already-mounted one — idempotent), or null when the
    // cache was empty / the markup unusable.
    function mountCachedFrame(pre, cachedHtml, hashTag) {
        if (!pre || !pre.parentNode || !cachedHtml) return null;
        var existing = pre.previousElementSibling;
        // Idempotent: a frame already parked for this block + content (by the
        // observer's own earlier fire or the pass fallback) wins.
        if (existing && existing.getAttribute('data-viz-hash') === hashTag) {
            return existing;
        }
        var holder = document.createElement('div');
        holder.innerHTML = cachedHtml;
        var div = holder.firstChild;
        if (!div || div.nodeType !== 1) return null;
        // Restored markup is inert — re-attach the tap-to-expand handler.
        makeExpandable(div);
        div.setAttribute('data-viz-hash', hashTag);
        pre.style.display = 'none';
        pre.parentNode.insertBefore(div, pre);
        return div;
    }

    // Remove a frame previously parked ahead of `pre` (if any).
    function clearParkedFrame(pre) {
        var old = pre.previousElementSibling;
        if (old && old.classList && old.classList.contains('chat-viz-block')) old.remove();
    }

    function restoreCachedVizFrames(scope) {
        var blocks = scope.querySelectorAll('code.language-mermaid');
        for (var i = 0; i < blocks.length; i++) {
            var block = blocks[i];
            var pre = block.closest ? (block.closest('pre') || block) : block;
            if (!pre.parentNode) continue;
            var isOpen = block.getAttribute('data-viz-open') === 'true';
            var vizKey = block.getAttribute('data-viz-key') || '';
            var code = block.textContent || '';
            var cached;
            if (isOpen) {
                cached = vizCaches.getHeld(vizKey);
            } else {
                // Final renders restore from the closed cache. A block that
                // JUST closed (fence closed this tick) has no closed-cache
                // entry yet — fall back to the held streaming frame so the
                // last good diagram stays on screen until the final render
                // completes and swaps it (no raw-code flash at completion).
                // Only just-closed blocks carry a data-viz-key, so history
                // blocks (key-less) are unaffected.
                cached = vizCaches.lookupClosed(code) || vizCaches.getHeld(vizKey);
            }
            mountCachedFrame(pre, cached, fnv1a(code));
        }
    }

    function installRestoreObserver() {
        if (!document.body) return; // no-op; install is retried below
        var obs = new MutationObserver(function (muts) {
            for (var i = 0; i < muts.length; i++) {
                var target = muts[i].target;
                if (!target || target.nodeType !== 1 || !target.closest) continue;
                // Scope the scan to the bubble that was rewritten (cheap); the
                // fallback to the mutated node also covers other surfaces that
                // share this processor (e.g. the Easy Mode document viewer).
                restoreCachedVizFrames(target.closest('.chat-bubble-text') || target);
            }
        });
        obs.observe(document.body, { childList: true, subtree: true });
    }

    if (typeof MutationObserver !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', installRestoreObserver, { once: true });
        } else {
            installRestoreObserver();
        }
    }
})();
