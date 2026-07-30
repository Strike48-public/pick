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
        inner.style.cssText = 'max-width:96vw;max-height:92vh;overflow:auto;background:#1b211e;'
            + 'border-radius:10px;padding:20px;box-sizing:border-box;';
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
            if (s) { s.style.width = '100%'; s.style.height = 'auto'; s.removeAttribute('height'); }
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
            var blocks = container.querySelectorAll('pre code.language-mermaid:not([data-processed])');
            blocks.forEach(function(block, idx) {
                block.setAttribute('data-processed', 'true');
                var pre = block.closest('pre') || block;
                var code = block.textContent || block.innerText;
                var div = document.createElement('div');
                div.className = 'chat-viz-block';
                div.id = 'chat-mermaid-' + Date.now() + '-' + idx;
                div.style.cssText = 'background:rgba(0,0,0,0.3);border-radius:6px;padding:12px;margin:8px 0;overflow:auto;width:100%;box-sizing:border-box;';
                try {
                    window.mermaid.render(div.id + '-svg', code).then(function(result) {
                        div.innerHTML = result.svg;
                        var svg = div.querySelector('svg');
                        if (svg) { svg.style.display='block'; svg.style.width='100%'; svg.style.height='auto'; svg.style.minHeight='80px'; }
                        makeExpandable(div);
                    }).catch(function(err) {
                        renderChartError(div, 'Mermaid error', err.message);
                    });
                } catch(e) {
                    renderChartError(div, 'Mermaid error', e.message);
                }
                pre.parentNode.replaceChild(div, pre);
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
