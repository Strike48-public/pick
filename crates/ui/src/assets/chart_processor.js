(function() {
    if (window.__chatChartsInit) return;
    window.__chatChartsInit = true;

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

    // Render an error message as TEXT, never HTML. mermaid/jison errors and JSON
    // parse errors embed a snippet of the offending (untrusted) input, so building
    // this via innerHTML was a stored-XSS sink (#367 review, finding #2).
    function showVizError(container, message) {
        container.textContent = '';
        var err = document.createElement('div');
        err.style.cssText = 'color:#f38ba8;font-size:0.75rem;';
        err.textContent = message;
        container.appendChild(err);
    }

    // ECharts renders a `formatter` (e.g. tooltip.formatter) as raw HTML, so
    // untrusted chart JSON like {"tooltip":{"formatter":"<img src=x onerror=...>"}}
    // is XSS on hover. Drop every `formatter` regardless of type — a string, or an
    // array of strings (valid multi-series syntax) — since untrusted content has no
    // business supplying one; charts still render with the default, escaped tooltip
    // content. Also force any renderMode to the non-HTML 'richText' engine
    // (#367 review, finding #2). Note: the confirmed HTML sink is the tooltip
    // formatter; ECharts 5.6.0 has no `type:'html'` graphic element (verified
    // against the bundle: every "html" literal is the tooltip renderMode).
    function stripHtmlSinks(node) {
        if (Array.isArray(node)) {
            for (var i = 0; i < node.length; i++) stripHtmlSinks(node[i]);
        } else if (node && typeof node === 'object') {
            Object.keys(node).forEach(function(key) {
                if (key === 'formatter') {
                    delete node[key];
                } else if (key === 'renderMode') {
                    node[key] = 'richText';
                } else {
                    stripHtmlSinks(node[key]);
                }
            });
        }
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

    // Chart processor: finds unprocessed code blocks and renders them
    window.__processChatCharts = function() {
        var container = document.querySelector('.chat-messages');
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
                        // result.svg is produced by mermaid in strict mode, which
                        // sanitizes its output with DOMPurify. This innerHTML sink
                        // therefore relies on that upstream sanitization; a DOMPurify
                        // bypass in mermaid would make it a sink (#367 review).
                        div.innerHTML = result.svg;
                        var svg = div.querySelector('svg');
                        if (svg) { svg.style.display='block'; svg.style.width='100%'; svg.style.height='auto'; svg.style.minHeight='80px'; }
                    }).catch(function(err) {
                        showVizError(div, 'Mermaid error: ' + err.message);
                    });
                } catch(e) {
                    showVizError(div, 'Mermaid error: ' + e.message);
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
                    }, 10);
                } catch(e) {
                    div.style.height = 'auto';
                    div.style.padding = '8px';
                    showVizError(div, 'ECharts error: ' + e.message);
                    pre.parentNode.replaceChild(div, pre);
                }
            });
        }
    };
})();
