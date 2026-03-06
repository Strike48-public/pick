(async function() {
    const BASE = '__LIVEVIEW_BASE__';
    const container = document.getElementById('shell-container');
    if (!container) return;

    // Detect if we're in a real browser (http/https) vs a Dioxus webview
    // (dioxus://index.html). In the browser/liveview case, derive URLs from
    // the page origin so they work through proxies (e.g. Strike48 Studio).
    var isRealBrowser = (location.protocol === 'http:' || location.protocol === 'https:');
    var httpBase = isRealBrowser ? location.origin : BASE;

    // Load the restty bundle via script tag if not already loaded
    // (In Strike48 mode, it's already inlined in <head>)
    if (!window.ResttyXterm) {
        await new Promise(function(resolve, reject) {
            var script = document.createElement('script');
            script.src = httpBase + '/assets/restty.js';
            script.onload = resolve;
            script.onerror = function(e) {
                console.error('[Shell] Failed to load restty.js', e);
                reject(e);
            };
            document.head.appendChild(script);
        });
    }

    // Detect Strike48 iframe context: font is embedded as ArrayBuffer global
    // because CSP blocks CDN font fetches and local-fonts permission is denied.
    var fontSources = undefined;
    if (window.__STRIKE48_FONT_REGULAR__) {
        console.log('[Shell] Using embedded Strike48 font buffer');
        fontSources = [
            { type: 'buffer', data: window.__STRIKE48_FONT_REGULAR__, label: 'JetBrains Mono Regular (embedded)' }
        ];
    }

    // Track whether we've ever connected (to avoid showing
    // "[Connection closed]" from the initial "disconnected" status)
    var hasConnected = false;

    var term = new ResttyXterm.Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontSources: fontSources,
        theme: {
            background: '#1e1e2e',
            foreground: '#cdd6f4',
        },
        scrollback: 10000,
        appOptions: {
            callbacks: {
                onPtyStatus: function(status) {
                    console.log('[Shell] PTY status:', status);
                    if (status === 'connected') {
                        hasConnected = true;
                        var loading = document.getElementById('shell-loading');
                        if (loading) loading.style.display = 'none';
                    } else if (status === 'disconnected' && hasConnected) {
                        term.write('\r\n\x1b[31m[Connection closed]\x1b[0m\r\n');
                    }
                },
            },
        },
    });

    term.open(container);

    // Let layout fully settle before connecting
    await new Promise(function(r) { setTimeout(r, 500); });

    try {
        if (term.restty) {
            term.restty.updateSize(true);
        }
    } catch (e) {
        console.warn('[Shell] updateSize failed:', e);
    }

    // Connect to PTY via restty's built-in WebSocket transport.
    // connectPty sends initial resize on connect, routes keyboard input
    // to the PTY (no local echo), and renders PTY output automatically.
    var shellMode = '__SHELL_MODE__';
    // In a real browser (liveview / Studio proxy), derive the WebSocket URL
    // from the page origin so it works through HTTPS proxies.  In a Dioxus
    // desktop/mobile webview, use the hardcoded LIVEVIEW_BASE.
    var wsUrl;
    if (isRealBrowser) {
        var wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        wsUrl = wsProto + '//' + location.host + '/ws/shell?cols=80&rows=24&mode=' + shellMode;
    } else {
        wsUrl = BASE.replace('http', 'ws') + '/ws/shell?cols=80&rows=24&mode=' + shellMode;
    }
    console.log('[Shell] Connecting via connectPty to:', wsUrl);

    try {
        if (term.restty && typeof term.restty.connectPty === 'function') {
            term.restty.connectPty(wsUrl);
        } else {
            console.error('[Shell] connectPty not available on restty instance');
            if (term.restty) {
                console.log('[Shell] Available methods:', Object.getOwnPropertyNames(
                    Object.getPrototypeOf(term.restty)
                ).filter(function(k) { return typeof term.restty[k] === 'function'; }));
            }
        }
    } catch (e) {
        console.error('[Shell] connectPty failed:', e);
    }

    // Handle container resize
    var resizeObserver = new ResizeObserver(function() {
        try {
            if (term.restty) {
                term.restty.updateSize();
            }
        } catch (e) {
            // Ignore resize errors (e.g. during teardown)
        }
    });
    resizeObserver.observe(container);

    container._shellCleanup = function() {
        resizeObserver.disconnect();
        try {
            if (term.restty && typeof term.restty.disconnectPty === 'function') {
                term.restty.disconnectPty();
            }
            term.dispose();
        } catch (e) {
            console.warn('[Shell] cleanup error:', e);
        }
    };
})();
