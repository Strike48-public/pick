(async function() {
    console.log('[Shell] init script start');
    const BASE = '__LIVEVIEW_BASE__';
    const container = document.getElementById('shell-container');
    if (!container) {
        console.error('[Shell] init aborted: #shell-container not found in DOM');
        return;
    }
    console.log('[Shell] container found; size=' + container.clientWidth + 'x' + container.clientHeight);

    // Whether we are embedded in StrikeHub (IPC mode). This is the AUTHORITATIVE
    // signal from Rust: shell.rs substitutes __IS_STRIKEHUB__ with the boolean
    // literal `true`/`false` from `std::env::var("STRIKEHUB_SOCKET").is_ok()` —
    // the same check liveview_server.rs / easy_mode.rs use. It must NOT be
    // guessed from the webview origin: the Dioxus webview origin is identical
    // for StrikeHub-embedded AND standalone builds, so the old
    // hostname/protocol heuristic wrongly treated standalone Android (origin
    // https://dioxus.index.html) as StrikeHub and routed asset/WS loads through
    // a bridge that does not exist there (restty.js 404 -> blank shell).
    var isStrikeHub = __IS_STRIKEHUB__;

    // Detect the Dioxus native webview (desktop/mobile) vs a real browser tab.
    // The Android webview reports protocol `https:` with hostname
    // `dioxus.index.html`; the Linux webview uses the `dioxus:` protocol. Either
    // way it is NOT a real browser and must use the hardcoded LIVEVIEW_BASE
    // (127.0.0.1:3030) rather than `location.origin` (which is the bogus
    // dioxus.index.html host). This is a legitimate webview-vs-browser signal,
    // distinct from the StrikeHub-embedded question above.
    var isDioxusWebview = location.hostname === 'dioxus.index.html' || location.protocol === 'dioxus:';

    // Real browser (liveview / Strike48 Studio proxy): derive URLs from the page
    // origin so they work through HTTPS proxies. Excludes StrikeHub and the
    // native webview.
    var isRealBrowser = !isStrikeHub && !isDioxusWebview && (location.protocol === 'http:' || location.protocol === 'https:');

    var httpBase;
    if (isStrikeHub) {
        // Assets must route through the StrikeHub asset handler → bridge → IPC.
        // Build a base that includes the /connector/{id} prefix so requests
        // like /connector/{id}/assets/restty.js get intercepted properly.
        var pathParts = location.pathname.split('/');
        var connectorBase = pathParts.slice(0, 3).join('/'); // /connector/{id}
        httpBase = location.origin + connectorBase;
    } else if (isRealBrowser) {
        httpBase = location.origin;
    } else {
        httpBase = BASE;
    }
    // Normalize: `location.origin` can be empty/`null` under the Dioxus custom
    // protocol, and the StrikeHub branch can leave a trailing slash — either
    // way `httpBase + '/assets/...'` would produce a double slash
    // (`//assets/restty.js`), which the desktop asset resolver rejects. Trim any
    // trailing slash so exactly one joins the path.
    httpBase = (httpBase || '').replace(/\/+$/, '');

    // Load the restty bundle via script tag if not already loaded
    // (In Strike48 mode, it's already inlined in <head>)
    if (!window.ResttyXterm) {
        console.log('[Shell] loading restty.js from ' + httpBase + '/assets/restty.js');
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
    console.log('[Shell] restty ready (ResttyXterm=' + (!!window.ResttyXterm) + '); awaiting non-zero container size');

    // Detect Strike48 iframe context: font is embedded as ArrayBuffer global
    // because CSP blocks CDN font fetches and local-fonts permission is denied.
    var fontSources = undefined;
    if (window.__STRIKE48_FONT_REGULAR__) {
        console.log('[Shell] Using embedded Strike48 font buffer');
        fontSources = [
            { type: 'buffer', data: window.__STRIKE48_FONT_REGULAR__, label: 'JetBrains Mono Regular (embedded)' }
        ];
    }

    // Wait until the shell container has a real, non-zero layout size before
    // creating the terminal. The shell pane is persistent (always mounted,
    // CSS-toggled via `hidden`), so this init effect can run while the pane is
    // still `display:none` (0×0). restty builds its WebGL2 renderer against the
    // container's size at `term.open()` time — if that happens at 0×0 it locks
    // in a dead 1×1 grid ("[init webgl2] canvas=1x1 grid=1x1") that never
    // resizes or connects, leaving the pane stuck on "Starting shell...".
    // WebKit/WKWebView tolerate the later reflow; Chromium/WebView2 (Windows)
    // does not — so on Windows the shell hung. Gate on non-zero size so
    // `term.open()` always runs against the visible dimensions.
    await new Promise(function(resolve) {
        var isSized = function() {
            return container.clientWidth > 0 && container.clientHeight > 0;
        };
        if (isSized()) {
            resolve();
            return;
        }
        var done = false;
        var finish = function() {
            if (done) return;
            done = true;
            try { ro.disconnect(); } catch (e) { /* ignore */ }
            clearTimeout(timer);
            resolve();
        };
        var ro = new ResizeObserver(function() {
            if (isSized()) finish();
        });
        ro.observe(container);
        // Fallback: don't wait forever if the pane never reports a size
        // (e.g. observer never fires). Proceed anyway after a bounded wait so
        // the resize-driven `updateSize()` below can still recover it later.
        var timer = setTimeout(finish, 10000);
    });
    console.log('[Shell] size gate passed; container=' + container.clientWidth + 'x' + container.clientHeight + '; creating terminal');

    // Track whether we've ever connected (to avoid showing
    // "[Connection closed]" from the initial "disconnected" status)
    var hasConnected = false;
    var reconnectAttempts = 0;
    var maxReconnectAttempts = 5;
    var reconnectDelay = 2000; // Start with 2 seconds

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
                        reconnectAttempts = 0; // Reset on successful connection
                        var loading = document.getElementById('shell-loading');
                        if (loading) loading.style.display = 'none';
                    } else if (status === 'disconnected' && hasConnected) {
                        term.write('\r\n\x1b[33m[Connection closed]\x1b[0m\r\n');

                        // Attempt automatic reconnection
                        if (reconnectAttempts < maxReconnectAttempts) {
                            reconnectAttempts++;
                            var delay = reconnectDelay * reconnectAttempts; // Exponential backoff
                            term.write('\x1b[36m[Reconnecting in ' + (delay/1000) + ' seconds... (attempt ' + reconnectAttempts + '/' + maxReconnectAttempts + ')]\x1b[0m\r\n');

                            setTimeout(function() {
                                console.log('[Shell] Attempting reconnection...');
                                try {
                                    if (term.restty && typeof term.restty.connectPty === 'function') {
                                        term.restty.connectPty(wsUrl);
                                    }
                                } catch (e) {
                                    console.error('[Shell] Reconnection failed:', e);
                                }
                            }, delay);
                        } else {
                            term.write('\x1b[31m[Maximum reconnection attempts reached. Refresh the page to reconnect.]\x1b[0m\r\n');
                        }
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
    var shellToken = '__SHELL_TOKEN__';
    // In a real browser (liveview / Studio proxy), derive the WebSocket URL
    // from the page origin so it works through HTTPS proxies.  In a Dioxus
    // desktop/mobile webview, use the hardcoded LIVEVIEW_BASE.
    // In StrikeHub IPC mode, route through the WsRelay bridge.
    var wsUrl;
    if (isStrikeHub && window.__MATRIX_WS_URL__) {
        // __MATRIX_WS_URL__ is like 'ws://127.0.0.1:{port}/ws/graphql'
        // Extract the bridge base and route through /ws/{connector_id}/ws/shell
        var wsBridgeBase = window.__MATRIX_WS_URL__.replace(/\/ws\/graphql$/, '');
        var connectorId = location.pathname.split('/')[2]; // /connector/{id}/...
        wsUrl = wsBridgeBase + '/ws/' + connectorId + '/ws/shell?cols=80&rows=24&mode=' + shellMode + '&token=' + shellToken;
    } else if (isRealBrowser) {
        var wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        wsUrl = wsProto + '//' + location.host + '/ws/shell?cols=80&rows=24&mode=' + shellMode + '&token=' + shellToken;
    } else {
        wsUrl = BASE.replace('http', 'ws') + '/ws/shell?cols=80&rows=24&mode=' + shellMode + '&token=' + shellToken;
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
