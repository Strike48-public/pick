// Storage polyfill for sandboxed iframes (sessionStorage/localStorage blocked)
// Must use Object.defineProperty because even reading window.sessionStorage throws in sandbox
(function() {
  function createMemoryStorage() {
    var data = {};
    return {
      getItem: function(key) { return data.hasOwnProperty(key) ? data[key] : null; },
      setItem: function(key, value) { data[key] = String(value); },
      removeItem: function(key) { delete data[key]; },
      clear: function() { data = {}; },
      get length() { return Object.keys(data).length; },
      key: function(i) { var keys = Object.keys(data); return i < keys.length ? keys[i] : null; }
    };
  }
  var memSession = createMemoryStorage();
  var memLocal = createMemoryStorage();
  try {
    // Test if we can access sessionStorage at all
    var test = window.sessionStorage;
    test.setItem('__test__', '1');
    test.removeItem('__test__');
  } catch (e) {
    console.log('[Strike48] Storage blocked, installing polyfills via defineProperty');
    Object.defineProperty(window, 'sessionStorage', { value: memSession, writable: false, configurable: true });
    Object.defineProperty(window, 'localStorage', { value: memLocal, writable: false, configurable: true });
  }
})();

// Strike48 Phoenix Socket Shim for Dioxus LiveView
(function() {
  console.log('[Strike48WsShim] Installing WebSocket shim...');

  const PHX_VSN = '2.0.0';
  const SOCKET_STATES = {connecting: 0, open: 1, closing: 2, closed: 3};

  const NativeWebSocket = window.WebSocket;
  window.__STRIKE48_NATIVE_WEBSOCKET__ = NativeWebSocket;

  class Strike48WebSocket {
    // Static constants to match native WebSocket
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;

    constructor(url) {
      this.url = url;
      this.readyState = SOCKET_STATES.connecting;
      this.onopen = null;
      this.onclose = null;
      this.onerror = null;
      this.onmessage = null;
      this._ref = 0;
      this._joinRef = null;
      this.binaryType = 'blob';
      this._eventListeners = {open: [], close: [], error: [], message: []};

      const urlObj = new URL(url, window.location.origin);
      const isLiveViewWs = urlObj.pathname.includes('/ws') || urlObj.pathname.includes('/live');

      if (!isLiveViewWs) {
        console.log('[Strike48WsShim] Non-LiveView WebSocket, using native:', url);
        return new NativeWebSocket(url);
      }

      this._wsPath = urlObj.pathname;
      this._wsQuery = urlObj.search ? urlObj.search.substring(1) : ''; // Remove leading '?'
      console.log('[Strike48WsShim] LiveView WebSocket detected, path:', this._wsPath, 'query:', this._wsQuery);
      this._waitForStrike48AndConnect();
    }

    _waitForStrike48AndConnect() {
      const check = () => {
        if (window.__MATRIX_SESSION_TOKEN__ && window.__MATRIX_APP_ADDRESS__) {
          console.log('[Strike48WsShim] Strike48 ready, connecting...');
          this._connectToStrike48();
        } else {
          setTimeout(check, 50);
        }
      };
      check();
    }

    _connectToStrike48() {
      const token = window.__MATRIX_SESSION_TOKEN__;
      const appAddress = window.__MATRIX_APP_ADDRESS__;

      let host = window.location.host;
      const baseTag = document.querySelector('base');
      if (baseTag && baseTag.href) {
        try {
          const baseUrl = new URL(baseTag.href);
          host = baseUrl.host;
        } catch (e) {}
      }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const phoenixUrl = protocol + '//' + host +
        '/api/app/ws/websocket?__st=' + encodeURIComponent(token) +
        '&app=' + encodeURIComponent(appAddress) +
        '&vsn=' + PHX_VSN;

      console.log('[Strike48WsShim] Connecting to Phoenix socket:', phoenixUrl);

      this._socket = new NativeWebSocket(phoenixUrl);
      this._socket.binaryType = 'arraybuffer';

      this._socket.onopen = () => {
        console.log('[Strike48WsShim] Phoenix socket connected, joining channel');
        this._joinChannel();
      };

      this._socket.onclose = (event) => {
        this.readyState = SOCKET_STATES.closed;
        if (this._heartbeatInterval) clearInterval(this._heartbeatInterval);
        this._dispatchEvent('close', event);
      };

      this._socket.onerror = (event) => {
        this._dispatchEvent('error', event);
      };

      this._socket.onmessage = (event) => {
        this._handlePhoenixMessage(event.data);
      };
    }

    _joinChannel() {
      this._joinRef = String(++this._ref);
      const topic = 'app_ws:' + this._wsPath;
      // Pass query string in payload so Strike48 can forward it to connector
      const payload = this._wsQuery ? { query_string: this._wsQuery } : {};
      const joinMsg = JSON.stringify([this._joinRef, String(++this._ref), topic, 'phx_join', payload]);
      console.log('[Strike48WsShim] Joining channel:', topic, 'with query:', this._wsQuery);
      this._socket.send(joinMsg);
    }

    _handlePhoenixMessage(data) {
      let msg;
      try { msg = JSON.parse(data); } catch (e) { return; }

      const [joinRef, ref, topic, event, payload] = msg;

      if (event === 'phx_reply' && joinRef === this._joinRef) {
        if (payload.status === 'ok') {
          console.log('[Strike48WsShim] Channel joined successfully');
          this.readyState = SOCKET_STATES.open;
          this._startHeartbeat();
          this._dispatchEvent('open', {type: 'open'});
        } else {
          this._dispatchEvent('error', new Error('Channel join failed'));
        }
      } else if (event === 'frame') {
        const frameData = payload.data;
        let messageData;
        try {
          const binary = atob(frameData);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
          }
          messageData = bytes.buffer;
        } catch (e) {
          messageData = frameData;
        }
        this._dispatchEvent('message', {data: messageData, type: 'message'});
      } else if (event === 'close' || event === 'phx_close') {
        this.readyState = SOCKET_STATES.closed;
        this._dispatchEvent('close', {code: 1000, reason: 'closed'});
      } else if (event === 'phx_error') {
        this._dispatchEvent('error', new Error('Channel error'));
      }
    }

    _startHeartbeat() {
      this._heartbeatInterval = setInterval(() => {
        if (this.readyState !== SOCKET_STATES.open) return;
        const heartbeat = JSON.stringify([null, String(++this._ref), 'phoenix', 'heartbeat', {}]);
        this._socket.send(heartbeat);
      }, 30000);
    }

    send(data) {
      if (this.readyState !== SOCKET_STATES.open) return;

      const topic = 'app_ws:' + this._wsPath;
      let framePayload;

      if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
        const bytes = new Uint8Array(data);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        framePayload = {data: btoa(binary), type: 'binary'};
      } else {
        const str = String(data);
        const bytes = new TextEncoder().encode(str);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        framePayload = {data: btoa(binary), type: 'text'};
      }

      const msg = JSON.stringify([this._joinRef, String(++this._ref), topic, 'frame', framePayload]);
      this._socket.send(msg);
    }

    close(code, reason) {
      if (this.readyState === SOCKET_STATES.closed) return;
      this.readyState = SOCKET_STATES.closing;
      if (this._heartbeatInterval) clearInterval(this._heartbeatInterval);
      this._socket.close(code || 1000, reason || '');
    }

    addEventListener(type, listener) {
      this._eventListeners[type] = this._eventListeners[type] || [];
      this._eventListeners[type].push(listener);
    }

    removeEventListener(type, listener) {
      if (this._eventListeners[type]) {
        this._eventListeners[type] = this._eventListeners[type].filter(l => l !== listener);
      }
    }

    _dispatchEvent(type, event) {
      const handler = this['on' + type];
      if (handler) handler.call(this, event);
      if (this._eventListeners[type]) {
        this._eventListeners[type].forEach(l => l.call(this, event));
      }
    }
  }

  window.WebSocket = Strike48WebSocket;
  console.log('[Strike48WsShim] WebSocket shim installed');
})();
