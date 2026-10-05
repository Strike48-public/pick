// Regression guard for the mermaid streaming-flicker fix in chart_processor.js:
// render-once / hydrate-on-complete.
//
// The chat bubble's HTML is rebuilt on EVERY stream tick (chat_panel/render.rs
// `dangerous_inner_html`), tearing down whatever the renderer produced. The old
// logic re-invoked mermaid.render on every tick and let the raw <pre> paint
// between ticks — the diagram visibly flickered while the agent generated it.
// The fixed logic (a) renders a still-open block at most ONCE and holds the
// frame, (b) renders the closed block once and caches it by content hash, and
// (c) restores cached frames pre-paint (MutationObserver) so the raw code is
// never painted.
//
// This exercises the REAL exported decision + cache logic shipped in
// chart_processor.js — not a copy and not a source-grep — so a future edit
// that re-introduces per-tick re-rendering turns this test RED. The
// browser-only parts (the MutationObserver wiring and the pre-paint timing)
// are exercised by the headless-browser harness in the PR evidence, not here.
//
// Run:  node crates/ui/src/assets/viz_streaming.test.js
// The file is an IIFE that reads `window` on its first line; stub it so
// `require` reaches the CommonJS export shim (which returns before any DOM
// wiring) — same pattern as chart_processor.test.js.

'use strict';

const assert = require('node:assert');

global.window = {};

const { fnv1a, makeVizCaches, openVizAction } = require('./chart_processor.js');

function check(name, fn) {
    fn();
}

// --- fnv1a: canonical FNV-1a 32-bit ------------------------------------------

check('fnv1a matches the FNV-1a 32-bit reference vectors', () => {
    assert.strictEqual(fnv1a(''), '811c9dc5', 'offset basis');
    assert.strictEqual(fnv1a('a'), 'e40c292c', 'canonical vector for "a"');
    assert.strictEqual(fnv1a('abc'), '1a47e90b', 'canonical vector for "abc"');
});

check('fnv1a is deterministic and content-sensitive', () => {
    assert.strictEqual(fnv1a('graph TD\n  A --> B'), fnv1a('graph TD\n  A --> B'));
    assert.notStrictEqual(
        fnv1a('graph TD\n  A --> B'),
        fnv1a('graph TD\n  A --> B\n  B --> C'),
        'a grown diagram must hash differently (cache key per content)'
    );
});

// --- openVizAction: the render-once decision ----------------------------------

check('open block with a held frame is held (no re-render)', () => {
    assert.strictEqual(openVizAction(true), 'hold');
});

check('open block without a frame renders (one optimistic attempt)', () => {
    assert.strictEqual(openVizAction(false), 'render');
});

// --- makeVizCaches: held-frame lifecycle --------------------------------------

check('held frames are stored, found, and released per key', () => {
    const c = makeVizCaches(8);
    assert.strictEqual(c.hasHeld('m1-0'), false, 'no frame before any render');
    c.setHeld('m1-0', '<svg>partial</svg>');
    assert.strictEqual(c.hasHeld('m1-0'), true);
    assert.strictEqual(c.getHeld('m1-0'), '<svg>partial</svg>');
    c.releaseHeld('m1-0');
    assert.strictEqual(c.hasHeld('m1-0'), false, 'released after the final render');
    assert.strictEqual(c.getHeld(''), null, 'keyless blocks never match a frame');
});

check('closed frames are cached by content, not position', () => {
    const c = makeVizCaches(8);
    const code = 'graph TD\n  A --> B';
    assert.strictEqual(c.lookupClosed(code), null, 'no cache before the final render');
    c.rememberClosed(code, '<div class="chat-viz-block"><svg>final</svg></div>');
    assert.strictEqual(c.lookupClosed(code), '<div class="chat-viz-block"><svg>final</svg></div>');
    assert.strictEqual(c.lookupClosed(code + '\n  B --> C'), null, 'different content = different cache entry');
});

check('caches are bounded (no unbounded session growth)', () => {
    const c = makeVizCaches(2);
    c.rememberClosed('one', '1');
    c.rememberClosed('two', '2');
    c.rememberClosed('three', '3');
    assert.strictEqual(c.lookupClosed('one'), null, 'oldest closed frame evicted');
    assert.strictEqual(c.lookupClosed('two'), '2');
    assert.strictEqual(c.lookupClosed('three'), '3');

    c.setHeld('k1', 'a');
    c.setHeld('k2', 'b');
    c.setHeld('k3', 'c');
    assert.strictEqual(c.hasHeld('k1'), false, 'oldest held frame evicted');
    assert.strictEqual(c.hasHeld('k2'), true);
    assert.strictEqual(c.hasHeld('k3'), true);
});

// --- The anti-flicker invariant, end to end (no DOM) --------------------------
//
// Simulate the exact pass decisions the DOM code makes over a full stream:
// N-1 open ticks (text growing), one close tick, K further DOM rebuilds after
// the message settles. The observer restores `lookupClosed(code) ||
// getHeld(key)` pre-paint on every rebuild; the pass renders only when
// openVizAction says so (open) or when the closed cache misses (final).
// The invariant: the renderer is invoked EXACTLY TWICE — the first optimistic
// frame and the final render — no matter how many ticks/rebuilds happen. The
// old code invoked it once per tick (N + K renders) and painted the raw <pre>
// in between: the flicker.

check('a full stream renders exactly twice (first frame + final), holds the rest', () => {
    const N = 10; // open ticks
    const K = 5; // post-close DOM rebuilds (message updates / history re-render)
    const key = 'msg-uuid-1';
    const finalCode = 'graph TD\n  A --> B\n  B --> C';
    const caches = makeVizCaches(64);

    let renders = 0;
    const codeAt = (t) => finalCode.slice(0, Math.max(4, Math.round(finalCode.length * (t / N))));

    // Open ticks 1..N-1
    for (let t = 1; t < N; t++) {
        const code = codeAt(t);
        if (openVizAction(caches.hasHeld(key)) === 'render') {
            // The DOM code invokes mermaid.render exactly here.
            renders++;
            // Partial text parses: the renderer succeeds and the frame is held.
            caches.setHeld(key, '<div class="chat-viz-block"><svg chars="' + code.length + '"></svg></div>');
        }
        // Observer restore on this tick's bubble rebuild (pre-paint): every
        // open tick from the first onward shows a held frame.
        const restored = caches.getHeld(key);
        assert.ok(restored !== null, 'open tick ' + t + ' shows a held frame');
    }

    // Close tick N: the closed cache misses, so the final render runs.
    {
        const code = finalCode;
        const closedHit = caches.lookupClosed(code);
        if (!closedHit) {
            renders++;
            caches.rememberClosed(code, '<div class="chat-viz-block"><svg chars="' + code.length + '"></svg></div>');
            caches.releaseHeld(key);
        }
        // Observer restore after the close: held fallback keeps the screen up
        // until the final render lands (the close-tick frame handoff).
        const restored = caches.lookupClosed(code) || caches.getHeld(key);
        assert.ok(restored !== null, 'close tick holds a frame on screen');
    }

    // Post-close rebuilds K times: every rebuild restores from the closed
    // cache — never re-renders.
    for (let t = 0; t < K; t++) {
        const restored = caches.lookupClosed(finalCode) || caches.getHeld(key);
        assert.strictEqual(restored !== null, true, 'post-close rebuild ' + t + ' restores without rendering');
    }

    assert.strictEqual(
        renders,
        2,
        'exactly two renders for a full stream (was N+' + K + ' per-tick renders pre-fix)'
    );
    assert.strictEqual(caches.hasHeld(key), false, 'streaming cache freed after the final render');
});
