// Regression guard for the chart_processor.js ECharts option sanitizer (#371).
//
// This exercises the REAL stripHtmlSinks shipped in chart_processor.js — not a
// copy and not a source-grep — so a future edit that breaks the recursion, the
// `delete`, or the renderMode override turns this test RED. That is the guard
// the #367/#371 review asked for: the XSS fix must fail loudly if reopened.
//
// Run:  node crates/ui/src/assets/chart_processor.test.js
// The file is an IIFE that reads `window` on its first line; stub it so `require`
// reaches the CommonJS export shim (which returns before any DOM wiring).

'use strict';

const assert = require('node:assert');

// Minimal stub: chart_processor.js checks `window.__chatChartsInit` before it
// hits the node export shim. No `document` is needed — the shim returns early.
global.window = {};

const { stripHtmlSinks } = require('./chart_processor.js');

assert.strictEqual(
    typeof stripHtmlSinks,
    'function',
    'chart_processor.js must export stripHtmlSinks for this guard to run'
);

let passed = 0;
function check(name, fn) {
    fn();
    passed++;
    console.log('  ok - ' + name);
}

// --- formatter is an XSS sink: dropped regardless of shape --------------------

check('string formatter is dropped', () => {
    const opt = { tooltip: { formatter: '<img src=x onerror=alert(1)>' } };
    stripHtmlSinks(opt);
    assert.ok(!('formatter' in opt.tooltip), 'string formatter must be deleted');
});

check('array formatter is dropped', () => {
    const opt = { tooltip: { formatter: ['<img src=x onerror=alert(1)>', 'ok'] } };
    stripHtmlSinks(opt);
    assert.ok(!('formatter' in opt.tooltip), 'array formatter must be deleted');
});

check('deeply nested formatter is dropped', () => {
    const opt = { series: [{ data: [{ tooltip: { formatter: '<script>x</script>' } }] }] };
    stripHtmlSinks(opt);
    assert.ok(
        !('formatter' in opt.series[0].data[0].tooltip),
        'formatter nested in an array-of-objects must be deleted'
    );
});

// --- extraCssText is a CSS-injection / beacon sink: dropped (#371) ------------

check('extraCssText is dropped', () => {
    const opt = { tooltip: { extraCssText: 'background-image:url(https://evil/beacon)' } };
    stripHtmlSinks(opt);
    assert.ok(!('extraCssText' in opt.tooltip), 'extraCssText must be deleted');
});

// --- renderMode is forced to the non-HTML engine ------------------------------

check("renderMode is forced to 'richText'", () => {
    const opt = { tooltip: { renderMode: 'html' } };
    stripHtmlSinks(opt);
    assert.strictEqual(opt.tooltip.renderMode, 'richText', "renderMode must be forced to 'richText'");
});

// --- safe fields survive: sanitizer must not gut legitimate charts ------------

check('safe fields (title, data, type) are preserved', () => {
    const opt = {
        title: { text: 'Open ports by host' },
        xAxis: { type: 'category', data: ['10.0.0.1', '10.0.0.2'] },
        series: [{ type: 'bar', data: [3, 7] }],
    };
    stripHtmlSinks(opt);
    assert.strictEqual(opt.title.text, 'Open ports by host');
    assert.deepStrictEqual(opt.xAxis.data, ['10.0.0.1', '10.0.0.2']);
    assert.strictEqual(opt.series[0].type, 'bar');
    assert.deepStrictEqual(opt.series[0].data, [3, 7]);
});

console.log('\nchart_processor sanitizer: ' + passed + ' checks passed');
