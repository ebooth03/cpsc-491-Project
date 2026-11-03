// Control 4 (Safe display of scan results) - "no HTML parser" tests.
//
// The progress panel and the message line must show server and user text with
// innerText only. jsdom does not implement innerText, so comparing text cannot
// prove that. Instead, these tests wrap the innerHTML setter before app.js
// runs and record every assignment. If any of these fields is ever switched
// to innerHTML, the matching test fails, even in jsdom.
//
// Some tests cover fixed strings (for example clearMessage). They are
// regression guards, not evidence of a currently exploitable path.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
const payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror="alert(1)">',
    '"><svg onload=alert(1)>',
    'javascript:alert(1)'
];
const settle = () => new Promise(resolve => setImmediate(resolve));

async function setup(t) {
    const dom = new JSDOM(html, {
        url: 'http://localhost/', runScripts: 'outside-only'
    });
    t.after(() => dom.window.close());
    const { window } = dom;
    const writes = [];
    // Install before evaluating app.js, including its initial history request.
    const descriptor = Object.getOwnPropertyDescriptor(
        window.Element.prototype, 'innerHTML'
    );
    assert.ok(descriptor && descriptor.set && descriptor.get);
    Object.defineProperty(window.Element.prototype, 'innerHTML', {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        get() { return descriptor.get.call(this); },
        set(value) {
            writes.push({ element: this, id: this.id, value: String(value) });
            return descriptor.set.call(this, value);
        }
    });
    window.fetch = async () => ({ ok: true, json: async () => [] });
    window.console.log = () => {};
    window.console.error = () => {};
    window.eval(app);
    await settle();
    return {
        window, writes,
        element: id => window.document.getElementById(id)
    };
}

function assertNoHtmlWrites(writes, ids) {
    const matching = writes.filter(write => ids.includes(write.id));
    assert.deepEqual(matching.map(({ id, value }) => ({ id, value })), [],
        `Unsafe innerHTML assignment to ${ids.join(', ')}`);
}

function assertNoInjectedStructure(root) {
    assert.equal(root.querySelectorAll('script, img, svg, iframe, object, embed').length, 0);
    for (const node of root.querySelectorAll('*')) {
        for (const attr of node.attributes) {
            assert.ok(!/^on/i.test(attr.name), `unexpected event attribute ${attr.name}`);
        }
    }
}

const progressIds = [
    'statusBadge', 'progressPercent', 'currentHost', 'currentPort',
    'currentService', 'elapsedTime', 'progressMessage',
    'scanId', 'progressTarget'
];

// Catches app.js ~442 progressPercent.innerText -> innerHTML,
// ~463 and ~472 elapsedTime.innerText -> innerHTML (both branches).
for (const payload of payloads) {
    test(`C4-04 progress numeric sinks: ${payload}`, async t => {
        const { window, writes, element } = await setup(t);
        window.updateProgressDisplay({
            status: 'running', progress_percent: payload,
            current_host: '192.0.2.10', current_port: 80,
            current_service: 'http', elapsed_time: payload, message: 'Scanning'
        });
        // Numeric coercion may produce NaN; the invariant is that these
        // display-only fields must never use an HTML parser, even for NaN/0.
        window.updateProgressDisplay({
            status: 'running', progress_percent: 30,
            elapsed_time: null, message: 'Scanning'
        });
        assertNoHtmlWrites(writes, progressIds);
        assertNoInjectedStructure(element('progressSection'));
        assert.equal(element('progressBar').style.width, '30%');
    });
}

// Catches app.js ~1089 scanIdText.innerText -> innerHTML and
// ~1093 progressTarget.innerText -> innerHTML, plus ~1101, ~1105,
// ~1113, ~1117, ~1121, ~1125, ~1129 on the reset path.
for (const payload of payloads) {
    test(`C4-04 showProgressSection scan ID and target: ${payload}`, async t => {
        const { window, writes, element } = await setup(t);
        window.showProgressSection(payload, payload);
        assert.equal(element('scanId').innerText, payload);
        assert.equal(element('progressTarget').innerText, payload);
        assertNoHtmlWrites(writes, progressIds);
        assertNoInjectedStructure(element('progressSection'));
    });
}

// Catches app.js ~1179 showError, ~1191 showSuccess,
// ~1203 showInfo: messageDiv.innerText -> innerHTML.
for (const [method, className] of [
    ['showError', 'message-error'],
    ['showSuccess', 'message-success'],
    ['showInfo', 'message-info']
]) {
    for (const payload of payloads) {
        test(`C4-04 ${method} message: ${payload}`, async t => {
            const { window, writes, element } = await setup(t);
            window[method](payload);
            assert.equal(element('message').innerText, payload);
            assert.equal(element('message').className, className);
            assertNoHtmlWrites(writes, ['message']);
            assertNoInjectedStructure(element('message'));
        });
    }
}

// Catches app.js ~407 progressMessage.innerText -> innerHTML in
// getScanStatus's catch branch (the message is fixed, not attacker input).
test('C4-04 status request failure never uses innerHTML', async t => {
    const { window, writes, element } = await setup(t);
    window.fetch = async () => { throw new Error('offline'); };
    assert.equal(await window.getScanStatus('scan-test'), 'error');
    assert.equal(element('progressMessage').innerText,
        'Unable to retrieve scan status.');
    assertNoHtmlWrites(writes, ['progressMessage']);
});

// Catches app.js ~1213 clearMessage innerText -> innerHTML.
// This is a fixed empty string, so it is a safe-rendering regression
// guard rather than evidence of a currently exploitable XSS path.
test('C4-04 clearMessage does not switch to innerHTML', async t => {
    const { window, writes, element } = await setup(t);
    window.showError(payloads[1]);
    window.clearMessage();
    assert.equal(element('message').innerText, '');
    assertNoHtmlWrites(writes, ['message']);
    assertNoInjectedStructure(element('message'));
});
