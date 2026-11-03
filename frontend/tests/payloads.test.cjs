// Control 4 (Safe display of scan results) - payload tests.
// Covers test plan IDs C4-01 to C4-05 from the Sprint 4 SOC 2 proposal.
//
// Every test puts a synthetic attack string into a field and checks that the
// dashboard shows it as literal text. The checks look at page structure (no
// injected elements or attributes), because jsdom does not run inline event
// handlers, so "alert never ran" would pass even if escaping failed.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
const app = fs.readFileSync(path.join(root, "app.js"), "utf8");

const PAYLOADS = [
    "<script>alert(1)</script>",
    '<img src=x onerror="alert(1)">',
    '"><svg onload=alert(1)>',
    "javascript:alert(1)"
];

const URL_ATTRIBUTES = new Set([
    "href", "src", "action", "formaction", "xlink:href", "data", "srcdoc"
]);

const settle = () => new Promise(resolve => setImmediate(resolve));

async function setup(t) {
    const dom = new JSDOM(html, {
        url: "http://localhost/",
        runScripts: "outside-only"
    });
    t.after(() => dom.window.close());

    const window = dom.window;
    window.fetch = async () => ({ ok: true, json: async () => [] });
    window.console.log = () => {};
    window.console.error = () => {};
    window.eval(app);
    await settle();

    const element = id => window.document.getElementById(id);
    return { window, element };
}

// Fails if the container holds any element or attribute that an attacker
// string could have created.
function assertNoInjection(container, label) {
    for (const tag of ["script", "img", "svg", "iframe", "a", "object", "embed"]) {
        assert.equal(
            container.querySelectorAll(tag).length, 0,
            `${label}: unexpected <${tag}> element`
        );
    }
    for (const el of container.querySelectorAll("*")) {
        for (const attr of el.attributes) {
            assert.ok(
                !attr.name.startsWith("on"),
                `${label}: unexpected attribute ${attr.name} on <${el.tagName.toLowerCase()}>`
            );
            // Only attributes that can load a URL matter here. A data-*
            // attribute that merely holds the text is harmless.
            if (URL_ATTRIBUTES.has(attr.name)) {
                assert.ok(
                    !/^\s*javascript:/i.test(attr.value),
                    `${label}: javascript: URL in attribute ${attr.name}`
                );
            }
        }
    }
}

const cells = row =>
    [...row.querySelectorAll("td")].map(cell => cell.textContent.trim());

function scanFixture(overrides = {}) {
    return {
        scan_id: "scan-fixture-1",
        target: "192.0.2.10",
        status: "completed",
        start_time: "2026-11-02T12:00:00Z",
        hosts: [{
            host: "192.0.2.10",
            ports: [{
                port: 80, protocol: "tcp", state: "open",
                service: "http", version: "Apache 2.4.49"
            }]
        }],
        findings: [],
        ...overrides
    };
}

function findingFixture(overrides = {}) {
    return {
        finding_id: "fixture-finding-1",
        scan_id: "scan-fixture-1",
        host: "192.0.2.10",
        port: 80,
        protocol: "tcp",
        service: "http",
        detected_version: "Apache 2.4.49",
        cve_id: "CVE-2021-41773",
        cvss_score: 9.8,
        severity: "CRITICAL",
        description: "Controlled fixture description.",
        ...overrides
    };
}

// ---------------------------------------------------------------------------
// C4-01  History table, including the scan ID in the View button attribute
// ---------------------------------------------------------------------------

for (const payload of PAYLOADS) {
    test(`C4-01 history shows payload as text: ${payload}`, async t => {
        const { window, element } = await setup(t);
        const history = element("scanHistory");

        window.displayScanHistory([{
            scan_id: payload,
            target: payload,
            status: payload,
            start_time: "2026-11-02T12:00:00Z",
            hosts: []
        }]);

        assertNoInjection(history, "history");
        const [id, target, status] = cells(history.querySelector("tbody tr"));
        assert.equal(id, payload);
        assert.equal(target, payload);
        assert.equal(status, payload);
    });

    test(`C4-01 View button keeps scan ID in its attribute only: ${payload}`, async t => {
        const { window, element } = await setup(t);
        const history = element("scanHistory");

        window.displayScanHistory([{
            scan_id: payload,
            target: "192.0.2.10",
            status: "completed",
            start_time: "2026-11-02T12:00:00Z",
            hosts: []
        }]);

        const buttons = history.querySelectorAll("button");
        assert.equal(buttons.length, 1);
        const names = [...buttons[0].attributes].map(a => a.name).sort();
        assert.deepEqual(names, ["class", "data-scan-id", "type"]);
        assert.equal(buttons[0].dataset.scanId, payload);
    });
}

test("C4-01 invalid start_time does not break the history table", async t => {
    const { window, element } = await setup(t);
    const history = element("scanHistory");

    window.displayScanHistory([{
        scan_id: "scan-a",
        target: "192.0.2.10",
        status: "completed",
        start_time: PAYLOADS[0],
        hosts: []
    }]);

    assertNoInjection(history, "history start_time");
    assert.equal(history.querySelectorAll("tbody tr").length, 1);
});

// ---------------------------------------------------------------------------
// C4-02  Results summary and host/port table, including the port number
// ---------------------------------------------------------------------------

for (const payload of PAYLOADS) {
    test(`C4-02 summary, host and port text fields: ${payload}`, async t => {
        const { window, element } = await setup(t);
        const results = element("results");

        window.displayResults(scanFixture({
            scan_id: payload,
            target: payload,
            status: payload,
            hosts: [{
                host: payload,
                ports: [{
                    port: 80, protocol: payload, state: payload,
                    service: payload, version: payload
                }]
            }]
        }));

        assertNoInjection(results, "results text fields");
        assert.equal(
            results.querySelector(".host-result h3").textContent.trim(),
            payload
        );
        assert.deepEqual(
            cells(results.querySelector("tbody tr")),
            ["80", payload, payload, payload, payload]
        );
        for (const p of results.querySelectorAll(".result-summary p")) {
            assert.ok(p.textContent.includes(payload));
        }
    });

    test(`C4-02 port number column shows payload as text: ${payload}`, async t => {
        const { window, element } = await setup(t);
        const results = element("results");

        window.displayResults(scanFixture({
            hosts: [{
                host: "192.0.2.10",
                ports: [{
                    port: payload, protocol: "tcp", state: "open",
                    service: "http", version: null
                }]
            }]
        }));

        assertNoInjection(results, "port number column");
        assert.equal(cells(results.querySelector("tbody tr"))[0], payload);
    });
}

// ---------------------------------------------------------------------------
// C4-03  Findings table, all nine columns including CVSS score and port
// ---------------------------------------------------------------------------

for (const payload of PAYLOADS) {
    test(`C4-03 findings table shows payload in every column: ${payload}`, async t => {
        const { window, element } = await setup(t);
        const results = element("results");

        window.displayResults(scanFixture({
            findings: [findingFixture({
                cve_id: payload,
                severity: payload,
                cvss_score: payload,
                host: payload,
                port: payload,
                protocol: payload,
                service: payload,
                detected_version: payload,
                description: payload
            })]
        }));

        assertNoInjection(results, "findings table");
        const row = results.querySelector(".findings-table tbody tr");
        const values = cells(row);
        assert.equal(values.length, 9);
        for (const value of values) {
            assert.equal(value, payload);
        }
    });
}

// ---------------------------------------------------------------------------
// C4-04  Progress/status panel
// ---------------------------------------------------------------------------
// jsdom does not implement innerText, so assigning it only sets a plain
// property and these checks cannot prove browser behavior. They confirm the
// code does not build elements from these fields. The browser check (C4-06)
// covers real innerText behavior.

for (const payload of PAYLOADS) {
    test(`C4-04 progress panel creates no elements from: ${payload}`, async t => {
        const { window, element } = await setup(t);
        const panel = element("progressSection");

        window.updateProgressDisplay({
            status: payload,
            progress_percent: 50,
            current_host: payload,
            current_port: payload,
            current_service: payload,
            elapsed_time: 1.5,
            message: payload
        });

        assertNoInjection(panel, "progress panel");
        for (const id of [
            "statusBadge", "currentHost", "currentPort",
            "currentService", "progressMessage"
        ]) {
            assert.equal(
                element(id).children.length, 0,
                `${id} should have no child elements`
            );
        }
    });
}

// ---------------------------------------------------------------------------
// C4-05  Normal, empty and missing values; fields the dashboard does not show
// ---------------------------------------------------------------------------

test("C4-05 normal values stay readable", async t => {
    const { window, element } = await setup(t);
    const results = element("results");

    window.displayResults(scanFixture({ findings: [findingFixture()] }));

    assert.deepEqual(
        cells(results.querySelector(".host-result tbody tr")),
        ["80", "tcp", "open", "http", "Apache 2.4.49"]
    );
    assert.deepEqual(
        cells(results.querySelector(".findings-table tbody tr")),
        [
            "CVE-2021-41773", "CRITICAL", "9.8", "192.0.2.10",
            "80", "tcp", "http", "Apache 2.4.49",
            "Controlled fixture description."
        ]
    );
});

test("C4-05 empty-string and missing finding fields do not throw", async t => {
    const { window, element } = await setup(t);
    const results = element("results");

    assert.doesNotThrow(() => window.displayResults(scanFixture({
        findings: [
            findingFixture({ description: "", detected_version: "" }),
            { cve_id: "CVE-2099-0001" }
        ]
    })));

    const rows = results.querySelectorAll(".findings-table tbody tr");
    assert.equal(rows.length, 2);
    assert.equal(cells(rows[1])[0], "CVE-2099-0001");
    assert.equal(cells(rows[1])[1], "Unknown");
});

test("C4-05 missing top-level fields do not throw", async t => {
    const { window } = await setup(t);

    assert.doesNotThrow(() => window.displayResults({
        scan_id: "scan-min", target: "192.0.2.10", status: "completed"
    }));
    assert.doesNotThrow(() => window.displayScanHistory(undefined));
});

test("C4-05 contract fields the dashboard does not show are not rendered", async t => {
    const { window, element } = await setup(t);
    const results = element("results");
    const marker = "UNDISPLAYED-FIELD-MARKER";

    window.displayResults(scanFixture({
        errors: [PAYLOADS[1], marker],
        hosts: [{
            host: "192.0.2.10",
            ports: [{
                port: 80, protocol: "tcp", state: "open",
                service: "http", version: null,
                banner: PAYLOADS[0] + marker
            }]
        }],
        findings: [findingFixture({
            remediation: PAYLOADS[2] + marker,
            reference_url: PAYLOADS[3] + marker
        })]
    }));

    assert.ok(
        !results.innerHTML.includes(marker),
        "banner, remediation, reference_url and errors should not appear in the page"
    );
    assertNoInjection(results, "undisplayed fields");
});

test("C4-05 text with HTML entities is shown exactly as received", async t => {
    const { window, element } = await setup(t);
    const results = element("results");
    // If "&" were not escaped, the browser would decode these entities and
    // show "<b> & '" instead of the literal text the scanner reported.
    const literal = "&lt;b&gt; &amp; &#39;";

    window.displayResults(scanFixture({
        hosts: [{
            host: "192.0.2.10",
            ports: [{
                port: 80, protocol: "tcp", state: "open",
                service: literal, version: literal
            }]
        }]
    }));

    assert.deepEqual(
        cells(results.querySelector("tbody tr")),
        ["80", "tcp", "open", literal, literal]
    );
});

test("C4-05 progress panel shows placeholders for null and missing values", async t => {
    const { window, element } = await setup(t);

    for (const value of [null, undefined]) {
        window.updateProgressDisplay({
            status: "running", progress_percent: 0,
            current_host: value, current_port: value,
            current_service: value, message: value
        });
        for (const id of ["currentHost", "currentPort", "currentService"]) {
            assert.equal(String(element(id).innerText), "-");
        }
        assert.equal(element("progressMessage").innerText, "Scan is running.");
    }
});

// ---------------------------------------------------------------------------
// CSP  Content-Security-Policy meta tag (KAN-112)
// ---------------------------------------------------------------------------
// jsdom does not enforce CSP. This test only guards against the tag being
// removed or loosened. Enforcement was checked in a real browser.

test("CSP meta tag is exactly the approved deny-by-default policy", t => {
    const dom = new JSDOM(html);
    t.after(() => dom.window.close());

    const meta = dom.window.document.querySelector(
        'meta[http-equiv="Content-Security-Policy"]'
    );
    assert.ok(meta, "CSP <meta> tag is missing from index.html");

    const directives = meta.getAttribute("content")
        .split(";")
        .map(directive => directive.trim())
        .filter(Boolean)
        .map(directive => {
            const [name, ...sources] = directive.split(/\s+/);
            return [name.toLowerCase(), sources];
        });

    // Browsers use the first copy of a repeated directive and ignore the
    // rest, so a repeat could make this test and the browser disagree.
    const names = directives.map(([name]) => name);
    assert.deepEqual(
        names.filter((name, index) => names.indexOf(name) !== index),
        [],
        "CSP repeats a directive"
    );

    // connect-src must match the API address the app really calls.
    const apiBase = app.match(/const API_BASE_URL = "([^"]+)"/)[1];

    // The comparison is deliberately exact. Any added, removed or loosened
    // directive (script-src-elem, form-action, img-src ...) fails here, so
    // changing the policy means changing this test on purpose.
    assert.deepEqual(Object.fromEntries(directives), {
        "default-src": ["'none'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "connect-src": [apiBase],
        "img-src": ["'none'"],
        "font-src": ["'none'"],
        "object-src": ["'none'"],
        "base-uri": ["'none'"],
        "form-action": ["'none'"]
    });
});
