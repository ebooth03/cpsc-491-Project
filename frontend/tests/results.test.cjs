const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const frontendDir = path.resolve(__dirname, "..");
const html = fs.readFileSync(
    path.join(frontendDir, "index.html"), "utf8"
);
const app = fs.readFileSync(
    path.join(frontendDir, "app.js"), "utf8"
);

function setup(t) {
    const dom = new JSDOM(html, {
        url: "http://localhost/",
        runScripts: "outside-only"
    });

    t.after(() => dom.window.close());

    // Initial history loading uses a controlled response.
    dom.window.fetch = async () => ({
        ok: true,
        json: async () => [],
        text: async () => ""
    });

    dom.window.eval(app);

    return {
        window: dom.window,
        document: dom.window.document,
        results: dom.window.document.getElementById("results")
    };
}

function scan(overrides = {}) {
    return {
        scan_id: "scan-test-001",
        target: "127.0.0.1",
        status: "completed",
        hosts: [{
            host: "127.0.0.1",
            ports: [{
                port: 80,
                protocol: "tcp",
                state: "open",
                service: "http",
                version: "Apache 2.4.49"
            }]
        }],
        ...overrides
    };
}

function cells(row) {
    return [...row.querySelectorAll("td")]
        .map(cell => cell.textContent.trim());
}

test("displays scan summary and reveals results", t => {
    const { window, document, results } = setup(t);
    window.displayResults(scan());

    const summary = results.querySelector(".result-summary");
    assert.ok(summary);
    assert.match(summary.textContent, /scan-test-001/);
    assert.match(summary.textContent, /127\.0\.0\.1/);
    assert.match(summary.textContent, /completed/);
    assert.equal(
        document.getElementById("resultsSection")
            .classList.contains("hidden"),
        false
    );
});

test("displays port, protocol, state, service and version", t => {
    const { window, results } = setup(t);
    window.displayResults(scan());

    assert.equal(
        results.querySelector(".host-result h3")
            .textContent.trim(),
        "127.0.0.1"
    );
    assert.deepEqual(
        cells(results.querySelector("tbody tr")),
        ["80", "tcp", "open", "http", "Apache 2.4.49"]
    );
});

test("displays multiple hosts and their separate ports", t => {
    const { window, results } = setup(t);
    window.displayResults(scan({
        hosts: [
            {
                host: "192.0.2.10",
                ports: [
                    { port: 22, protocol: "tcp", state: "open",
                      service: "ssh", version: "OpenSSH" },
                    { port: 443, protocol: "tcp", state: "open",
                      service: "https", version: null }
                ]
            },
            {
                host: "192.0.2.20",
                ports: [
                    { port: 3306, protocol: "tcp", state: "open",
                      service: "mysql", version: "8.0" }
                ]
            }
        ]
    }));

    const hosts = [...results.querySelectorAll(".host-result")];
    assert.equal(hosts.length, 2);
    assert.equal(hosts[0].querySelector("h3").textContent.trim(),
        "192.0.2.10");
    assert.equal(hosts[1].querySelector("h3").textContent.trim(),
        "192.0.2.20");
    assert.deepEqual(
        [...hosts[0].querySelectorAll("tbody tr")]
            .map(row => cells(row)[0]),
        ["22", "443"]
    );
    assert.deepEqual(
        cells(hosts[1].querySelector("tbody tr")),
        ["3306", "tcp", "open", "mysql", "8.0"]
    );
});

test("handles empty and omitted host lists", t => {
    const { window, results } = setup(t);

    for (const hosts of [[], undefined]) {
        window.displayResults(scan({ hosts }));
        assert.match(
            results.textContent,
            /No hosts were returned by this scan\./
        );
        assert.equal(results.querySelectorAll("table").length, 0);
        assert.match(results.textContent, /scan-test-001/);
    }
});

test("handles empty and omitted port lists", t => {
    const { window, results } = setup(t);

    for (const ports of [[], undefined]) {
        window.displayResults(scan({
            hosts: [{ host: "127.0.0.1", ports }]
        }));
        assert.match(results.textContent, /No ports returned\./);
        assert.equal(results.querySelectorAll("table").length, 0);
        assert.equal(
            results.querySelector("h3").textContent.trim(),
            "127.0.0.1"
        );
    }
});

test("uses placeholders for missing service and version", t => {
    const { window, results } = setup(t);

    for (const missing of [null, undefined]) {
        window.displayResults(scan({
            hosts: [{
                host: "127.0.0.1",
                ports: [{
                    port: 8080,
                    protocol: "tcp",
                    state: "open",
                    service: missing,
                    version: missing
                }]
            }]
        }));
        assert.deepEqual(
            cells(results.querySelector("tbody tr")),
            ["8080", "tcp", "open", "-", "-"]
        );
    }
});

test("renders backend HTML text literally without creating elements", t => {
    const { window, results } = setup(t);
    const payload = '<img src=x onerror="alert(1)">';

    window.displayResults(scan({
        scan_id: payload,
        target: payload,
        status: payload,
        hosts: [{
            host: payload,
            ports: [{
                port: 80,
                protocol: payload,
                state: payload,
                service: payload,
                version: payload
            }]
        }]
    }));

    assert.equal(results.querySelectorAll("img").length, 0);
    assert.equal(results.querySelectorAll("[onerror]").length, 0);
    assert.equal(
        results.querySelector("h3").textContent.trim(),
        payload
    );
    assert.deepEqual(
        cells(results.querySelector("tbody tr")),
        ["80", payload, payload, payload, payload]
    );
    const summaryValues = [...results.querySelectorAll(
        ".result-summary p"
    )].map(p => p.textContent);
    assert.equal(summaryValues.length, 3);
    for (const value of summaryValues) {
        assert.ok(value.includes(payload));
    }
});

test("replaces previous results when displaying an empty scan", t => {
    const { window, results } = setup(t);
    window.displayResults(scan());
    assert.match(results.textContent, /Apache 2\.4\.49/);

    window.displayResults(scan({
        scan_id: "scan-test-002",
        hosts: []
    }));

    assert.match(results.textContent, /scan-test-002/);
    assert.match(results.textContent, /No hosts were returned/);
    assert.doesNotMatch(results.textContent, /scan-test-001/);
    assert.doesNotMatch(results.textContent, /Apache/);
    assert.equal(results.querySelectorAll(".host-result").length, 0);
});
