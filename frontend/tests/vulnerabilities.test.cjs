const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
const app = fs.readFileSync(path.join(root, "app.js"), "utf8");

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
    await new Promise(resolve => setImmediate(resolve));
    return {
        window,
        results: window.document.getElementById("results")
    };
}

// Controlled display fixture; not a real scan result.
function finding(overrides = {}) {
    return {
        finding_id: "fixture-finding-1",
        scan_id: "fixture-scan",
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

function scan(findings) {
    return {
        scan_id: "fixture-scan",
        target: "192.0.2.10",
        status: "completed",
        hosts: [],
        findings
    };
}

function cells(row) {
    return [...row.querySelectorAll("td")]
        .map(cell => cell.textContent.trim());
}

test("displays all finding fields even when no hosts are returned", async t => {
    const { window, results } = await setup(t);
    window.displayResults(scan([finding()]));

    assert.deepEqual(
        cells(results.querySelector(".findings-table tbody tr")),
        [
            "CVE-2021-41773", "CRITICAL", "9.8", "192.0.2.10",
            "80", "tcp", "http", "Apache 2.4.49",
            "Controlled fixture description."
        ]
    );
    assert.match(results.textContent, /No hosts were returned/);
});

test("keeps multiple findings and severity values in separate rows", async t => {
    const { window, results } = await setup(t);
    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    window.displayResults(scan(severities.map((severity, index) =>
        finding({
            finding_id: `fixture-${index}`,
            cve_id: `CVE-2099-${1000 + index}`,
            severity
        })
    )));

    const rows = [...results.querySelectorAll(".findings-table tbody tr")];
    assert.equal(rows.length, severities.length);
    rows.forEach((row, index) => {
        assert.equal(cells(row)[0], `CVE-2099-${1000 + index}`);
        assert.equal(cells(row)[1], severities[index]);
    });
});

test("missing optional version and CVSS use placeholders; zero is preserved", async t => {
    const { window, results } = await setup(t);
    window.displayResults(scan([
        finding({ detected_version: null, cvss_score: null }),
        finding({ detected_version: undefined, cvss_score: 0 })
    ]));

    const rows = results.querySelectorAll(".findings-table tbody tr");
    assert.equal(cells(rows[0])[2], "-");
    assert.equal(cells(rows[0])[7], "-");
    assert.equal(cells(rows[1])[2], "0");
    assert.equal(cells(rows[1])[7], "-");
});

test("empty or omitted findings show an accurate empty-state message", async t => {
    const { window, results } = await setup(t);

    for (const findings of [[], undefined]) {
        window.displayResults(scan(findings));
        assert.match(
            results.querySelector(".empty-findings").textContent,
            /No vulnerability findings were returned\./
        );
        assert.equal(results.querySelectorAll(".findings-table").length, 0);
        assert.doesNotMatch(results.textContent, /vulnerability-free/i);
    }
});

test("finding text is escaped rather than interpreted as HTML", async t => {
    const { window, results } = await setup(t);
    const payload = '<img src=x onerror="alert(1)">';
    window.displayResults(scan([finding({
        cve_id: payload,
        severity: payload,
        host: payload,
        protocol: payload,
        service: payload,
        detected_version: payload,
        description: payload
    })]));

    assert.equal(results.querySelectorAll("img").length, 0);
    assert.equal(results.querySelectorAll("[onerror]").length, 0);
    const values = cells(results.querySelector(".findings-table tbody tr"));
    for (const index of [0, 1, 3, 5, 6, 7, 8]) {
        assert.equal(values[index], payload);
    }
});

test("loading another scan replaces previous vulnerability findings", async t => {
    const { window, results } = await setup(t);

    window.fetch = async url => ({
        ok: true,
        json: async () => url.endsWith("/scan-a/results")
            ? { ...scan([finding()]), scan_id: "scan-a" }
            : { ...scan([]), scan_id: "scan-b" }
    });

    await window.getScanResults("scan-a");
    assert.match(results.textContent, /CVE-2021-41773/);

    await window.getScanResults("scan-b");
    assert.match(results.textContent, /scan-b/);
    assert.doesNotMatch(results.textContent, /CVE-2021-41773/);
    assert.equal(results.querySelectorAll(".findings-table").length, 0);
});
