const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
const app = fs.readFileSync(path.join(root, "app.js"), "utf8");

const settle = () => new Promise(resolve => setImmediate(resolve));

async function setup(t) {
    const dom = new JSDOM(html, {
        url: "http://localhost/",
        runScripts: "outside-only"
    });
    t.after(() => dom.window.close());

    const window = dom.window;
    window.fetch = async () => ({
        ok: true,
        json: async () => []
    });
    window.console.log = () => {};
    window.console.error = () => {};
    window.eval(app);
    await settle();

    return {
        window,
        history: window.document.getElementById("scanHistory"),
        results: window.document.getElementById("results"),
        message: window.document.getElementById("message")
    };
}

function scan(id, target = "192.0.2.10") {
    return {
        scan_id: id,
        target,
        status: "completed",
        start_time: "2026-10-12T12:00:00Z",
        hosts: []
    };
}

test("history displays scan details and matching View buttons", async t => {
    const { window, history } = await setup(t);
    const scans = [scan("scan-a"), scan("scan-b", "192.0.2.20")];

    window.displayScanHistory(scans);

    const rows = [...history.querySelectorAll("tbody tr")];
    assert.equal(rows.length, 2);

    scans.forEach((item, index) => {
        const cells = [...rows[index].querySelectorAll("td")];
        assert.equal(cells[0].textContent.trim(), item.scan_id);
        assert.equal(cells[1].textContent.trim(), item.target);
        assert.equal(cells[2].textContent.trim(), item.status);
        assert.equal(
            cells[3].textContent.trim(),
            new window.Date(item.start_time).toLocaleString()
        );
        assert.equal(
            rows[index].querySelector("button").dataset.scanId,
            item.scan_id
        );
    });
});

test("empty or missing history replaces previously displayed rows", async t => {
    const { window, history } = await setup(t);

    for (const value of [[], null, undefined]) {
        window.displayScanHistory([scan("scan-old")]);
        window.displayScanHistory(value);

        assert.match(history.textContent, /No scans yet\./);
        assert.equal(history.querySelectorAll("tbody tr").length, 0);
        assert.doesNotMatch(history.textContent, /scan-old/);
    }
});

test("loads history from the scans endpoint", async t => {
    const { window, history } = await setup(t);
    const requests = [];

    window.fetch = async url => {
        requests.push(url);
        return {
            ok: true,
            json: async () => [scan("scan-loaded")]
        };
    };

    await window.loadScanHistory();

    assert.deepEqual(requests, ["http://127.0.0.1:8000/scans"]);
    assert.match(history.textContent, /scan-loaded/);
});

test("HTTP and network failures replace history with error feedback", async t => {
    const { window, history } = await setup(t);

    for (const fetch of [
        async () => ({ ok: false, status: 500 }),
        async () => { throw new Error("Network unavailable"); }
    ]) {
        window.displayScanHistory([scan("scan-old")]);
        window.fetch = fetch;
        await window.loadScanHistory();

        assert.match(history.textContent, /Could not load scan history\./);
        assert.equal(history.querySelectorAll("button").length, 0);
        assert.doesNotMatch(history.textContent, /scan-old/);
    }
});

test("selecting different scans requests and displays their own results", async t => {
    const { window, history, results } = await setup(t);
    const scans = [scan("scan-a"), scan("scan-b", "192.0.2.20")];
    const requests = [];

    window.displayScanHistory(scans);
    window.fetch = async url => {
        requests.push(url);
        const selected = scans.find(item =>
            url.endsWith(`/${item.scan_id}/results`)
        );
        assert.ok(selected, `Unexpected request: ${url}`);
        return { ok: true, json: async () => selected };
    };

    const buttons = history.querySelectorAll(".view-scan-button");
    buttons[0].click();
    await settle();

    assert.match(results.textContent, /scan-a/);
    assert.doesNotMatch(results.textContent, /scan-b/);

    buttons[1].click();
    await settle();

    assert.match(results.textContent, /scan-b/);
    assert.match(results.textContent, /192\.0\.2\.20/);
    assert.doesNotMatch(results.textContent, /scan-a/);
    assert.deepEqual(requests, [
        "http://127.0.0.1:8000/scans/scan-a/results",
        "http://127.0.0.1:8000/scans/scan-b/results"
    ]);
});

test("clicking history outside a View button makes no request", async t => {
    const { window, history } = await setup(t);
    window.displayScanHistory([scan("scan-a")]);

    let requests = 0;
    window.fetch = async () => {
        requests++;
        return { ok: true, json: async () => [] };
    };

    history.querySelector("td").click();
    await settle();

    assert.equal(requests, 0);
});

test("history escapes HTML and reports a selected result request failure", async t => {
    const { window, history, message } = await setup(t);
    const payload = '<img src=x onerror="alert(1)">';
    window.displayScanHistory([{
        ...scan("scan-safe"),
        target: payload,
        status: payload
    }]);

    assert.equal(history.querySelectorAll("img").length, 0);
    assert.equal(history.querySelectorAll("[onerror]").length, 0);
    const cells = history.querySelectorAll("tbody td");
    assert.equal(cells[1].textContent.trim(), payload);
    assert.equal(cells[2].textContent.trim(), payload);

    window.fetch = async () => ({ ok: false, status: 404 });
    history.querySelector("button").click();
    await settle();

    assert.equal(message.className, "message-error");
    assert.equal(
        message.innerText,
        "Scan completed, but results could not be loaded."
    );
});
