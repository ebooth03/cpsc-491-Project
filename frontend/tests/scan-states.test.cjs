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
    const timers = new Map();
    let nextTimer = 1;

    // Controlled timers prevent real polling during tests.
    window.setInterval = (callback, delay) => {
        const id = nextTimer++;
        timers.set(id, { callback, delay });
        return id;
    };
    window.clearInterval = id => timers.delete(id);
    window.fetch = async () => ({
        ok: true,
        json: async () => []
    });

    // Suppress expected application logs during tests.
    window.console.log = () => {};
    window.console.error = () => {};
    window.eval(app);

    // Allow initial history loading to finish.
    await new Promise(resolve => setImmediate(resolve));

    return {
        window,
        timers,
        element: id => window.document.getElementById(id)
    };
}

test("running status displays progress and current service details", async t => {
    const { window, element } = await setup(t);
    window.updateProgressDisplay({
        status: "running",
        progress_percent: 35,
        current_host: "192.0.2.10",
        current_port: 443,
        current_service: "https",
        elapsed_time: 2.34,
        message: "Scanning ports"
    });

    assert.equal(element("statusBadge").innerText, "running");
    assert.ok(element("statusBadge").classList.contains("status-running"));
    assert.equal(element("progressBar").style.width, "35%");
    assert.equal(element("progressPercent").innerText, "35%");
    assert.equal(element("currentHost").innerText, "192.0.2.10");
    assert.equal(String(element("currentPort").innerText), "443");
    assert.equal(element("currentService").innerText, "https");
    assert.equal(element("elapsedTime").innerText, "2.3");
    assert.equal(element("progressMessage").innerText, "Scanning ports");
});

test("progress is clamped and missing details have defaults", async t => {
    const { window, element } = await setup(t);

    for (const [percent, expected] of [
        [-10, "0%"], [150, "100%"], [undefined, "0%"]
    ]) {
        window.updateProgressDisplay({
            status: "running",
            progress_percent: percent
        });
        assert.equal(element("progressBar").style.width, expected);
        assert.equal(element("progressPercent").innerText, expected);
        assert.equal(element("currentHost").innerText, "-");
        assert.equal(element("currentPort").innerText, "-");
        assert.equal(element("currentService").innerText, "-");
        assert.equal(element("elapsedTime").innerText, "0");
        assert.equal(element("progressMessage").innerText, "Scan is running.");
    }
});

test("completed status stops polling and loads matching results", async t => {
    const { window, timers, element } = await setup(t);
    const requests = [];

    window.fetch = async url => {
        requests.push(url);
        if (url.endsWith("/status")) {
            return {
                ok: true,
                json: async () => ({
                    status: "COMPLETED",
                    progress_percent: 100
                })
            };
        }
        if (url.endsWith("/results")) {
            return {
                ok: true,
                json: async () => ({
                    scan_id: "scan-complete",
                    target: "127.0.0.1",
                    status: "completed",
                    hosts: []
                })
            };
        }
        return { ok: true, json: async () => [] };
    };

    element("scanButton").disabled = true;
    window.startStatusPolling("scan-complete");

    assert.equal(await window.getScanStatus("scan-complete"), "completed");
    assert.equal(timers.size, 0);
    assert.equal(element("scanButton").disabled, false);
    assert.ok(element("statusBadge").classList.contains("status-completed"));
    assert.match(element("results").textContent, /scan-complete/);
    assert.ok(requests.some(url => url.endsWith("/scan-complete/results")));
    assert.equal(
        requests.filter(url => url.endsWith("/scans")).length,
        1,
        "Terminal status should refresh history exactly once"
    );
});

test("failed and cancelled states stop polling without loading results", async t => {
    const { window, timers, element } = await setup(t);

    for (const state of ["failed", "cancelled"]) {
        const requests = [];
        window.fetch = async url => {
            requests.push(url);
            return {
                ok: true,
                json: async () => url.endsWith("/status")
                    ? { status: state, progress_percent: 20,
                        message: `Scan ${state}` }
                    : []
            };
        };

        element("scanButton").disabled = true;
        window.startStatusPolling("scan-terminal");

        assert.equal(await window.getScanStatus("scan-terminal"), state);
        assert.equal(timers.size, 0);
        assert.equal(element("scanButton").disabled, false);
        assert.equal(element("statusBadge").innerText, state);
        assert.equal(element("progressMessage").innerText, `Scan ${state}`);
        assert.equal(requests.some(url => url.endsWith("/results")), false);
        assert.equal(
        requests.filter(url => url.endsWith("/scans")).length,
        1,
        "Terminal status should refresh history exactly once"
    );

        if (state === "failed") {
            assert.ok(element("statusBadge").classList.contains("status-failed"));
        }
        if (state === "cancelled") {
            assert.ok(
                element("statusBadge").classList.contains("status-cancelled"),
                "Cancelled scans should have a cancelled badge"
            );
        }
    }
});

test("status HTTP and network failures show retrieval feedback", async t => {
    const { window, element } = await setup(t);
    const responses = [
        async () => ({ ok: false, status: 503 }),
        async () => { throw new Error("Network unavailable"); }
    ];

    for (const fetch of responses) {
        window.fetch = fetch;
        assert.equal(await window.getScanStatus("scan-error"), "error");
        assert.equal(
            element("progressMessage").innerText,
            "Unable to retrieve scan status."
        );
    }
});

test("results request failure shows an error message", async t => {
    const { window, element } = await setup(t);
    window.fetch = async () => ({ ok: false, status: 500 });

    await window.getScanResults("scan-error");

    assert.equal(element("message").className, "message-error");
    assert.equal(
        element("message").innerText,
        "Scan completed, but results could not be loaded."
    );
});

test("cancel resets the frontend and stops polling without a backend request", async t => {
    const { window, timers, element } = await setup(t);
    let requests = 0;
    window.fetch = async () => {
        requests++;
        return { ok: true, json: async () => [] };
    };

    element("target").value = "192.0.2.10";
    element("scanButton").disabled = true;
    window.showProgressSection("scan-reset", "192.0.2.10");
    window.displayResults({
        scan_id: "scan-reset",
        target: "192.0.2.10",
        status: "completed",
        hosts: []
    });
    window.showInfo("Scanning");
    window.startStatusPolling("scan-reset");

    element("cancelButton").click();

    assert.equal(timers.size, 0);
    assert.equal(element("target").value, "");
    assert.equal(element("scanButton").disabled, false);
    assert.ok(element("progressSection").classList.contains("hidden"));
    assert.ok(element("resultsSection").classList.contains("hidden"));
    assert.equal(element("results").innerHTML, "");
    assert.equal(element("message").innerText, "");
    assert.equal(requests, 0);
});

test("unchecked authorization blocks submission without a request", async t => {
    const { window, element } = await setup(t);
    const checkbox = element("authorizationAcknowledged");
    assert.equal(checkbox.checked, false);
    assert.equal(checkbox.required, true);

    let requests = 0;
    window.fetch = async () => {
        requests++;
        return { ok: true, json: async () => [] };
    };

    element("target").value = "192.0.2.10";
    element("scanForm").dispatchEvent(
        new window.Event("submit", { bubbles: true, cancelable: true })
    );
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(requests, 0);
    assert.equal(
        element("message").innerText,
        "Confirm that you have permission to scan this target."
    );
});

test("checked authorization sends an explicit Boolean acknowledgement", async t => {
    const { window, element } = await setup(t);
    const posts = [];

    element("target").value = "192.0.2.10";
    element("startPort").value = "20";
    element("endPort").value = "25";
    element("timeout").value = "5";
    element("scanType").value = "tcp";
    element("scanDepth").value = "standard";
    element("authorizationAcknowledged").checked = true;
    element("scanAccessToken").value = "test-scan-token";

    window.fetch = async (url, options = {}) => {
        if (options.method === "POST") {
            assert.equal(options.headers.Authorization, "Bearer test-scan-token");
            assert.ok(!options.body.includes("test-scan-token"));
            posts.push(JSON.parse(options.body));
            return {
                ok: true,
                json: async () => ({
                    scan_id: "scan-authorized",
                    status: "queued"
                })
            };
        }
        return {
            ok: true,
            json: async () => url.endsWith("/status")
                ? { status: "running", progress_percent: 0 }
                : []
        };
    };

    element("scanForm").dispatchEvent(
        new window.Event("submit", { bubbles: true, cancelable: true })
    );
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(posts.length, 1);
    assert.equal(posts[0].target, "192.0.2.10");
    assert.equal(posts[0].options.authorization_acknowledged, true);
});
