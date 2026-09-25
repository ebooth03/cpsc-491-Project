const API_BASE_URL = "http://127.0.0.1:8000";


// ==================================================
// Form elements
// ==================================================

const scanForm = document.getElementById("scanForm");
const targetInput = document.getElementById("target");
const startPortInput = document.getElementById("startPort");
const endPortInput = document.getElementById("endPort");
const scanDepthSelect = document.getElementById("scanDepth");
const scanTypeSelect = document.getElementById("scanType");
const timeoutInput = document.getElementById("timeout");
const scanButton = document.getElementById("scanButton");
const cancelButton = document.getElementById("cancelButton");
const messageDiv = document.getElementById("message");


// ==================================================
// Progress elements
// ==================================================

const progressSection = document.getElementById("progressSection");
const statusBadge = document.getElementById("statusBadge");
const scanIdText = document.getElementById("scanId");
const progressTarget = document.getElementById("progressTarget");
const progressBar = document.getElementById("progressBar");
const progressPercent = document.getElementById("progressPercent");
const currentHost = document.getElementById("currentHost");
const currentPort = document.getElementById("currentPort");
const currentService = document.getElementById("currentService");
const elapsedTime = document.getElementById("elapsedTime");
const progressMessage = document.getElementById("progressMessage");


// ==================================================
// Results / history elements
// ==================================================

const resultsSection = document.getElementById("resultsSection");
const resultsDiv = document.getElementById("results");
const scanHistoryDiv = document.getElementById("scanHistory");


// Used to stop/start status polling
let statusPollingInterval = null;


// ==================================================
// Start scan
// ==================================================

scanForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    clearMessage();
    hideResults();

    const target = targetInput.value.trim();
    const startPort = Number(startPortInput.value);
    const endPort = Number(endPortInput.value);
    const scanDepth = scanDepthSelect.value;
    const scanType = scanTypeSelect.value;
    const timeout = Number(timeoutInput.value);


    // ------------------------------
    // Validation
    // ------------------------------

    if (target === "") {

        showError("Please enter a target.");
        return;

    }


    if (
        startPort < 1 ||
        startPort > 65535 ||
        endPort < 1 ||
        endPort > 65535
    ) {

        showError(
            "Ports must be between 1 and 65535."
        );

        return;

    }


    if (startPort > endPort) {

        showError(
            "Start port cannot be greater than end port."
        );

        return;

    }


    if (timeout < 1) {

        showError(
            "Timeout must be at least 1 second."
        );

        return;

    }


    // ------------------------------
    // Matches ScanConfiguration
    // in contracts.py
    // ------------------------------

    const scanConfig = {

        target: target,

        target_type:
            determineTargetType(target),

        port_range: {
            start: startPort,
            end: endPort
        },

        scan_type: scanType,

        scan_depth: scanDepth,

        timeout: timeout,

        options: {}

    };


    console.log(
        "Sending scan:",
        scanConfig
    );


    scanButton.disabled = true;

    showInfo(
        "Starting scan..."
    );


    try {

        const response = await fetch(
            `${API_BASE_URL}/scans`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(scanConfig)
            }
        );


        if (!response.ok) {

            const errorBody =
                await response.text();

            throw new Error(
                `${response.status}: ${errorBody}`
            );

        }


        const scan =
            await response.json();


        console.log(
            "Scan created:",
            scan
        );


        showSuccess(
            "Scan started successfully."
        );


        showProgressSection(
            scan.scan_id,
            target
        );


        /*
         * Get the current status immediately.
         *
         * Right now your mock backend returns
         * "completed" immediately, so this may
         * also load the results right away.
         */

        const currentStatus =
            await getScanStatus(
                scan.scan_id
            );


        /*
         * Only start polling if the scan
         * is still running.
         */

        if (
            currentStatus !== "completed" &&
            currentStatus !== "failed" &&
            currentStatus !== "cancelled"
        ) {

            startStatusPolling(
                scan.scan_id
            );

        }

    }

    catch (error) {

        console.error(
            "Could not start scan:",
            error
        );


        showError(
            "Could not start scan. Make sure the backend is running."
        );


        scanButton.disabled =
            false;

    }

});


// ==================================================
// Poll status
// ==================================================

function startStatusPolling(scanId) {

    stopStatusPolling();


    statusPollingInterval =
        setInterval(

            async function () {

                await getScanStatus(
                    scanId
                );

            },

            1000
        );

}


function stopStatusPolling() {

    if (
        statusPollingInterval !== null
    ) {

        clearInterval(
            statusPollingInterval
        );


        statusPollingInterval =
            null;

    }

}


// ==================================================
// GET /scans/{id}/status
// ==================================================

async function getScanStatus(scanId) {

    try {

        const response = await fetch(
            `${API_BASE_URL}/scans/${scanId}/status`
        );


        if (!response.ok) {

            throw new Error(
                `Status request failed: ${response.status}`
            );

        }


        const status =
            await response.json();


        console.log(
            "Status:",
            status
        );


        updateProgressDisplay(
            status
        );


        const normalizedStatus =
            status.status.toLowerCase();


        /*
         * Stop checking once the scan
         * reaches a final state.
         */

        if (
            normalizedStatus === "completed" ||
            normalizedStatus === "failed" ||
            normalizedStatus === "cancelled"
        ) {

            stopStatusPolling();


            scanButton.disabled =
                false;


            /*
             * Load results when a scan
             * completes successfully.
             */

            if (
                normalizedStatus === "completed"
            ) {

                await getScanResults(
                    scanId
                );

                await loadScanHistory();

            }


            /*
             * Refresh scan history whenever
             * a scan reaches a final state.
             */

            await loadScanHistory();

        }


        return normalizedStatus;

    }

    catch (error) {

        console.error(
            "Could not retrieve status:",
            error
        );


        progressMessage.innerText =
            "Unable to retrieve scan status.";


        return "error";

    }

}


// ==================================================
// Update progress display
// ==================================================

function updateProgressDisplay(status) {

    const percent =
        Math.max(
            0,
            Math.min(
                100,
                status.progress_percent ?? 0
            )
        );


    statusBadge.innerText =
        status.status;


    progressBar.style.width =
        `${percent}%`;


    progressPercent.innerText =
        `${percent}%`;


    currentHost.innerText =
        status.current_host ?? "-";


    currentPort.innerText =
        status.current_port ?? "-";


    currentService.innerText =
        status.current_service ?? "-";


    if (
        status.elapsed_time !== null &&
        status.elapsed_time !== undefined
    ) {

        elapsedTime.innerText =
            Number(
                status.elapsed_time
            ).toFixed(1);

    }

    else {

        elapsedTime.innerText =
            "0";

    }


    progressMessage.innerText =
        status.message ??
        "Scan is running.";


    /*
     * Update status badge appearance.
     */

    statusBadge.className = "";


    const normalizedStatus =
        status.status.toLowerCase();


    if (
        normalizedStatus === "completed"
    ) {

        statusBadge.classList.add(
            "status-completed"
        );

    }

    else if (
        normalizedStatus === "failed"
    ) {

        statusBadge.classList.add(
            "status-failed"
        );

    }

    else {

        statusBadge.classList.add(
            "status-running"
        );

    }

}


// ==================================================
// GET /scans/{id}/results
// ==================================================

async function getScanResults(scanId) {

    try {

        const response = await fetch(
            `${API_BASE_URL}/scans/${scanId}/results`
        );


        if (!response.ok) {

            throw new Error(
                `Results request failed: ${response.status}`
            );

        }


        const result =
            await response.json();


        console.log(
            "Results:",
            result
        );


        displayResults(
            result
        );

    }

    catch (error) {

        console.error(
            "Could not retrieve results:",
            error
        );


        showError(
            "Scan completed, but results could not be loaded."
        );

    }

}


// ==================================================
// Scan history
// ==================================================

async function loadScanHistory() {

    try {

        const response = await fetch(
            `${API_BASE_URL}/scans`
        );


        if (!response.ok) {

            throw new Error(
                `History request failed: ${response.status}`
            );

        }


        const scans =
            await response.json();


        displayScanHistory(
            scans
        );

    }

    catch (error) {

        console.error(
            "Could not load scan history:",
            error
        );


        scanHistoryDiv.innerHTML = `
            <p class="empty-results">
                Could not load scan history.
            </p>
        `;

    }

}


function displayScanHistory(scans) {

    if (
        !scans ||
        scans.length === 0
    ) {

        scanHistoryDiv.innerHTML = `
            <p class="empty-results">
                No scans yet.
            </p>
        `;


        return;

    }


    let html = `

        <div class="table-wrapper">

            <table>

                <thead>

                    <tr>
                        <th>Scan ID</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Started</th>
                        <th>Action</th>
                    </tr>

                </thead>

                <tbody>

    `;


    scans.forEach(
        function (scan) {

            const startTime =
                new Date(
                    scan.start_time
                ).toLocaleString();


            html += `

                <tr>

                    <td>
                        ${escapeHtml(
                            scan.scan_id
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            scan.target
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            scan.status
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            startTime
                        )}
                    </td>

                    <td>

                        <button
                            type="button"
                            class="view-scan-button"
                            data-scan-id="${escapeHtml(
                                scan.scan_id
                            )}"
                        >
                            View
                        </button>

                    </td>

                </tr>

            `;

        }
    );


    html += `

                </tbody>

            </table>

        </div>

    `;


    scanHistoryDiv.innerHTML =
        html;

}


// ==================================================
// View a scan from history
// ==================================================

scanHistoryDiv.addEventListener(
    "click",

    async function (event) {

        const viewButton =
            event.target.closest(
                ".view-scan-button"
            );


        if (!viewButton) {
            return;
        }


        const scanId =
            viewButton.dataset.scanId;


        await getScanResults(
            scanId
        );

    }
);


// ==================================================
// Display results
// ==================================================

function displayResults(result) {

    resultsSection.classList.remove(
        "hidden"
    );


    let html = `

        <div class="result-summary">

            <p>
                <strong>Scan ID:</strong>
                ${escapeHtml(
                    result.scan_id
                )}
            </p>

            <p>
                <strong>Target:</strong>
                ${escapeHtml(
                    result.target
                )}
            </p>

            <p>
                <strong>Status:</strong>
                ${escapeHtml(
                    result.status
                )}
            </p>

        </div>

    `;


    if (
        !result.hosts ||
        result.hosts.length === 0
    ) {

        html += `

            <p class="empty-results">
                No hosts were returned by this scan.
            </p>

        `;


        resultsDiv.innerHTML =
            html;


        return;

    }


    result.hosts.forEach(
        function (host) {

            html += `

                <div class="host-result">

                    <h3>
                        ${escapeHtml(
                            host.host
                        )}
                    </h3>

            `;


            if (
                !host.ports ||
                host.ports.length === 0
            ) {

                html += `

                    <p>
                        No ports returned.
                    </p>

                `;

            }

            else {

                html += `

                    <div class="table-wrapper">

                        <table>

                            <thead>

                                <tr>
                                    <th>Port</th>
                                    <th>Protocol</th>
                                    <th>State</th>
                                    <th>Service</th>
                                    <th>Version</th>
                                </tr>

                            </thead>

                            <tbody>

                `;


                host.ports.forEach(
                    function (port) {

                        html += `

                            <tr>

                                <td>
                                    ${port.port}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        port.protocol
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        port.state
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        port.service ?? "-"
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        port.version ?? "-"
                                    )}
                                </td>

                            </tr>

                        `;

                    }
                );


                html += `

                            </tbody>

                        </table>

                    </div>

                `;

            }


            html += `

                </div>

            `;

        }
    );


    resultsDiv.innerHTML =
        html;

}


// ==================================================
// Target type
// ==================================================

function determineTargetType(target) {

    /*
     * CIDR example:
     * 192.168.1.0/24
     */

    if (
        target.includes("/")
    ) {

        return "cidr";

    }


    /*
     * Simple IPv4 check.
     */

    const ipv4Pattern =
        /^(\d{1,3}\.){3}\d{1,3}$/;


    if (
        ipv4Pattern.test(target)
    ) {

        return "ip";

    }


    return "hostname";

}


// ==================================================
// Show progress section
// ==================================================

function showProgressSection(
    scanId,
    target
) {

    progressSection.classList.remove(
        "hidden"
    );


    scanIdText.innerText =
        scanId;


    progressTarget.innerText =
        target;


    progressBar.style.width =
        "0%";


    progressPercent.innerText =
        "0%";


    statusBadge.innerText =
        "Starting";


    statusBadge.className =
        "status-running";


    currentHost.innerText =
        "-";


    currentPort.innerText =
        "-";


    currentService.innerText =
        "-";


    elapsedTime.innerText =
        "0";


    progressMessage.innerText =
        "Waiting for scan status...";

}


// ==================================================
// Cancel / reset
// ==================================================

cancelButton.addEventListener(
    "click",

    function () {

        stopStatusPolling();


        scanForm.reset();


        progressSection.classList.add(
            "hidden"
        );


        hideResults();


        clearMessage();


        scanButton.disabled =
            false;

    }
);


// ==================================================
// Message helpers
// ==================================================

function showError(message) {

    messageDiv.className =
        "message-error";


    messageDiv.innerText =
        message;

}


function showSuccess(message) {

    messageDiv.className =
        "message-success";


    messageDiv.innerText =
        message;

}


function showInfo(message) {

    messageDiv.className =
        "message-info";


    messageDiv.innerText =
        message;

}


function clearMessage() {

    messageDiv.className = "";

    messageDiv.innerText = "";

}


// ==================================================
// Result helpers
// ==================================================

function hideResults() {

    resultsSection.classList.add(
        "hidden"
    );


    resultsDiv.innerHTML = "";

}


// ==================================================
// Escape backend text
// ==================================================

function escapeHtml(value) {

    return String(value)

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );

}


// ==================================================
// Initial page load
// ==================================================

loadScanHistory();