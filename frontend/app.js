const API_BASE_URL = "http://127.0.0.1:8000";


// ==================================================
// Form elements
// ==================================================

const scanForm =
    document.getElementById("scanForm");

const targetInput =
    document.getElementById("target");

const startPortInput =
    document.getElementById("startPort");

const endPortInput =
    document.getElementById("endPort");

const scanDepthSelect =
    document.getElementById("scanDepth");

const scanTypeSelect =
    document.getElementById("scanType");

const timeoutInput =
    document.getElementById("timeout");

const scanButton =
    document.getElementById("scanButton");

const cancelButton =
    document.getElementById("cancelButton");

const messageDiv =
    document.getElementById("message");


// ==================================================
// Progress elements
// ==================================================

const progressSection =
    document.getElementById("progressSection");

const statusBadge =
    document.getElementById("statusBadge");

const scanIdText =
    document.getElementById("scanId");

const progressTarget =
    document.getElementById("progressTarget");

const progressBar =
    document.getElementById("progressBar");

const progressPercent =
    document.getElementById("progressPercent");

const currentHost =
    document.getElementById("currentHost");

const currentPort =
    document.getElementById("currentPort");

const currentService =
    document.getElementById("currentService");

const elapsedTime =
    document.getElementById("elapsedTime");

const progressMessage =
    document.getElementById("progressMessage");


// ==================================================
// Results elements
// ==================================================

const resultsSection =
    document.getElementById("resultsSection");

const resultsDiv =
    document.getElementById("results");


// Used to stop/start status polling
let statusPollingInterval = null;


// ==================================================
// START SCAN
// ==================================================

scanForm.addEventListener(
    "submit",
    async function(event) {

        event.preventDefault();

        clearMessage();
        hideResults();


        const target =
            targetInput.value.trim();

        const startPort =
            Number(startPortInput.value);

        const endPort =
            Number(endPortInput.value);

        const scanDepth =
            scanDepthSelect.value;

        const scanType =
            scanTypeSelect.value;

        const timeout =
            Number(timeoutInput.value);


        // ------------------------------------------
        // Validation
        // ------------------------------------------

        if (target === "") {

            showError(
                "Please enter a target."
            );

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


        // ------------------------------------------
        // This matches ScanConfiguration
        // in contracts.py
        // ------------------------------------------

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

            // --------------------------------------
            // POST /scans
            // --------------------------------------

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


            // Get first status immediately
            await getScanStatus(
                scan.scan_id
            );


            // Continue checking every second
            startStatusPolling(
                scan.scan_id
            );

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

    }
);


// ==================================================
// POLL STATUS
// ==================================================

function startStatusPolling(scanId) {

    stopStatusPolling();


    statusPollingInterval =
        setInterval(

            async function() {

                await getScanStatus(
                    scanId
                );

            },

            1000
        );

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


        // ------------------------------------------
        // Stop checking after scan finishes
        // ------------------------------------------

        if (
            normalizedStatus === "completed" ||
            normalizedStatus === "failed" ||
            normalizedStatus === "cancelled"
        ) {

            stopStatusPolling();


            scanButton.disabled =
                false;


            // Retrieve scan results
            if (
                normalizedStatus === "completed"
            ) {

                await getScanResults(
                    scanId
                );

            }

        }

    }

    catch (error) {

        console.error(
            "Could not retrieve status:",
            error
        );


        progressMessage.innerText =
            "Unable to retrieve scan status.";

    }

}


// ==================================================
// UPDATE PROGRESS DISPLAY
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


    // Status text
    statusBadge.innerText =
        status.status;


    // Progress bar
    progressBar.style.width =
        `${percent}%`;


    progressPercent.innerText =
        `${percent}%`;


    // Current scan information
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


    // ------------------------------------------
    // Status badge appearance
    // ------------------------------------------

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


        const results =
            await response.json();


        console.log(
            "Results:",
            results
        );


        displayResults(
            results
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
// DISPLAY RESULTS
// ==================================================

function displayResults(result) {

    resultsSection.classList.remove(
        "hidden"
    );


    let html = `

        <div class="result-summary">

            <p>
                <strong>Scan ID:</strong>
                ${escapeHtml(result.scan_id)}
            </p>

            <p>
                <strong>Target:</strong>
                ${escapeHtml(result.target)}
            </p>

            <p>
                <strong>Status:</strong>
                ${escapeHtml(result.status)}
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
        function(host) {

            html += `

                <div class="host-result">

                    <h3>
                        ${escapeHtml(host.host)}
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
                    function(port) {

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
// TARGET TYPE
// ==================================================

function determineTargetType(target) {

    // CIDR example:
    // 192.168.1.0/24

    if (target.includes("/")) {

        return "cidr";

    }


    // Simple IPv4 check
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
// SHOW PROGRESS SECTION
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
// CANCEL / RESET
// ==================================================

cancelButton.addEventListener(
    "click",
    function() {

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
// STOP POLLING
// ==================================================

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
// MESSAGE HELPERS
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
// RESULT HELPERS
// ==================================================

function hideResults() {

    resultsSection.classList.add(
        "hidden"
    );


    resultsDiv.innerHTML = "";

}


// ==================================================
// ESCAPE BACKEND TEXT
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