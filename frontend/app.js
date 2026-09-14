// Get references to HTML elements
const scanForm = document.getElementById("scanForm");

const targetInput = document.getElementById("target");

const portsInput = document.getElementById("ports");

const intensitySelect = document.getElementById("intensity");

const scanTypeSelect = document.getElementById("scanType");

const cancelButton = document.getElementById("cancelButton");

const messageDiv = document.getElementById("message");

const scanSummaryDiv = document.getElementById("scanSummary");


// Runs when Start Scan is clicked
scanForm.addEventListener("submit", async function(event) {

    // Stop browser from refreshing the page
    event.preventDefault();


    // Get values entered by user
    const target = targetInput.value.trim();

    const ports = portsInput.value.trim();

    const intensity = intensitySelect.value;

    const scanType = scanTypeSelect.value;


    // Basic validation
    if (target === "") {
        showError("Please enter a target IP address or hostname.");
        return;
    }


    if (ports === "") {
        showError("Please enter a port range.");
        return;
    }


    // Create configuration object
    const scanConfig = {
        target: target,
        ports: ports,
        intensity: intensity,
        scan_type: scanType
    };


    console.log("Sending scan configuration:");
    console.log(scanConfig);


    // Let the user know something is happening
    messageDiv.style.color = "#94a3b8";
    messageDiv.innerText = "Sending scan configuration...";


    try {

        // Send configuration to Python backend
        const response = await fetch(
            "http://127.0.0.1:8000/api/scans",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(scanConfig)
            }
        );


        // Check whether backend returned an error
        if (!response.ok) {
            throw new Error(
                `Server returned status ${response.status}`
            );
        }


        // Convert JSON response into JavaScript object
        const data = await response.json();


        console.log("Backend response:");
        console.log(data);


        // Show success message
        messageDiv.style.color = "#22c55e";

        messageDiv.innerText = data.message;


        // Display configuration returned by backend
        displayScanSummary(data);

    } catch (error) {

        console.error("Error communicating with backend:");
        console.error(error);

        showError(
            "Could not connect to the backend. Make sure FastAPI is running."
        );

    }

});



// Cancel button
cancelButton.addEventListener("click", function() {

    // Reset form fields
    scanForm.reset();


    // Remove any messages
    messageDiv.innerText = "";


    // Clear summary
    scanSummaryDiv.innerHTML = "";

    scanSummaryDiv.style.display = "none";

});



// Displays errors
function showError(message) {

    messageDiv.style.color = "#ef4444";

    messageDiv.innerText = message;

}



// Displays the configuration returned by backend
function displayScanSummary(data) {

    scanSummaryDiv.style.display = "block";


    scanSummaryDiv.innerHTML = `

        <h2>Scan Configuration</h2>

        <p>
            <strong>Scan ID:</strong>
            ${data.scan_id}
        </p>

        <p>
            <strong>Status:</strong>
            ${data.status}
        </p>

        <p>
            <strong>Target:</strong>
            ${data.configuration.target}
        </p>

        <p>
            <strong>Ports:</strong>
            ${data.configuration.ports}
        </p>

        <p>
            <strong>Intensity:</strong>
            ${data.configuration.intensity}
        </p>

        <p>
            <strong>Scan Type:</strong>
            ${data.configuration.scan_type}
        </p>

    `;

}