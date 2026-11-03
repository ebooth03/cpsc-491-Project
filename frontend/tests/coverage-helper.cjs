const fs = require("node:fs");
const path = require("node:path");
const { createCoverageMap } = require("istanbul-lib-coverage");

const coverageDir = path.join(__dirname, "..", ".nyc_output");

function saveCoverage(window) {
    if (!window.__coverage__) {
        throw new Error("No Istanbul coverage data found");
    }

    fs.mkdirSync(coverageDir, { recursive: true });

    const coverageMap = createCoverageMap({});
    coverageMap.merge(window.__coverage__);

    const filename = path.join(
        coverageDir,
        `${process.pid}-${require("node:crypto").randomUUID()}.json`
    );

    fs.writeFileSync(
        filename,
        JSON.stringify(coverageMap.toJSON()),
        "utf8"
    );
}

module.exports = { saveCoverage };