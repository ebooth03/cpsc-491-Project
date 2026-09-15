import requests


class NVDClient:
    """Client for communicating with the NIST NVD API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key=None):
        self.api_key = api_key

    def search_cves(self, keyword):
        """Search the NVD for CVEs matching a keyword."""

        headers = {}

        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10
        }

        response = requests.get(
            self.BASE_URL,
            params=params,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    def parse_cves(self, data):
        """Extract useful vulnerability information from an NVD API response."""

        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for item in vulnerabilities:
            cve = item.get("cve", {})

            cve_id = cve.get("id")

            descriptions = cve.get("descriptions", [])
            description = ""

            if descriptions:
                description = descriptions[0].get("value", "")

            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = None

            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")

            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")

            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity
            })

        return results