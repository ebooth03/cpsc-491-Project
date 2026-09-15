import requests


class NVDClient:
    """Client for communicating with the NIST NVD API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key=None):
        self.api_key = api_key

    def search_cves(self, software, version=None):
        """Search the NVD for CVEs matching software and optionally a version."""

        headers = {}

        if self.api_key:
            headers["apiKey"] = self.api_key

        keyword = software

        if version:
            keyword = f"{software} {version}"

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10
        }

        try:
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=10
            )

            response.raise_for_status()

            return response.json()

        except requests.exceptions.Timeout:
            print("NVD API request timed out.")
            return None

        except requests.exceptions.HTTPError as error:
            print(f"NVD API returned an HTTP error: {error}")
            return None

        except requests.exceptions.RequestException as error:
            print(f"NVD API request failed: {error}")
            return None

    def parse_cves(self, data):
        """Extract useful vulnerability information from an NVD API response."""

        if not data:
            return []

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

            configurations = cve.get("configurations", [])
            affected_software = []

            for configuration in configurations:
                nodes = configuration.get("nodes", [])

                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])

                    for cpe_match in cpe_matches:
                        criteria = cpe_match.get("criteria")

                        if criteria:
                            affected_software.append({
                                "cpe": criteria,
                                "version_start_including": cpe_match.get(
                                    "versionStartIncluding"
                                ),
                                "version_start_excluding": cpe_match.get(
                                    "versionStartExcluding"
                                ),
                                "version_end_including": cpe_match.get(
                                    "versionEndIncluding"
                                ),
                                "version_end_excluding": cpe_match.get(
                                    "versionEndExcluding"
                                )
                            })

            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "affected_software": affected_software
            })

        return results