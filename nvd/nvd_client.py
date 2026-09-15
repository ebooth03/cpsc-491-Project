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