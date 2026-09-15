import unittest
from unittest.mock import patch

import requests

from nvd.nvd_client import NVDClient


class TestNVDClient(unittest.TestCase):

    def setUp(self):
        self.client = NVDClient()

    def test_parse_cves(self):
        sample_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Apache HTTP Server vulnerability."
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL"
                                    }
                                }
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }

        results = self.client.parse_cves(sample_data)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(
            results[0]["description"],
            "Apache HTTP Server vulnerability."
        )
        self.assertEqual(results[0]["cvss_score"], 9.8)
        self.assertEqual(results[0]["severity"], "CRITICAL")
        self.assertEqual(len(results[0]["affected_software"]), 1)
        self.assertIn(
            "apache:http_server:2.4.49",
            results[0]["affected_software"][0]["cpe"]
        )

    def test_parse_empty_response(self):
        results = self.client.parse_cves(None)
        self.assertEqual(results, [])

    def test_parse_no_vulnerabilities(self):
        sample_data = {
            "vulnerabilities": []
        }

        results = self.client.parse_cves(sample_data)

        self.assertEqual(results, [])

    def test_search_cves_handles_request_error(self):
        self.client.BASE_URL = "https://invalid-nvd-url.example"

        result = self.client.search_cves("apache", "2.4.49")

        self.assertIsNone(result)

    def test_search_cves_handles_timeout(self):
        with patch(
            "nvd.nvd_client.requests.get",
            side_effect=requests.exceptions.Timeout
        ):
            result = self.client.search_cves("apache", "2.4.49")

        self.assertIsNone(result)

    def test_parse_version_boundaries(self):
        sample_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-TEST-0001",
                        "descriptions": [],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:a:test:software:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "1.0",
                                                "versionStartExcluding": "2.0",
                                                "versionEndIncluding": "3.0",
                                                "versionEndExcluding": "4.0"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }

        results = self.client.parse_cves(sample_data)

        affected = results[0]["affected_software"][0]

        self.assertEqual(affected["version_start_including"], "1.0")
        self.assertEqual(affected["version_start_excluding"], "2.0")
        self.assertEqual(affected["version_end_including"], "3.0")
        self.assertEqual(affected["version_end_excluding"], "4.0")


if __name__ == "__main__":
    unittest.main()
