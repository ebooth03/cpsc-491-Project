import unittest

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


if __name__ == "__main__":
    unittest.main()
