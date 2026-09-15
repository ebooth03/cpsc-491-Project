# cpsc-491-Project
# CPSC 491 Vulnerability Scanner

A cybersecurity vulnerability scanner that identifies software vulnerabilities using network scanning and the NIST National Vulnerability Database (NVD).

## NVD API Integration

The NVD integration allows the scanner to search the NIST National Vulnerability Database for known CVEs based on software and an optional version.

The NVD client:

- Searches for CVEs using software names and versions
- Extracts CVE identifiers
- Extracts vulnerability descriptions
- Extracts CVSS scores and severity levels
- Extracts affected software and CPE information
- Extracts affected version boundaries
- Handles API timeouts and request errors
- Provides structured vulnerability data for use by other scanner components

### Example

```python
from nvd.nvd_client import NVDClient

client = NVDClient()

data = client.search_cves("apache", "2.4.49")
vulnerabilities = client.parse_cves(data)

for vulnerability in vulnerabilities:
    print(vulnerability["cve_id"])
    print(vulnerability["cvss_score"])
    print(vulnerability["severity"])