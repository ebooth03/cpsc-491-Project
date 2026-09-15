from scanner.scanner import Scanner
from vulnerability.matcher import VulnerabilityMatcher


class InMemoryStorage:
    """Temporary storage used for integration testing."""

    def __init__(self):
        self.results = []

    def save(self, result):
        self.results.append(result)

    def get_all(self):
        return self.results


class ScanWorkflow:
    """Coordinates scanning, vulnerability matching, and storage."""

    def __init__(self, scanner=None, matcher=None, storage=None):
        self.scanner = scanner or Scanner()
        self.matcher = matcher or VulnerabilityMatcher()
        self.storage = storage or InMemoryStorage()

    def run(self, target, ports, vulnerabilities):
        scan_results = self.scanner.scan(target, ports)

        final_results = []

        for scan_result in scan_results:
            service = scan_result.get("service")

            findings = []

            if service:
                findings = self.matcher.match(
                    service["name"],
                    service["version"],
                    vulnerabilities,
                )

            result = {
                "target": scan_result["target"],
                "port": scan_result["port"],
                "state": scan_result["state"],
                "service": service,
                "vulnerabilities": findings,
            }

            self.storage.save(result)
            final_results.append(result)

        return final_results