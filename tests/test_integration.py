import pytest

from integration.workflow import InMemoryStorage, ScanWorkflow
from vulnerability.matcher import VulnerabilityMatcher


class FakeScanner:
    """Predictable scanner used for integration tests."""

    def scan(self, target, ports):
        results = []

        for port in ports:
            if port == 80:
                results.append({
                    "target": target,
                    "port": port,
                    "state": "open",
                    "service": {
                        "name": "apache",
                        "version": "2.4.49",
                    },
                })
            else:
                results.append({
                    "target": target,
                    "port": port,
                    "state": "closed",
                    "service": None,
                })

        return results


@pytest.fixture
def vulnerabilities():
    return [
        {
            "cve": "CVE-TEST-0001",
            "service": "apache",
            "version": "2.4.49",
        }
    ]


@pytest.fixture
def workflow():
    return ScanWorkflow(
        scanner=FakeScanner(),
        matcher=VulnerabilityMatcher(),
        storage=InMemoryStorage(),
    )


def test_complete_scan_workflow(workflow, vulnerabilities):
    results = workflow.run(
        "127.0.0.1",
        [80],
        vulnerabilities,
    )

    assert len(results) == 1

    result = results[0]

    assert result["target"] == "127.0.0.1"
    assert result["port"] == 80
    assert result["state"] == "open"
    assert result["service"]["name"] == "apache"

    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["cve"] == "CVE-TEST-0001"


def test_results_are_saved_to_storage(workflow, vulnerabilities):
    workflow.run(
        "127.0.0.1",
        [80],
        vulnerabilities,
    )

    stored_results = workflow.storage.get_all()

    assert len(stored_results) == 1
    assert stored_results[0]["port"] == 80


def test_no_vulnerability_match(workflow, vulnerabilities):
    results = workflow.run(
        "127.0.0.1",
        [443],
        vulnerabilities,
    )

    assert results[0]["vulnerabilities"] == []


def test_multiple_ports_flow_through_workflow(workflow, vulnerabilities):
    results = workflow.run(
        "127.0.0.1",
        [80, 443],
        vulnerabilities,
    )

    assert len(results) == 2

    assert results[0]["port"] == 80
    assert results[0]["state"] == "open"

    assert results[1]["port"] == 443
    assert results[1]["state"] == "closed"


def test_frontend_result_contains_expected_fields(workflow, vulnerabilities):
    results = workflow.run(
        "127.0.0.1",
        [80],
        vulnerabilities,
    )

    result = results[0]

    assert "target" in result
    assert "port" in result
    assert "state" in result
    assert "service" in result
    assert "vulnerabilities" in result