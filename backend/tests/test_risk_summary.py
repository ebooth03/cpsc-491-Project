from app.services.risk_summary import (
    classify_cvss,
    generate_risk_summary,
)


def make_finding(finding_factory, cve_id, score, severity):
    return finding_factory(
        cve_id=cve_id,
        cvss_score=score,
        severity=severity,
        remediation="Install the latest security update.",
    )


def test_cvss_categories():
    assert classify_cvss(3.9) == "low"
    assert classify_cvss(4.0) == "medium"
    assert classify_cvss(6.9) == "medium"
    assert classify_cvss(7.0) == "high"
    assert classify_cvss(8.9) == "high"
    assert classify_cvss(9.0) == "critical"
    assert classify_cvss(10.0) == "critical"


def test_generate_summary(finding_factory):

    findings = [
        make_finding(finding_factory, "CVE-TEST-1", 9.8, "critical"),
        make_finding(finding_factory, "CVE-TEST-2", 7.5, "high"),
        make_finding(finding_factory, "CVE-TEST-3", 5.0, "medium"),
    ]

    summary = generate_risk_summary(findings)

    assert summary["total_vulnerabilities"] == 3
    assert summary["severity_counts"]["critical"] == 1
    assert summary["severity_counts"]["high"] == 1
    assert summary["severity_counts"]["medium"] == 1
    assert summary["highest_cvss"] == 9.8
    assert summary["overall_risk"] == "high"


def test_missing_cvss(finding_factory):

    findings = [
        make_finding(finding_factory, "CVE-TEST-4",
            None,
            "medium",
        )
    ]

    summary = generate_risk_summary(findings)

    assert summary["overall_risk_score"] is None
    assert len(summary["warnings"]) > 0


def test_empty_findings():

    summary = generate_risk_summary([])

    assert summary["total_vulnerabilities"] == 0
    assert summary["overall_risk"] is None
    assert summary["highest_cvss"] is None