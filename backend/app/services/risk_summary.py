from app.models.contracts import VulnerabilityFinding


def classify_cvss(score: float) -> str:
    """
    Convert CVSS score into a risk category.

    Four categories are:
    low, medium, high, and critical.
    """

    if score < 0 or score > 10:
        raise ValueError("CVSS score must be between 0 and 10.")

    if score < 4.0:
        return "low"

    if score < 7.0:
        return "medium"

    if score < 9.0:
        return "high"

    return "critical"


def generate_risk_summary(
    findings: list[VulnerabilityFinding],
) -> dict:
    """
    Generate a summarized risk assessment from
    vulnerability findings.
    """

    severity_counts = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }

    valid_scores = []
    warnings = []

    for finding in findings:

        if finding.cvss_score is not None:
            severity = classify_cvss(finding.cvss_score)
            severity_counts[severity] += 1
            valid_scores.append(finding.cvss_score)
        else:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        

        

    # Handle incomplete CVSS data
    missing_scores = len(findings) - len(valid_scores)

    if missing_scores > 0:
        warnings.append(
            f"{missing_scores} finding(s) are missing CVSS scores."
        )

    # Calculate risk information
    if valid_scores:

        average_cvss = round(
            sum(valid_scores) / len(valid_scores),
            2,
        )

        highest_cvss = max(valid_scores)

        overall_risk = classify_cvss(
            average_cvss
        )

    else:

        average_cvss = None
        highest_cvss = None
        overall_risk = None

        if findings:
            warnings.append(
                "Overall risk could not be calculated because "
                "no CVSS scores were available."
            )

    # Highest-risk findings first
    scored_findings = [
        finding
        for finding in findings
        if finding.cvss_score is not None
    ]

    scored_findings.sort(
        key=lambda finding: finding.cvss_score,
        reverse=True,
    )

    key_findings = []

    for finding in scored_findings[:5]:

        key_findings.append(
            {
                "cve_id": finding.cve_id,
                "host": finding.host,
                "port": finding.port,
                "service": finding.service,
                "cvss_score": finding.cvss_score,
                "severity": finding.severity,
            }
        )

    # Collect remediation recommendations
    recommendations = []

    for finding in scored_findings:

        if (
            finding.remediation
            and finding.remediation not in recommendations
        ):
            recommendations.append(
                finding.remediation
            )

    return {
        "total_vulnerabilities": len(findings),
        "severity_counts": severity_counts,
        "overall_risk_score": average_cvss,
        "overall_risk": overall_risk,
        "highest_cvss": highest_cvss,
        "key_findings": key_findings,
        "recommendations": recommendations[:5],
        "warnings": warnings,
    }