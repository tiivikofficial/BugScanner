from core.finding_deduplicator import FindingDeduplicator
from core.models import Severity, Vulnerability
from core.risk_prioritizer import RiskPrioritizer


def finding(vuln_type="xss", url="https://example.com/a", parameter="q", method="GET", cvss=6.0, evidence="evidence"):
    return Vulnerability(
        vuln_type=vuln_type,
        url=url,
        severity=Severity.MEDIUM,
        cvss_score=cvss,
        title="Test finding",
        description="Test description",
        evidence=evidence,
        exploitation="authorized test",
        remediation="fix it",
        parameter=parameter,
        method=method,
    )


def test_deduplicates_same_logical_finding():
    findings = [finding(), finding(url="https://EXAMPLE.com/a#fragment")]
    result = FindingDeduplicator.deduplicate(findings)
    assert len(result) == 1
    assert "evidence" in result[0].evidence


def test_keeps_different_parameters_separate():
    result = FindingDeduplicator.deduplicate([finding(parameter="a"), finding(parameter="b")])
    assert len(result) == 2


def test_keeps_higher_cvss_duplicate():
    result = FindingDeduplicator.deduplicate([finding(cvss=5.0), finding(cvss=8.0)])
    assert len(result) == 1
    assert result[0].cvss_score == 8.0


def test_risk_prioritizer_orders_findings():
    low = finding(cvss=2.0, evidence="")
    high = finding(cvss=9.0)
    result = RiskPrioritizer.prioritize([low, high])
    assert result == [high, low]


def test_risk_score_is_explainable_and_bounded():
    score = RiskPrioritizer.score(finding(cvss=10.0))
    assert 0.0 <= score.score <= 12.0
    assert score.cvss == 10.0
    assert score.evidence_bonus == 0.5
