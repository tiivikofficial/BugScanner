from core.finding_pipeline import FindingPipeline
from core.models import Severity, Vulnerability


def make_finding(kind="xss"):
    return Vulnerability(
        vuln_type=kind,
        url="https://example.test/search?q=hello",
        severity=Severity.HIGH,
        cvss_score=8.1,
        title="Test finding",
        description="Evidence-backed test finding",
        evidence="Reflected marker observed in response",
        exploitation="Impact requires manual confirmation",
        remediation="Fix the vulnerable input handling",
        parameter="q",
        payload_used="BUGSCANNER_POC",
        references=["CWE-79"],
    )


def test_pipeline_adds_poc_verification_and_priority():
    findings, manifest = FindingPipeline.process([make_finding()])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.poc_available is True
    assert finding.curl_poc
    assert finding.verification_status in {"medium-confidence", "high-confidence", "verified"}
    assert finding.risk_priority in {"P0", "P1", "P2", "P3"}
    assert manifest["final_findings"] == 1


def test_pipeline_filters_duplicates():
    findings, manifest = FindingPipeline.process([make_finding(), make_finding()])
    assert len(findings) == 1
    assert manifest["duplicates_filtered"] == 1
