from core.finding_pipeline import FindingPipeline
from core.models import Severity, Vulnerability
from core.poc_engine import PoCEngine


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


def test_pipeline_adds_safe_poc_without_claiming_reproduction():
    findings, manifest = FindingPipeline.process([make_finding()])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.poc_available is True
    assert finding.poc_status == "generated"
    assert finding.curl_poc
    assert "poc-reproduced" not in finding.evidence
    assert finding.verification_observed is False
    assert "verification guidance" not in finding.curl_poc.lower()
    assert finding.impact_status == "unconfirmed"
    assert finding.source_modules == ["xss"]
    assert finding.verification_status in {"medium-confidence", "high-confidence", "verified"}
    assert finding.risk_priority in {"P0", "P1", "P2", "P3"}
    assert manifest["final_findings"] == 1
    assert manifest["poc_generated"] == 1
    assert manifest["poc_reproduced"] == 0
    assert manifest["impact_confirmed"] == 0
    assert manifest["source_modules"]["xss"] == 1


def test_pipeline_filters_duplicates_and_merges_sources():
    first = make_finding()
    second = make_finding()
    second.source_modules = ["nuclei"]
    findings, manifest = FindingPipeline.process([first, second])
    assert len(findings) == 1
    assert manifest["duplicates_filtered"] == 1
    assert findings[0].source_modules == ["xss", "nuclei"]


def test_unverified_finding_does_not_get_a_poc():
    finding = make_finding()
    finding.verification_status = "unverified"
    finding.evidence = ""
    findings = PoCEngine.enrich([finding])
    assert findings[0].poc_available is False
    assert findings[0].poc_status == "not-generated"
    assert findings[0].curl_poc is None
    assert findings[0].verification_observed is False
