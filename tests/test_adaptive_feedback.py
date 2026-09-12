from core.adaptive_feedback import AdaptiveFeedbackEngine
from core.models import Vulnerability
from core.vulnerability_orchestrator import VulnerabilityOrchestrator


def _finding(vuln_type: str, status: str = "verified") -> Vulnerability:
    finding = Vulnerability(
        vuln_type=vuln_type,
        url="https://example.com/api/search?q=test",
        severity="high",
        evidence="confirmed evidence",
    )
    finding.verification_status = status
    return finding


def test_feedback_boosts_related_test_family():
    orchestrator = VulnerabilityOrchestrator()
    plans = orchestrator.prioritize(
        [
            "https://example.com/api/search?q=test",
            "https://example.com/home",
        ]
    )
    findings = [_finding("xss")]

    adjusted = AdaptiveFeedbackEngine.prioritize(plans, findings)

    search = next(plan for plan in adjusted if "api/search" in plan.url)
    assert search.priority == 10
    assert any("current-scan evidence" in reason for reason in search.reasons)


def test_low_confidence_findings_do_not_create_feedback_signal():
    finding = _finding("xss", status="low-confidence")
    assert AdaptiveFeedbackEngine.build_signal([finding]) == {}
