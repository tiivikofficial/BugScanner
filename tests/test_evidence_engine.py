from core.evidence_engine import EvidenceEngine
from core.models import Severity, Vulnerability


def make_finding(**kwargs):
    values = {
        "vuln_type": "xss",
        "url": "https://example.com/search?q=test",
        "severity": Severity.MEDIUM,
        "cvss_score": 6.1,
        "title": "Potential XSS",
        "description": "test",
        "evidence": "reflected marker",
        "exploitation": "marker reflected in response",
        "remediation": "encode output",
        "parameter": "q",
        "payload_used": "test-marker",
        "curl_poc": "curl example",
        "references": ["https://owasp.org/"],
    }
    values.update(kwargs)
    return Vulnerability(**values)


def test_evidence_engine_marks_strong_finding_verified():
    finding = make_finding(independent_confirmations=2)
    EvidenceEngine.enrich([finding])

    assert finding.confidence >= 0.85
    assert finding.verification_status == "verified"


def test_evidence_engine_keeps_sparse_finding_low_confidence():
    finding = make_finding(
        evidence="",
        exploitation="",
        payload_used=None,
        curl_poc=None,
        parameter=None,
        references=[],
    )
    EvidenceEngine.enrich([finding])

    assert finding.confidence < 0.40
    assert finding.verification_status == "low-confidence"
