"""Single auditable post-processing pipeline for scanner findings.

The pipeline is offline: it processes evidence already collected by scanner
modules and never expands scope or executes exploits.
"""

from __future__ import annotations

from collections import Counter

from core.finding_deduplicator import FindingDeduplicator
from core.poc_engine import PoCEngine
from core.risk_prioritizer import RiskPrioritizer
from core.verification_engine import VerificationEngine
from core.models import Vulnerability


class FindingPipeline:
    """Normalize, generate safe reproduction material, verify and prioritize."""

    @classmethod
    def process(cls, findings: list[Vulnerability]) -> tuple[list[Vulnerability], dict]:
        before = len(findings)
        findings = FindingDeduplicator.deduplicate(findings)
        duplicates = before - len(findings)

        findings = PoCEngine.enrich(findings)
        findings = VerificationEngine.enrich(findings)
        findings = PoCEngine.enrich(findings)
        findings = RiskPrioritizer.prioritize(findings)

        return findings, {
            "input_findings": before,
            "duplicates_filtered": duplicates,
            "final_findings": len(findings),
            "poc_available": sum(1 for f in findings if f.poc_available),
            "verification": dict(Counter(f.verification_status for f in findings)),
            "exploitability": dict(Counter(f.exploitability for f in findings)),
            "impact": dict(Counter(f.impact_status for f in findings)),
            "priority": dict(Counter(f.risk_priority for f in findings)),
            "severity": dict(Counter(f.severity.value for f in findings)),
        }
