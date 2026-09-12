"""Single auditable post-processing pipeline for scanner findings."""

from __future__ import annotations

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
        findings = RiskPrioritizer.prioritize(findings)
        verification = {}
        for finding in findings:
            verification[finding.verification_status] = verification.get(finding.verification_status, 0) + 1
        return findings, {
            "input_findings": before,
            "duplicates_filtered": duplicates,
            "final_findings": len(findings),
            "poc_available": sum(1 for f in findings if f.poc_available),
            "verification": verification,
            "priority": {p: sum(1 for f in findings if f.risk_priority == p) for p in ("P0", "P1", "P2", "P3")},
        }
