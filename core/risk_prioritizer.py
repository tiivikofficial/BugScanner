"""Deterministic risk prioritization for authorized scan findings."""

from __future__ import annotations

from dataclasses import dataclass

from core.models import Severity, Vulnerability


_SEVERITY_WEIGHT = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}


@dataclass(frozen=True)
class RiskScore:
    score: float
    severity_weight: int
    cvss: float
    evidence_bonus: float


class RiskPrioritizer:
    """Rank findings using severity, CVSS and evidence strength."""

    @staticmethod
    def score(finding: Vulnerability) -> RiskScore:
        severity_weight = _SEVERITY_WEIGHT[finding.severity]
        cvss = max(0.0, min(10.0, float(finding.cvss_score)))
        evidence_bonus = min(1.5, max(0.0, finding.confidence) * 1.5)
        score = round((cvss * 0.70) + (severity_weight * 0.70) + evidence_bonus, 2)
        return RiskScore(score, severity_weight, cvss, evidence_bonus)

    @staticmethod
    def _priority(finding: Vulnerability, score: float) -> str:
        if finding.severity is Severity.CRITICAL or score >= 10.0: return "P0"
        if finding.severity is Severity.HIGH or score >= 8.0: return "P1"
        if finding.severity is Severity.MEDIUM or score >= 5.0: return "P2"
        return "P3"

    @classmethod
    def prioritize(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        for finding in findings:
            finding.risk_priority = cls._priority(finding, cls.score(finding).score)
        return sorted(findings, key=lambda finding: cls.score(finding).score, reverse=True)
