"""Deterministic risk prioritization for authorized scan findings."""

from __future__ import annotations

from dataclasses import dataclass

from core.models import Severity, Vulnerability


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass(frozen=True)
class RiskScore:
    """Normalized priority score with explainable components."""

    score: float
    severity_weight: int
    cvss: float
    evidence_bonus: float


class RiskPrioritizer:
    """Rank findings without changing their technical severity."""

    @staticmethod
    def score(finding: Vulnerability) -> RiskScore:
        severity_weight = _SEVERITY_WEIGHT[finding.severity]
        cvss = max(0.0, min(10.0, float(finding.cvss_score)))
        evidence_bonus = 0.5 if finding.evidence.strip() else 0.0
        score = round((cvss * 0.75) + (severity_weight * 0.75) + evidence_bonus, 2)
        return RiskScore(score, severity_weight, cvss, evidence_bonus)

    @classmethod
    def prioritize(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        """Return findings ordered by risk, preserving input order for ties."""
        return sorted(
            findings,
            key=lambda finding: cls.score(finding).score,
            reverse=True,
        )
