"""Evidence-based confidence scoring for vulnerability findings.

The engine is deliberately deterministic and conservative. It scores the
quality of evidence already collected by scanners; it does not perform new
network requests, generate stealth payloads, or expand scan scope.
"""

from __future__ import annotations

from collections import defaultdict

from core.models import Vulnerability


class EvidenceEngine:
    """Assign auditable confidence levels from existing finding evidence."""

    _STATUS = (
        (0.85, "verified"),
        (0.65, "high-confidence"),
        (0.40, "medium-confidence"),
        (0.0, "low-confidence"),
    )

    @classmethod
    def score(cls, finding: Vulnerability) -> float:
        score = 0.0
        if finding.evidence.strip():
            score += 0.35
        if finding.payload_used:
            score += 0.15
        if finding.curl_poc:
            score += 0.10
        if finding.exploitation.strip():
            score += 0.10
        if finding.parameter:
            score += 0.05
        if finding.references:
            score += 0.05
        score += min(finding.independent_confirmations * 0.10, 0.20)
        return round(min(score, 1.0), 2)

    @classmethod
    def classify(cls, score: float) -> str:
        for threshold, status in cls._STATUS:
            if score >= threshold:
                return status
        return "low-confidence"

    @classmethod
    def enrich(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        """Merge duplicate evidence counts and assign confidence metadata."""
        groups: dict[tuple[str, str, str, str], list[Vulnerability]] = defaultdict(list)
        for finding in findings:
            key = (
                finding.vuln_type.strip().lower(),
                finding.url.strip().lower(),
                (finding.parameter or "").strip().lower(),
                (finding.method or "GET").strip().upper(),
            )
            groups[key].append(finding)

        for group in groups.values():
            confirmations = max(0, len(group) - 1)
            for finding in group:
                finding.independent_confirmations = max(
                    finding.independent_confirmations,
                    confirmations,
                )
                finding.evidence_quality = cls.score(finding)
                finding.confidence = finding.evidence_quality
                finding.verification_status = cls.classify(finding.confidence)

        return findings
