"""Conservative verification and evidence normalization.

This layer does not expand scope or execute exploitation. It evaluates evidence
already collected by scanners and looks for corroboration from distinct
signals (payload, response marker, timing/error evidence, and scanner family).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from core.models import Vulnerability


@dataclass(frozen=True)
class VerificationResult:
    confidence: float
    status: str
    signals: tuple[str, ...]
    independent_confirmations: int


class VerificationEngine:
    """Turn raw findings into conservative, auditable verification metadata."""

    _THRESHOLDS = ((0.90, "verified"), (0.75, "high-confidence"), (0.50, "medium-confidence"), (0.0, "low-confidence"))
    _ERROR_MARKERS = re.compile(r"sql|syntax|exception|stack trace|traceback|database|oracle|mysql|postgres|mssql", re.I)

    @classmethod
    def _signals(cls, finding: Vulnerability) -> list[str]:
        signals: list[str] = []
        evidence = finding.evidence or ""
        if evidence.strip():
            signals.append("response-evidence")
        if finding.payload_used:
            signals.append("controlled-payload")
        if finding.parameter:
            signals.append("parameter-correlation")
        if finding.curl_poc:
            signals.append("reproducible-poc")
        if finding.exploitation:
            signals.append("impact-evidence")
        if finding.references:
            signals.append("taxonomy-reference")
        if cls._ERROR_MARKERS.search(evidence):
            signals.append("server-error-correlation")
        return signals

    @classmethod
    def verify(cls, finding: Vulnerability, peer_findings: list[Vulnerability] | None = None) -> VerificationResult:
        signals = cls._signals(finding)
        score = min(0.80, 0.20 * len(set(signals)))

        peers = peer_findings or []
        # Corroboration must come from a distinct finding shape, not duplicate copies.
        corroborating = {
            (p.vuln_type.lower(), (p.parameter or "").lower(), (p.method or "GET").upper(), p.evidence[:120])
            for p in peers
            if p is not finding
        }
        confirmations = min(2, len(corroborating))
        score += confirmations * 0.10
        score = round(min(score, 1.0), 2)

        for threshold, status in cls._THRESHOLDS:
            if score >= threshold:
                return VerificationResult(score, status, tuple(dict.fromkeys(signals)), confirmations)
        return VerificationResult(score, "low-confidence", tuple(dict.fromkeys(signals)), confirmations)

    @classmethod
    def enrich(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        groups: dict[tuple[str, str, str], list[Vulnerability]] = defaultdict(list)
        for finding in findings:
            groups[(finding.vuln_type.lower(), finding.url.lower(), (finding.parameter or "").lower())].append(finding)

        for group in groups.values():
            for finding in group:
                result = cls.verify(finding, group)
                finding.evidence_quality = result.confidence
                finding.confidence = result.confidence
                finding.verification_status = result.status
                finding.independent_confirmations = max(
                    finding.independent_confirmations,
                    result.independent_confirmations,
                )
                if result.signals:
                    marker = "Verification signals: " + ", ".join(result.signals)
                    finding.evidence = f"{finding.evidence}\n{marker}".strip()
        return findings
