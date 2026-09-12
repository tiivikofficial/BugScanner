"""Deterministic finding deduplication for scan reporting.

Deduplication is intentionally conservative: findings are considered the same
only when their vulnerability type, normalized URL, parameter, and method
match. Distinct evidence and provenance are merged without changing finding
semantics.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from core.models import Vulnerability
from core.provenance import ProvenanceEngine


class FindingDeduplicator:
    """Collapse exact logical duplicates while preserving strongest evidence."""

    @staticmethod
    def normalize_url(value: str) -> str:
        parsed = urlparse(value.strip())
        if not parsed.scheme or not parsed.hostname:
            return value.strip().lower()
        host = parsed.hostname.lower().rstrip(".")
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, ""))

    @classmethod
    def fingerprint(cls, finding: Vulnerability) -> tuple[str, str, str, str]:
        return (
            finding.vuln_type.strip().lower(),
            cls.normalize_url(finding.url),
            (finding.parameter or "").strip().lower(),
            (finding.method or "GET").strip().upper(),
        )

    @classmethod
    def deduplicate(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        unique: dict[tuple[str, str, str, str], Vulnerability] = {}
        for finding in findings:
            ProvenanceEngine.enrich([finding])
            key = cls.fingerprint(finding)
            current = unique.get(key)
            if current is None:
                unique[key] = finding
                continue
            if finding.cvss_score > current.cvss_score:
                winner, other = finding, current
            else:
                winner, other = current, finding
            if other.evidence and other.evidence != winner.evidence:
                evidence = winner.evidence.strip()
                extra = other.evidence.strip()
                if extra not in evidence:
                    winner.evidence = f"{evidence}\n{extra}" if evidence else extra
            ProvenanceEngine.merge_sources(winner, other)
            unique[key] = winner
        return list(unique.values())
