"""Deterministic provenance and source attribution for findings.

Provenance describes which BugScanner module logically owns a finding. It is
metadata only: it does not perform network requests or alter scanner scope.
"""

from __future__ import annotations

from core.models import Vulnerability


_TYPE_TO_MODULES: dict[str, tuple[str, ...]] = {
    "xss": ("xss",),
    "sqli": ("sqli",),
    "sql injection": ("sqli",),
    "ssrf": ("ssrf",),
    "idor": ("idor",),
    "bola": ("idor",),
    "cors": ("cors",),
    "open redirect": ("redirect",),
    "redirect": ("redirect",),
    "jwt": ("jwt",),
    "api security": ("api_security",),
    "information disclosure": ("disclosure",),
    "disclosure": ("disclosure",),
    "business logic": ("business_logic",),
    "nuclei": ("nuclei",),
}


class ProvenanceEngine:
    """Attach stable source-module attribution without inventing request evidence."""

    @classmethod
    def infer_modules(cls, finding: Vulnerability) -> tuple[str, ...]:
        modules = list(finding.source_modules)
        modules.extend(_TYPE_TO_MODULES.get(finding.vuln_type.strip().lower(), ()))
        return tuple(dict.fromkeys(module for module in modules if module))

    @classmethod
    def enrich(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        for finding in findings:
            finding.source_modules = list(cls.infer_modules(finding))
        return findings

    @staticmethod
    def merge_sources(winner: Vulnerability, other: Vulnerability) -> None:
        winner.source_modules = list(dict.fromkeys([*winner.source_modules, *other.source_modules]))
