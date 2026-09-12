"""Safe proof-of-concept generation for authorized vulnerability reporting.

This module produces non-destructive, human-reviewable reproduction material from
findings that already exist in the current scan. It does not execute exploits,
perform credential theft, bypass controls, access cloud metadata, or expand scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

from core.models import Vulnerability


@dataclass(frozen=True)
class PoC:
    title: str
    steps: tuple[str, ...]
    curl: str
    safety: str = "non-destructive; manual review required"


class PoCEngine:
    """Build bounded reproduction material for already-detected findings."""

    _SAFE_MARKER = "BUGSCANNER_POC"

    @staticmethod
    def _url_with_parameter(url: str, parameter: str | None, value: str) -> str:
        if not parameter:
            return url
        parts = urlsplit(url)
        pairs = []
        for item in parts.query.split("&") if parts.query else []:
            if "=" in item:
                key, _ = item.split("=", 1)
                pairs.append((key, value if key == parameter else _))
            elif item == parameter:
                pairs.append((item, value))
        if not any(key == parameter for key, _ in pairs):
            pairs.append((parameter, value))
        query = "&".join(f"{quote(k, safe='')}={quote(v, safe='') }" for k, v in pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

    @classmethod
    def generate(cls, finding: Vulnerability) -> PoC:
        """Return a non-destructive reproduction recipe for a finding."""
        kind = finding.vuln_type.strip().lower()
        url = finding.url
        marker = cls._SAFE_MARKER

        if kind in {"xss", "cross-site scripting"}:
            probe = cls._url_with_parameter(url, finding.parameter, marker)
            steps = (
                "Replay the request against the authorized target.",
                f"Use the benign marker {marker} in the reported parameter.",
                "Confirm reflection/context using the response body or DOM; do not execute active script.",
            )
            return PoC("XSS reflection PoC", steps, f'curl -sk -i "{probe}"')

        if kind in {"sqli", "sql injection"}:
            probe = cls._url_with_parameter(url, finding.parameter, marker)
            steps = (
                "Replay the baseline request.",
                f"Replace only the reported parameter with the benign marker {marker}.",
                "Compare status, response size, and application error behavior; do not run destructive SQL.",
            )
            return PoC("SQL injection verification PoC", steps, f'curl -sk -i "{probe}"')

        if kind == "ssrf":
            steps = (
                "Replay the reported request only on an approved test endpoint.",
                "Use a collaborator or organization-controlled callback URL for confirmation.",
                "Confirm the callback event and stop; do not request cloud metadata or internal services.",
            )
            return PoC("SSRF callback PoC", steps, f'curl -sk -i "{url}"')

        if kind == "idor":
            steps = (
                "Replay the request with the original authorized test identity.",
                "Change only the reported object identifier to another test-owned identifier.",
                "Confirm whether authorization changes while keeping both objects inside the approved test dataset.",
            )
            return PoC("IDOR authorization PoC", steps, f'curl -sk -i "{url}"')

        return PoC(
            f"{finding.vuln_type} reproduction PoC",
            ("Replay the reported request against the authorized target.", "Compare the observed evidence with the finding."),
            f'curl -sk -i "{url}"',
        )

    @classmethod
    def enrich(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        """Attach reproducible PoC text without issuing any network requests."""
        for finding in findings:
            poc = cls.generate(finding)
            if not finding.curl_poc:
                finding.curl_poc = poc.curl
            if not finding.exploitation:
                finding.exploitation = "\n".join((poc.title, *poc.steps, f"Safety: {poc.safety}"))
        return findings
