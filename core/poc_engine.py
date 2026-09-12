"""Safe proof-of-concept generation for authorized vulnerability reporting."""

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
    """Build bounded reproduction material for findings already supported by evidence."""

    _SAFE_MARKER = "BUGSCANNER_POC"

    @staticmethod
    def _url_with_parameter(url: str, parameter: str | None, value: str) -> str:
        if not parameter:
            return url
        parts = urlsplit(url)
        pairs: list[tuple[str, str]] = []
        for item in parts.query.split("&") if parts.query else []:
            if "=" in item:
                key, original = item.split("=", 1)
                pairs.append((key, value if key == parameter else original))
            elif item:
                pairs.append((item, value if item == parameter else ""))
        if not any(key == parameter for key, _ in pairs):
            pairs.append((parameter, value))
        query = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

    @staticmethod
    def _evidence_backed(finding: Vulnerability) -> bool:
        """A generated PoC must be tied to an actual scanner observation."""
        evidence = (finding.evidence or "").strip().lower()
        return bool(evidence) and finding.verification_status not in {"unverified", "false-positive"}

    @classmethod
    def generate(cls, finding: Vulnerability) -> PoC:
        kind = finding.vuln_type.strip().lower()
        url = finding.url
        marker = cls._SAFE_MARKER
        if kind in {"xss", "cross-site scripting"}:
            probe = cls._url_with_parameter(url, finding.parameter, marker)
            return PoC("XSS safe verification", ("Replay only against the authorized target.", f"Place the benign marker {marker} in the reported parameter.", "Confirm reflection/context in the response or DOM; do not execute script."), f'curl -sk -i "{probe}"')
        if kind in {"sqli", "sql injection"}:
            probe = cls._url_with_parameter(url, finding.parameter, marker)
            return PoC("SQL injection safe verification", ("Replay the baseline request.", f"Replace only the reported parameter with the benign marker {marker}.", "Compare status, response size and application error behavior; do not run destructive SQL."), f'curl -sk -i "{probe}"')
        if kind == "ssrf":
            return PoC("SSRF safe callback verification", ("Replay only against an approved test endpoint.", "Use an organization-controlled callback URL.", "Confirm the callback event; do not access metadata or internal services."), f'curl -sk -i "{url}"')
        if kind in {"idor", "bola"}:
            return PoC("IDOR authorization verification", ("Replay with the authorized test identity.", "Change only the object identifier to another test-owned object.", "Confirm authorization behavior without accessing another user's data."), f'curl -sk -i "{url}"')
        if kind in {"information disclosure", "disclosure"}:
            return PoC("Information disclosure safe verification", ("Replay the request against the authorized target.", "Record HTTP status, content type and response size.", "Inspect only redacted/resource-specific evidence; never copy secrets into the report."), f'curl -sk -i "{url}"')
        return PoC(f"{finding.vuln_type} safe verification", ("Replay the reported request against the authorized target.", "Compare the observed response with the finding evidence.", "Stop after confirmation; do not perform destructive exploitation."), f'curl -sk -i "{url}"')

    @classmethod
    def enrich(cls, findings: list[Vulnerability]) -> list[Vulnerability]:
        for finding in findings:
            # No evidence => no PoC. This prevents generic curl commands from
            # making false positives look reproduced or actionable.
            if not cls._evidence_backed(finding):
                finding.poc_available = False
                finding.poc_status = "not-generated"
                finding.curl_poc = None
                finding.safe_verification = "Not generated: finding lacks sufficient scanner-observed evidence."
                continue

            poc = cls.generate(finding)
            if not finding.curl_poc:
                finding.curl_poc = poc.curl
            finding.poc_available = True
            finding.poc_status = "generated"
            finding.safe_verification = " ".join(poc.steps)
            finding.verification_observed = False
            if not finding.impact_status:
                finding.impact_status = "unconfirmed"
        return findings
