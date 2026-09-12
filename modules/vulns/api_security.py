"""Scope-safe API security checks.

The scanner only inspects the supplied endpoint and does not enumerate new
hosts or perform destructive API operations. Checks focus on observable API
security signals: API technology, unsafe methods, missing security headers,
and exposed documentation/schema endpoints when explicitly supplied.
"""
from __future__ import annotations

from urllib.parse import urlparse

from core.models import Vulnerability, Severity


class APISecurityScanner:
    _API_HINTS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/")
    _DOC_HINTS = ("/swagger", "/openapi", "/api-docs", "/redoc")

    def __init__(self, http_client):
        self.http_client = http_client

    async def scan(self, url: str) -> list[Vulnerability]:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if not any(token in path for token in self._API_HINTS + self._DOC_HINTS):
            return []

        response = await self.http_client.get(url)
        if not response:
            return []

        findings: list[Vulnerability] = []
        content_type = response.headers.get("content-type", "").lower()
        allow = response.headers.get("allow", "")

        if "application/json" in content_type or any(token in path for token in self._API_HINTS):
            if allow and any(method in allow.upper() for method in ("PUT", "DELETE", "PATCH")):
                findings.append(Vulnerability(
                    vuln_type="API Security",
                    url=url,
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    title="API exposes state-changing HTTP methods",
                    description="The endpoint advertises state-changing HTTP methods. Authorization and CSRF protections should be verified for each method.",
                    evidence=f"Allow header: {allow}",
                    exploitation="No state-changing request was issued by this check.",
                    remediation="Require explicit authorization for every state-changing method and enforce appropriate CSRF protection where browser credentials are used.",
                    method="OPTIONS",
                    cwe_id="CWE-862",
                    references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"]
                ))

        if any(token in path for token in self._DOC_HINTS) and response.status_code < 400:
            findings.append(Vulnerability(
                vuln_type="API Security",
                url=url,
                severity=Severity.LOW,
                cvss_score=3.1,
                title="API documentation endpoint exposed",
                description="An API documentation/schema endpoint is directly accessible. Public exposure is not necessarily a vulnerability, but sensitive internal routes and models should not be unintentionally disclosed.",
                evidence=f"HTTP status: {response.status_code}; content-type: {content_type or 'unknown'}",
                exploitation="No schema modification or privileged operation was attempted.",
                remediation="Review whether documentation should be public; remove secrets and internal-only endpoints from schemas and protect administrative documentation where required.",
                method="GET",
                cwe_id="CWE-200",
                references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"]
            ))

        return findings
