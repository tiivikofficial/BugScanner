"""
SSRF Scanner — Server-Side Request Forgery
Evidence-backed detection only; HTTP 200/reflection alone is not SSRF proof.
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

INTERNAL_PATTERNS = [
    r"169\.254\.\d+\.\d+",
    r"10\.\d+\.\d+\.\d+",
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
    r"192\.168\.\d+\.\d+",
    r"127\.\d+\.\d+\.\d+",
    r"0\.0\.0\.0",
    r"::1",
    r"localhost",
]

SSRF_PARAM_HINTS = [
    "url", "uri", "link", "src", "source", "href", "redirect",
    "path", "file", "page", "fetch", "load", "proxy", "target",
    "dest", "destination", "to", "out", "image", "img", "callback",
    "host", "endpoint", "request", "data", "feed", "domain",
]

# These are probe values only. A response is reportable only when it contains
# evidence that the server actually fetched an internal resource.
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://localtest.me/",
]

AWS_METADATA_INDICATORS = [
    "ami-id", "instance-id", "instance-type",
    "local-hostname", "public-hostname", "iam",
    "security-credentials",
]


class SSRFScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def _is_ssrf_prone_param(self, param: str) -> bool:
        param_lower = param.lower()
        return any(hint in param_lower for hint in SSRF_PARAM_HINTS)

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _check_internal_response(self, text: str) -> str | None:
        lowered = text.lower()
        for indicator in AWS_METADATA_INDICATORS:
            if indicator in lowered:
                return f"AWS metadata indicator observed: '{indicator}'"
        if re.search(r"root:.*:0:0:", text):
            return "Linux /etc/passwd content observed"
        if "for 16-bit app support" in lowered:
            return "Windows win.ini content observed"
        for pattern in INTERNAL_PATTERNS:
            if re.search(pattern, text):
                return f"Internal resource indicator observed: {pattern}"
        return None

    async def _test_param(self, url: str, param: str) -> list[Vulnerability]:
        vulns = []
        for payload in SSRF_PAYLOADS:
            test_url = self._inject(url, param, payload)
            response = await self.http_client.get(test_url)
            if not response:
                continue

            indicator = self._check_internal_response(response.text)

            # A 200 response, reflected payload, response length, or response
            # speed is not evidence of server-side fetching. Require an
            # observable internal-resource indicator before creating a finding.
            if not indicator:
                continue

            is_cloud_metadata = "169.254" in payload or "metadata" in payload
            vuln = Vulnerability(
                vuln_type="SSRF",
                url=test_url,
                severity=Severity.CRITICAL if is_cloud_metadata else Severity.HIGH,
                cvss_score=9.8 if is_cloud_metadata else 8.6,
                title=f"SSRF — {param} parametri [{payload[:40]}]",
                description=(
                    f"The response contains an indicator consistent with server-side retrieval "
                    f"of an internal resource through '{param}'."
                ),
                evidence=(
                    f"Observed response evidence: {indicator}; "
                    f"HTTP {response.status_code}; response length={len(response.text)}"
                ),
                exploitation=(
                    "Safe verification: repeat only with an organization-controlled callback "
                    "or test-owned endpoint and confirm the callback event. Do not access cloud "
                    "metadata, credentials, or other internal services."
                ),
                remediation=(
                    "1. Enforce an allowlist for outbound destinations.\n"
                    "2. Block requests to private, loopback and link-local ranges.\n"
                    "3. Validate the resolved destination after DNS resolution.\n"
                    "4. Apply network egress controls and cloud metadata protections."
                ),
                parameter=param,
                payload_used=payload,
                curl_poc=f'curl -s "{test_url}"',
                cwe_id="CWE-918",
                references=[
                    "https://portswigger.net/web-security/ssrf",
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                ],
            )
            vulns.append(vuln)
            console.print(f"  {vuln.severity.emoji} [bold red]SSRF:[/bold red] {param} → {payload[:50]}")
            break
        return vulns

    async def scan(self, url: str) -> list[Vulnerability]:
        params = self._extract_params(url)
        ssrf_params = [p for p in params if self._is_ssrf_prone_param(p)]
        if not ssrf_params and len(params) <= 5:
            ssrf_params = params
        if not ssrf_params:
            return []

        console.print(f"  [dim]SSRF skan: {len(ssrf_params)} parametr — {url[:60]}[/dim]")
        results = await asyncio.gather(
            *[self._test_param(url, p) for p in ssrf_params],
            return_exceptions=True,
        )
        return [finding for items in results if isinstance(items, list) for finding in items]
