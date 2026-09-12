"""
IDOR — Insecure Direct Object Reference Scanner
Evidence-backed detection only.
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

IDOR_PARAM_HINTS = [
    "id", "user_id", "userid", "uid", "account", "account_id",
    "order", "order_id", "invoice", "invoice_id", "file", "file_id",
    "doc", "document", "document_id", "record", "record_id",
    "profile", "profile_id", "customer", "customer_id",
    "ticket", "ticket_id", "report", "report_id", "msg", "message_id",
    "pid", "cid", "rid", "num", "number", "ref", "reference",
]

HTML_SHELL_MARKERS = ("<!doctype html", "<html", "<body")


class IDORScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_idor_params(self, url: str) -> list[tuple[str, str]]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        result = []
        for k, v in params.items():
            if any(hint in k.lower() for hint in IDOR_PARAM_HINTS):
                result.append((k, v[0]))
            elif v and re.match(r'^\d+$', v[0]):
                result.append((k, v[0]))
        return result

    def _extract_path_ids(self, url: str) -> list[tuple[int, str, str]]:
        parsed = urlparse(url)
        path = parsed.path
        results = []
        for match in re.finditer(r'/(\d+)(?=/|$)', path):
            results.append((match.start(), match.group(1), "numeric"))
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        for match in re.finditer(uuid_pattern, path, re.IGNORECASE):
            results.append((match.start(), match.group(0), "uuid"))
        return results

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _inject_path_id(self, url: str, original_id: str, new_id: str) -> str:
        parsed = urlparse(url)
        new_path = parsed.path.replace(f"/{original_id}", f"/{new_id}", 1)
        return urlunparse(parsed._replace(path=new_path))

    def _generate_test_ids(self, original: str, id_type: str) -> list[str]:
        if id_type == "numeric":
            orig_int = int(original)
            candidates = [str(orig_int + delta) for delta in [-1, 1, -2, 2, 10, -10, 100] if orig_int + delta > 0]
            candidates.extend(x for x in ["1", "2", "0"] if x != original)
            return candidates
        if id_type == "uuid":
            variants = []
            for i in [-1, -2, -3]:
                c = "0" if original[i] != "0" else "1"
                variants.append(original[:i] + c + original[i + 1:])
            return variants
        return []

    def _is_html_shell(self, response) -> bool:
        if not response:
            return True
        content_type = str(getattr(response, "headers", {}).get("content-type", "")).lower()
        text = str(getattr(response, "text", "") or "").lstrip().lower()
        return "text/html" in content_type or any(marker in text[:2000] for marker in HTML_SHELL_MARKERS)

    def _looks_like_structured_resource(self, response) -> bool:
        if not response or self._is_html_shell(response):
            return False
        content_type = str(getattr(response, "headers", {}).get("content-type", "")).lower()
        text = str(getattr(response, "text", "") or "").strip()
        if "json" in content_type or text.startswith(("{", "[")):
            return len(text) >= 20
        if "xml" in content_type or text.startswith("<?xml"):
            return len(text) >= 20
        return False

    def _compare_responses(self, original_resp, test_resp, original_id: str, test_id: str) -> bool:
        """Only flag a candidate when both responses look like real structured resources.
        A generic HTML/login/SPA response is never evidence of IDOR.
        """
        if not original_resp or not test_resp:
            return False
        if original_resp.status_code != 200 or test_resp.status_code != 200:
            return False
        if not self._looks_like_structured_resource(original_resp):
            return False
        if not self._looks_like_structured_resource(test_resp):
            return False
        if test_resp.text == original_resp.text:
            return False
        if len(test_resp.text) < 20:
            return False
        if original_id in test_resp.text and test_id not in test_resp.text:
            return False
        return True

    async def _test_param_idor(self, url: str, param: str, original_value: str) -> Vulnerability | None:
        original_resp = await self.http_client.get(url)
        if not original_resp or original_resp.status_code != 200:
            return None
        id_type = "numeric" if re.match(r'^\d+$', original_value) else "uuid"
        for test_id in self._generate_test_ids(original_value, id_type):
            test_url = self._inject_param(url, param, test_id)
            test_resp = await self.http_client.get(test_url)
            if self._compare_responses(original_resp, test_resp, original_value, test_id):
                return Vulnerability(
                    vuln_type="IDOR", url=test_url, severity=Severity.HIGH, cvss_score=8.1,
                    title=f"Potential IDOR — '{param}' parameter",
                    description=f"Changing '{param}' from {original_value} to {test_id} returned a different structured resource; authorization requires manual confirmation.",
                    evidence=(f"Original: {param}={original_value} → {original_resp.status_code}; "
                              f"Modified: {param}={test_id} → {test_resp.status_code}; "
                              f"structured response changed ({len(test_resp.text)} bytes)"),
                    exploitation="Safe verification: use two authorized test identities and two test-owned objects. Change only the object identifier and confirm ownership enforcement without accessing another user's data.",
                    remediation="Enforce server-side authorization and object ownership for every resource access.",
                    parameter=param, payload_used=f"{param}={test_id}",
                    curl_poc=f'curl -s "{test_url}"', cwe_id="CWE-639",
                    references=["https://portswigger.net/web-security/access-control/idor", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
                )
        return None

    async def _test_path_idor(self, url: str) -> list[Vulnerability]:
        vulns = []
        path_ids = self._extract_path_ids(url)
        if not path_ids:
            return vulns
        original_resp = await self.http_client.get(url)
        if not original_resp or original_resp.status_code != 200:
            return vulns
        for _, original_id, id_type in path_ids:
            for test_id in self._generate_test_ids(original_id, id_type):
                test_url = self._inject_path_id(url, original_id, test_id)
                test_resp = await self.http_client.get(test_url)
                if self._compare_responses(original_resp, test_resp, original_id, test_id):
                    vulns.append(Vulnerability(
                        vuln_type="IDOR", url=test_url, severity=Severity.HIGH, cvss_score=8.1,
                        title=f"Potential IDOR — path ID ({original_id} → {test_id})",
                        description="Changing a path object identifier returned a different structured resource; authorization requires manual confirmation.",
                        evidence=f"Original: {original_resp.status_code}; Modified: {test_resp.status_code}; structured response changed ({len(test_resp.text)} bytes)",
                        exploitation="Safe verification: compare only two test-owned objects under authorized identities and confirm ownership enforcement.",
                        remediation="Enforce server-side authorization and object ownership for every path resource.",
                        payload_used=f"path: {original_id} → {test_id}", curl_poc=f'curl -s "{test_url}"', cwe_id="CWE-639",
                    ))
                    break
        return vulns

    async def _test_http_method(self, url: str) -> list[Vulnerability]:
        """Method acceptance is not IDOR evidence. Do not report it as a vulnerability
        unless a safe, observable authorization/behavior change is demonstrated.
        """
        return []

    async def scan(self, url: str) -> list[Vulnerability]:
        console.print(f"  [dim]IDOR scan: {url[:60]}[/dim]")
        vulns = []
        idor_params = self._extract_idor_params(url)
        if idor_params:
            results = await asyncio.gather(
                *[self._test_param_idor(url, param, value) for param, value in idor_params],
                return_exceptions=True,
            )
            vulns.extend(r for r in results if isinstance(r, Vulnerability))
        vulns.extend(await self._test_path_idor(url))
        return vulns
