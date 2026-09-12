"""Information disclosure checks with resource-aware validation."""

import asyncio
import re
from urllib.parse import urljoin

from rich.console import Console

from core.models import Severity, Vulnerability

console = Console()

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".env.backup", ".env.example", "config.env", "env.txt",
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG", ".gitignore", ".gitconfig",
    "backup.sql", "backup.zip", "backup.tar.gz", "db_backup.sql", "database.sql", "dump.sql", "data.sql",
    "config.php", "config.yml", "config.yaml", "config.json", "configuration.php", "settings.php", "wp-config.php",
    "database.php", "db.php", "conn.php", "connection.php", "error.log", "access.log", "debug.log", "app.log",
    "logs/error.log", "var/log/error.log", "admin/", "administrator/", "phpmyadmin/", "adminer.php",
    "phpinfo.php", "info.php", "test.php", "debug.php", "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api/swagger", "api/docs", "api-docs", "api/schema", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "clientaccesspolicy.xml", "server-status", "server-info", "status", "package.json", "composer.json",
    "requirements.txt", "Gemfile", "yarn.lock", "package-lock.json", ".npmrc", ".travis.yml",
    ".github/workflows/", "Dockerfile", "docker-compose.yml", "Jenkinsfile", ".circleci/config.yml",
    "server.key", "private.key", "ssl.key", "certificate.pem",
]

SENSITIVE_PATTERNS = {
    "API Key (Generic)": (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', Severity.HIGH, 7.5),
    "AWS Access Key": (r'AKIA[0-9A-Z]{16}', Severity.CRITICAL, 9.0),
    "AWS Secret Key": (r'["\']?aws[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', Severity.CRITICAL, 9.0),
    "Private Key": (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', Severity.CRITICAL, 9.5),
    "Database Password": (r'(?:DB_PASS|DB_PASSWORD|DATABASE_PASSWORD)\s*=\s*(.+)', Severity.CRITICAL, 9.0),
    "GitHub Token": (r'ghp_[a-zA-Z0-9]{36}', Severity.HIGH, 8.0),
    "JWT Token": (r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}', Severity.MEDIUM, 6.0),
    "SendGrid API Key": (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', Severity.HIGH, 8.0),
    "Slack Token": (r'xox[baprs]-[a-zA-Z0-9\-]+', Severity.HIGH, 7.5),
    "Google API Key": (r'AIza[0-9A-Za-z\-_]{35}', Severity.HIGH, 7.5),
    "Stripe Key": (r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}', Severity.HIGH, 8.5),
}


class DisclosureScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    @staticmethod
    def _looks_like_spa_shell(content: str) -> bool:
        sample = content.lstrip().lower()[:4000]
        return "<!doctype html" in sample or "<html" in sample or "<body" in sample

    @classmethod
    def _matches_expected_resource(cls, path: str, content: str) -> bool:
        """Do not treat a generic login/index SPA shell as a sensitive file."""
        if not content or cls._looks_like_spa_shell(content):
            return False
        lower_path = path.lower()
        if lower_path.endswith((".env", ".env.local", ".env.production", ".env.backup", "config.env", "env.txt")):
            return bool(re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+", content))
        if lower_path.endswith(".git/head"):
            return bool(re.search(r"(?m)^\s*ref:\s*refs/", content))
        if lower_path.endswith(".git/config"):
            return "[core]" in content or "[remote \"" in content
        if lower_path.endswith(".sql"):
            return bool(re.search(r"(?i)\b(create|insert|update|delete|select|alter)\s+", content))
        if lower_path.endswith((".key", ".pem")) or "certificate" in lower_path:
            return "-----BEGIN " in content
        if "phpinfo" in lower_path:
            return "phpinfo" in content.lower() or "php version" in content.lower()
        if lower_path.endswith((".json", ".yaml", ".yml")):
            return content.lstrip().startswith(("{", "[")) or bool(re.search(r"(?m)^\s*[A-Za-z0-9_.-]+\s*:\s*\S+", content))
        return True

    @staticmethod
    def _response_metadata(response, content: str) -> tuple[str, int]:
        headers = getattr(response, "headers", {}) or {}
        content_type = str(headers.get("content-type", ""))
        content_length = len(content.encode("utf-8", errors="replace"))
        try:
            if headers.get("content-length"):
                content_length = int(headers["content-length"])
        except (TypeError, ValueError):
            pass
        return content_type, content_length

    def _check_content(self, content: str, url: str) -> list[Vulnerability]:
        vulns = []
        for name, (pattern, severity, cvss) in SENSITIVE_PATTERNS.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if not match:
                continue
            found = match.group(0)
            redacted = found[:8] + "***" if len(found) > 8 else "***"
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure", url=url, severity=severity, cvss_score=cvss,
                title=f"Sensitive Data Exposure — {name}",
                description=f"Response-da {name} pattern-i aşkar edildi.",
                evidence=f"Sensitive pattern detected (redacted): {redacted}",
                exploitation="Replay the reported request against the authorized target and inspect only redacted response evidence.",
                remediation="Revoke exposed credentials, remove sensitive files from the web root, and use secret management.",
                cwe_id="CWE-200", references=["https://owasp.org/www-project-top-ten/"],
            ))
        return vulns

    async def _check_path(self, base_url: str, path: str) -> list[Vulnerability]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = await self.http_client.get(url)
        if not response or response.status_code not in [200, 206]:
            return []

        content = response.text or ""
        content_type, content_length = self._response_metadata(response, content)
        vulns = []

        if "Index of /" in content or "Directory listing" in content.lower():
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure", url=url, severity=Severity.MEDIUM, cvss_score=5.3,
                title="Directory Listing Enabled", description="Web server directory listing-i aktiv edir.",
                evidence=f"'{path}' üçün directory listing cavabı alındı", exploitation=f'curl -i "{url}"',
                remediation="Disable directory indexing.", cwe_id="CWE-548",
            ))

        if ".git" in path and "ref:" in content:
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure", url=url, severity=Severity.HIGH, cvss_score=7.5,
                title=".git Directory Exposed", description=".git/HEAD returned a Git reference.",
                evidence=".git/HEAD returned a Git reference marker (content redacted).",
                exploitation="Replay the request against the authorized target and confirm the response; do not download repository history.",
                remediation="Block public access to .git paths.", curl_poc=f'curl -i "{url}"', cwe_id="CWE-538",
            ))

        if self._matches_expected_resource(path, content):
            vulns.extend(self._check_content(content, url))

        # Crucial: HTTP 200 alone is not proof. Only report a sensitive file when
        # its body matches the expected resource instead of the site's SPA shell.
        if not vulns and response.status_code == 200 and self._matches_expected_resource(path, content):
            sensitive_markers = (".env", ".sql", ".key", ".pem", "phpinfo", ".git/", "config.php", "config.yml", "config.yaml", "config.json")
            if any(marker in path.lower() for marker in sensitive_markers):
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure", url=url, severity=Severity.HIGH, cvss_score=7.2,
                    title=f"Sensitive File Accessible — {path}",
                    description=f"'{path}' returned resource-specific content over HTTP.",
                    evidence=f"HTTP {response.status_code}; content-type: {content_type or 'unknown'}; response size: {content_length} bytes; resource-specific content matched.",
                    exploitation="Replay with headers and inspect only redacted evidence; do not save or disclose sensitive values.",
                    remediation="Remove the file from the web root and block access to sensitive configuration paths.",
                    curl_poc=f'curl -i "{url}"', cwe_id="CWE-538",
                ))

        for vuln in vulns:
            console.print(f"  {vuln.severity.emoji} [bold]Disclosure:[/bold] {vuln.title} @ {path}")
        return vulns

    async def scan(self, base_url: str) -> list[Vulnerability]:
        console.print(f"  [dim]Info disclosure skan: {len(SENSITIVE_PATHS)} path...[/dim]")
        semaphore = asyncio.Semaphore(20)

        async def check_with_sem(path):
            async with semaphore:
                return await self._check_path(base_url, path)

        results = await asyncio.gather(*[check_with_sem(p) for p in SENSITIVE_PATHS], return_exceptions=True)
        return [item for result in results if isinstance(result, list) for item in result]
