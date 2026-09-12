"""
Ana Scanner Orchestrator — v2.0
WAF Detection + FP Validation + Business Logic + Auth
"""

import asyncio
import yaml
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.rate_limiter import AdaptiveRateLimiter
from core.http_client import HttpClient
from core.models import ScanResult
from core.waf_detector import WAFDetector
from core.validator import FalsePositiveValidator
from core.scope import ScopeError, ScopePolicy
from core.vulnerability_orchestrator import VulnerabilityOrchestrator
from core.adaptive_feedback import AdaptiveFeedbackEngine
from core.finding_pipeline import FindingPipeline

from modules.recon.subdomain import SubdomainScanner
from modules.recon.portscan import PortScanner
from modules.recon.fingerprint import TechFingerprinter
from modules.recon.discovery import DiscoveryScanner
from modules.vulns.xss import XSSScanner
from modules.vulns.cors import CORSScanner
from modules.vulns.disclosure import DisclosureScanner
from modules.vulns.sqli import SQLiScanner
from modules.vulns.ssrf import SSRFScanner
from modules.vulns.redirect import RedirectScanner
from modules.vulns.jwt import JWTScanner
from modules.vulns.idor import IDORScanner
from modules.vulns.api_security import APISecurityScanner
from modules.vulns.nuclei_wrapper import NucleiWrapper
from modules.vulns.business_logic import BusinessLogicScanner

console = Console()
CONFIG_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


class BugScanner:
    def __init__(self, config: dict = None, cookies: dict = None, headers: dict = None,
                 proxy: str = None, validate_fp: bool = True, run_business_logic: bool = False):
        self.config = config or load_config()
        self.cookies, self.headers, self.proxy = cookies or {}, headers or {}, proxy
        self.validate_fp = validate_fp
        self.run_business_logic = run_business_logic
        self.orchestrator = VulnerabilityOrchestrator()

        scope_cfg = self.config.get("scope", {})
        allowed_targets = scope_cfg.get("allowed_targets", []) or []
        self.scope_enforced = bool(allowed_targets)
        self.scope_policy = ScopePolicy.from_strings(
            allowed_targets, include_subdomains=bool(scope_cfg.get("include_subdomains", False))
        )
        rl, sc = self.config["rate_limiting"], self.config["scanning"]
        self.rate_limiter = AdaptiveRateLimiter(
            default_rps=rl["default_rps"], min_rps=rl["min_rps"], max_rps=rl["max_rps"],
            backoff_multiplier=rl["backoff_multiplier"], pause_on_503=rl["pause_on_503"]
        )
        self.http_config = {
            "timeout": sc["timeout"], "verify_ssl": sc["verify_ssl"], "user_agent": sc["user_agent"],
            "max_redirects": sc["max_redirects"], "cookies": self.cookies, "headers": self.headers, "proxy": self.proxy,
        }

    def _scope_allows(self, target: str) -> bool:
        if not self.scope_enforced:
            return True
        try:
            self.scope_policy.check(target)
            return True
        except ScopeError:
            return False

    def _require_scope(self, target: str) -> None:
        if self.scope_enforced:
            self.scope_policy.check(target)

    def _filter_in_scope_urls(self, urls: list[str]) -> list[str]:
        return [url for url in urls if self._scope_allows(url)]

    async def _scan_endpoint_with_plan(self, ep_url: str, scanners: dict) -> list:
        plan = self.orchestrator.plan(ep_url)
        selected = [scanners[name].scan(ep_url) for name in plan.tests if name in scanners]
        console.print(f"  [dim]{ep_url} → {', '.join(plan.tests)} (priority={plan.priority})[/dim]")
        if not selected:
            return []
        results = await asyncio.gather(*selected, return_exceptions=True)
        return [finding for item in results if isinstance(item, list) for finding in item]

    def _print_banner(self, target: str):
        auth = "[green]Authenticated[/green]" if self.cookies or self.headers else "[dim]Unauthenticated[/dim]"
        bl = "[green]ON[/green]" if self.run_business_logic else "[dim]OFF[/dim]"
        fp = "[green]ON[/green]" if self.validate_fp else "[dim]OFF[/dim]"
        scope = "[green]ENFORCED[/green]" if self.scope_enforced else "[dim]DISABLED (backward compatible)[/dim]"
        console.print(Panel.fit(
            f"[bold cyan]BugScanner[/bold cyan] [dim]v2.0[/dim]\n[bold]Target:[/bold] {target}\n"
            f"[bold]Auth:[/bold] {auth}\n[bold]Business Logic:[/bold] {bl}\n[bold]FP Validation:[/bold] {fp}\n"
            f"[bold]Scope:[/bold] {scope}\n[bold]Proxy:[/bold] {self.proxy or 'yoxdur'}\n"
            f"[bold]Time:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", border_style="cyan"
        ))

    def _print_summary(self, result: ScanResult):
        table = Table(title="📊 Scan Nəticəsi", box=box.ROUNDED, border_style="cyan")
        table.add_column("Kateqoriya", style="bold")
        table.add_column("Sayı", justify="right")
        for label, value in (("Subdomains", len(result.subdomains)), ("Açıq portlar", len(result.open_ports)),
                             ("Endpoints", len(result.endpoints)), ("Vulnerabilities", len(result.vulnerabilities)),
                             ("Duplicates filtered", result.duplicates_filtered), ("FP filtered", result.false_positives_filtered)):
            table.add_row(label, str(value))
        for sev, count in result.vuln_count_by_severity.items():
            if count > 0:
                table.add_row(sev.upper(), str(count))
        table.add_row("Risk Skoru", f"{result.risk_score}/10")
        console.print(table)

    async def _apply_waf_evasion(self, http: HttpClient, base_url: str) -> dict:
        """Detect WAF and reduce request pressure when defensive controls are observed."""
        console.print("\n[bold cyan]🛡️  WAF Detection...[/bold cyan]")
        waf_info = await WAFDetector(http).detect(base_url)
        if waf_info["waf"]:
            evasion = waf_info["evasion"]
            import tldextract
            from core.rate_limiter import TokenBucket
            ext = tldextract.extract(base_url)
            domain = f"{ext.domain}.{ext.suffix}"
            self.rate_limiter._buckets.clear()
            self.rate_limiter._buckets[domain] = TokenBucket(rps=float(evasion["rps"]))
            console.print(f"  [yellow]Back-pressure protection:[/yellow] RPS→{evasion['rps']}, delay→{evasion['delay']}s")
        return waf_info

    async def scan(self, target: str, modes: list[str] = None, port_mode: str = "common", skip_subdomains: bool = False) -> ScanResult:
        if modes is None or "all" in modes:
            modes = ["recon", "vulns"]
        self._require_scope(target)
        self._print_banner(target)
        result = ScanResult(target=target, manifest={"scanner_version": "2.1", "modes": list(modes), "modules_enabled": []})
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        import tldextract
        ext = tldextract.extract(base_url)
        domain = f"{ext.domain}.{ext.suffix}"

        async with HttpClient(self.rate_limiter, **self.http_config) as http:
            await self._apply_waf_evasion(http, base_url)
            if "recon" in modes:
                result.manifest["modules_enabled"].extend(["subdomain", "portscan", "fingerprint", "discovery"])
                console.print(Panel("[bold]RECON FAZA[/bold]", border_style="blue"))
                fp = TechFingerprinter(http)
                techs, header_vulns = await fp.fingerprint(base_url)
                result.technologies, result.vulnerabilities = techs, header_vulns
                if not skip_subdomains:
                    result.subdomains = await SubdomainScanner(http).scan(domain)
                    if self.scope_enforced:
                        result.subdomains = [s for s in result.subdomains if self._scope_allows(f"https://{s.subdomain}")]
                result.open_ports = await PortScanner().scan(domain, mode=port_mode)
                endpoints, disc_vulns = await DiscoveryScanner(http).scan(base_url)
                result.endpoints = self._filter_in_scope_urls(endpoints)
                result.vulnerabilities.extend(v for v in disc_vulns if self._scope_allows(v.url))

            if "vulns" in modes:
                result.manifest["modules_enabled"].extend(["xss", "sqli", "cors", "ssrf", "redirect", "jwt", "idor", "api_security", "disclosure"])
                xss, sqli, cors = XSSScanner(http), SQLiScanner(http), CORSScanner(http)
                ssrf, redirect, jwt = SSRFScanner(http), RedirectScanner(http), JWTScanner(http)
                idor, disc_sc, api_security = IDORScanner(http), DisclosureScanner(http), APISecurityScanner(http)
                for scanner in (disc_sc, cors, xss, sqli, ssrf, redirect, jwt, idor, api_security):
                    result.vulnerabilities.extend(await scanner.scan(base_url))

                scanners = {"xss": xss, "sqli": sqli, "cors": cors, "ssrf": ssrf, "redirect": redirect,
                            "idor": idor, "disclosure": disc_sc, "jwt": jwt, "api_security": api_security}
                plans = self.orchestrator.prioritize(result.endpoints, limit=15)
                for plan in AdaptiveFeedbackEngine.prioritize(plans, result.vulnerabilities, limit=15):
                    result.vulnerabilities.extend(await self._scan_endpoint_with_plan(plan.url, scanners))

                for sub in result.subdomains[:10]:
                    if sub.status and sub.status < 400:
                        sub_url = f"https://{sub.subdomain}"
                        if self._scope_allows(sub_url):
                            for items in await asyncio.gather(cors.scan(sub_url), disc_sc.scan(sub_url), return_exceptions=True):
                                if isinstance(items, list):
                                    sub.vulnerabilities.extend(items)
                                    result.vulnerabilities.extend(items)

                if self.run_business_logic:
                    result.manifest["modules_enabled"].append("business_logic")
                    result.vulnerabilities.extend(await BusinessLogicScanner(http).scan(base_url))
                result.manifest["modules_enabled"].append("nuclei")
                result.vulnerabilities.extend(await NucleiWrapper().scan(base_url))

                if self.validate_fp and result.vulnerabilities:
                    result.vulnerabilities = [v for v in result.vulnerabilities if self._scope_allows(v.url)]
                    confirmed, filtered = await FalsePositiveValidator(http).validate_all(result.vulnerabilities)
                    result.vulnerabilities, result.false_positives_filtered = confirmed, len(filtered)

        result.vulnerabilities, pipeline_manifest = FindingPipeline.process(result.vulnerabilities)
        result.duplicates_filtered = pipeline_manifest["duplicates_filtered"]
        result.manifest.update(pipeline_manifest)
        result.end_time = datetime.now()
        self._print_summary(result)
        return result
