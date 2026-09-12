#!/usr/bin/env python3
"""BugScanner CLI v2.1 — authorized security testing only."""

import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.console import Console

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import BugScanner
from core.reporter import Reporter

console = Console()


def print_banner():
    console.print(
        "[bold cyan]BugScanner v2.1[/bold cyan]\n"
        "[dim]Recon & vulnerability assessment — authorized targets only[/dim]"
    )


def validate_target(url: str) -> str:
    """Normalize and validate a target URL before any network activity."""
    value = url.strip()
    if not value:
        raise click.BadParameter("Target cannot be empty")
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise click.BadParameter("Target must be a valid http(s) URL")
    if parsed.username or parsed.password:
        raise click.BadParameter("Credentials in target URLs are not supported")
    return value


def parse_cookies(cookie_list: tuple) -> dict:
    result = {}
    for c in cookie_list:
        if "=" in c:
            k, v = c.strip().split("=", 1)
            result[k.strip()] = v.strip()
        else:
            console.print(f"[yellow]⚠️ Cookie ignored:[/yellow] {c!r}")
    return result


def parse_headers(header_list: tuple) -> dict:
    result = {}
    for h in header_list:
        if ":" in h:
            k, v = h.strip().split(":", 1)
            result[k.strip()] = v.strip()
        else:
            console.print(f"[yellow]⚠️ Header ignored:[/yellow] {h!r}")
    return result


@click.group()
def cli():
    """BugScanner — authorized security testing tool."""


@cli.command()
@click.argument("url")
@click.option("--mode", "-m", type=click.Choice(["all", "recon", "vulns"]), default="all", show_default=True)
@click.option("--ports", "-p", type=click.Choice(["common", "extended", "full"]), default="common", show_default=True)
@click.option("--no-subdomains", is_flag=True)
@click.option("--output", "-o", default="./reports", show_default=True)
@click.option("--format", "-f", type=click.Choice(["all", "json", "html"]), default="all", show_default=True)
@click.option("--rps", type=click.FloatRange(min=0.1, max=1000), default=10.0, show_default=True)
@click.option("--cookie", "-c", multiple=True)
@click.option("--header", "-H", multiple=True)
@click.option("--proxy", default=None)
@click.option("--business-logic", is_flag=True)
@click.option("--no-fp-validation", is_flag=True)
def scan(url, mode, ports, no_subdomains, output, format, rps, cookie, header, proxy, business_logic, no_fp_validation):
    """Scan an explicitly authorized URL."""
    print_banner()
    target = validate_target(url)
    cookies = parse_cookies(cookie)
    headers = parse_headers(header)

    from core.scanner import load_config
    config = load_config()
    config["rate_limiting"]["default_rps"] = min(rps, config["rate_limiting"]["max_rps"])

    async def run():
        scanner = BugScanner(
            config=config,
            cookies=cookies,
            headers=headers,
            proxy=proxy,
            validate_fp=not no_fp_validation,
            run_business_logic=business_logic,
        )
        result = await scanner.scan(target, modes=[mode], port_mode=ports, skip_subdomains=no_subdomains)
        reporter = Reporter(output_dir=output)
        if format == "json":
            await reporter.save_json(result)
        elif format == "html":
            await reporter.save_html(result)
        else:
            await reporter.save_all(result)
        console.print(f"\n[bold green]✅ Scan completed[/bold green] Reports: {output}/")

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option("--ports", "-p", type=click.Choice(["common", "extended", "full"]), default="common")
@click.option("--no-subdomains", is_flag=True)
@click.option("--output", "-o", default="./reports")
def recon(url, ports, no_subdomains, output):
    """Run reconnaissance against an explicitly authorized URL."""
    target = validate_target(url)
    async def run():
        result = await BugScanner().scan(target, modes=["recon"], port_mode=ports, skip_subdomains=no_subdomains)
        await Reporter(output_dir=output).save_all(result)
    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option("--cookie", "-c", multiple=True)
@click.option("--header", "-H", multiple=True)
@click.option("--proxy", default=None)
@click.option("--output", "-o", default="./reports")
@click.option("--no-fp-validation", is_flag=True)
def vulnscan(url, cookie, header, proxy, output, no_fp_validation):
    """Run vulnerability checks against an explicitly authorized URL."""
    target = validate_target(url)
    async def run():
        result = await BugScanner(
            cookies=parse_cookies(cookie),
            headers=parse_headers(header),
            proxy=proxy,
            validate_fp=not no_fp_validation,
        ).scan(target, modes=["vulns"], skip_subdomains=True)
        await Reporter(output_dir=output).save_all(result)
    asyncio.run(run())


@cli.command()
def version():
    """Show version information."""
    console.print("[bold cyan]BugScanner[/bold cyan] v2.1")
    console.print("[dim]Authorized use only[/dim]")


if __name__ == "__main__":
    cli()
