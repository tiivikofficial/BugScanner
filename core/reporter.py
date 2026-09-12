"""
Reporter — JSON və HTML report generasiyası
"""

import asyncio
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import aiofiles
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from markupsafe import Markup, escape
from rich.console import Console

from core.models import ScanResult

console = Console()

TEMPLATE_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR = Path("./reports")

# Windows forbids these characters in file/directory names. Keeping the list
# platform-independent also makes generated report names portable.
_INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_MAX_FILENAME_STEM = 140


def format_dt(dt) -> str:
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt)[:19].replace("T", " ")


def safe_text(value) -> Markup:
    """HTML escape et amma newline-ları <br>-ə çevir"""
    if value is None:
        return Markup("")
    return Markup(str(escape(str(value))).replace("\n", "<br>"))


def safe_code(value) -> Markup:
    """Kod blokları üçün — escape et, newline saxla"""
    if value is None:
        return Markup("")
    return Markup(str(escape(str(value))))


def _safe_filename_stem(value: str) -> str:
    """Return a filesystem-safe, deterministic filename stem.

    URLs frequently contain query strings such as ``?ReturnUrl=...`` and
    percent-encoded characters. Windows rejects several of those characters
    (notably ``?`` and ``:``), so report generation must never use a raw URL as
    a filename. Reserved device names and trailing dots/spaces are handled as
    well. A short hash is appended when truncation is required to avoid losing
    uniqueness between long targets.
    """
    raw = str(value or "target").strip()
    raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    raw = _INVALID_FILENAME_CHARS.sub("_", raw)
    raw = re.sub(r"_+", "_", raw)
    raw = raw.strip(" ._") or "target"

    # Windows treats CON, NUL, COM1, etc. as reserved even with an extension.
    if raw.upper().split(".", 1)[0] in _RESERVED_WINDOWS_NAMES:
        raw = f"target_{raw}"

    if len(raw) > _MAX_FILENAME_STEM:
        digest = hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:10]
        raw = f"{raw[:_MAX_FILENAME_STEM - 11].rstrip(' ._')}_{digest}"

    return raw


class Reporter:
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir or REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.jinja = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )
        self.jinja.filters["format_dt"] = format_dt
        self.jinja.filters["safe_text"] = safe_text
        self.jinja.filters["safe_code"] = safe_code
        self.jinja.globals["Markup"] = Markup

    def _filename_base(self, target: str) -> str:
        safe = _safe_filename_stem(target)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{safe}_{ts}"

    async def save_json(self, result: ScanResult) -> Path:
        base = self._filename_base(result.target)
        path = self.output_dir / f"{base}.json"
        data = result.to_dict()
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(data, indent=2, ensure_ascii=False))
        console.print(f"[green]💾 JSON report:[/green] {path}")
        return path

    async def save_html(self, result: ScanResult) -> Path | None:
        # BUG FIX 2: template tapılmasa proqram çökmür,
        # xəbərdarlıq verib None qaytarır.
        base = self._filename_base(result.target)
        path = self.output_dir / f"{base}.html"
        try:
            template = self.jinja.get_template("template.html")
        except TemplateNotFound:
            console.print(
                "[yellow]⚠ HTML template tapılmadı "
                f"({TEMPLATE_DIR / 'template.html'}). "
                "HTML report atlanır.[/yellow]"
            )
            return None
        html = template.render(result=result, format_dt=format_dt)
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(html)
        console.print(f"[green]🌐 HTML report:[/green] {path}")
        return path

    async def save_all(self, result: ScanResult) -> dict[str, Path | None]:
        json_path, html_path = await asyncio.gather(
            self.save_json(result),
            self.save_html(result),
        )
        return {"json": json_path, "html": html_path}
