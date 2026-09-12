"""Management-oriented report renderer, separate from the technical report."""
from __future__ import annotations

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from core.models import ScanResult


class ExecutiveReporter:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(loader=FileSystemLoader(str(Path(__file__).parent.parent / "reports")), autoescape=True)

    async def save_html(self, result: ScanResult) -> Path | None:
        try:
            template = self.env.get_template("executive_template.html")
        except TemplateNotFound:
            return None
        safe_target = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in result.target)[:120] or "target"
        path = self.output_dir / f"{safe_target}_executive.html"
        path.write_text(template.render(result=result), encoding="utf-8")
        return path
