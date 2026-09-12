"""Runtime feedback for safe, deterministic endpoint prioritization.

The feedback loop only uses findings already produced during the current scan.
It does not discover new targets, expand scope, generate bypass behavior, or
persist sensitive target data between scans.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from core.models import Vulnerability
from core.vulnerability_orchestrator import TestPlan


class AdaptiveFeedbackEngine:
    """Boost endpoint plans when existing findings indicate a useful test family."""

    _TYPE_TO_TEST = {
        "xss": "xss",
        "sqli": "sqli",
        "ssrf": "ssrf",
        "open redirect": "redirect",
        "redirect": "redirect",
        "idor": "idor",
        "cors": "cors",
        "information disclosure": "disclosure",
        "disclosure": "disclosure",
    }

    @staticmethod
    def _host_path(value: str) -> tuple[str, str]:
        parsed = urlparse(value)
        return (parsed.netloc.lower(), parsed.path.lower())

    @classmethod
    def build_signal(cls, findings: list[Vulnerability]) -> Counter[str]:
        """Count confirmed finding families without retaining target-specific data."""
        signal: Counter[str] = Counter()
        for finding in findings:
            if getattr(finding, "verification_status", "unverified") == "low-confidence":
                continue
            test_name = cls._TYPE_TO_TEST.get(finding.vuln_type.strip().lower())
            if test_name:
                signal[test_name] += 1
        return signal

    @classmethod
    def adjust_plan(
        cls,
        plan: TestPlan,
        findings: list[Vulnerability],
    ) -> TestPlan:
        """Apply a bounded priority boost from current-scan evidence."""
        signal = cls.build_signal(findings)
        plan_tests = set(plan.tests)
        matching = [name for name in plan_tests if signal.get(name, 0) > 0]
        if not matching:
            return plan

        boost = min(2, sum(min(signal[name], 2) for name in matching))
        reasons = tuple(dict.fromkeys(
            (*plan.reasons, "current-scan evidence supports related test family")
        ))
        return TestPlan(
            url=plan.url,
            tests=plan.tests,
            priority=min(10, plan.priority + boost),
            reasons=reasons,
        )

    @classmethod
    def prioritize(
        cls,
        plans: list[TestPlan],
        findings: list[Vulnerability],
        limit: int | None = None,
    ) -> list[TestPlan]:
        """Re-rank existing plans using only findings from the same scan."""
        adjusted = [cls.adjust_plan(plan, findings) for plan in plans]
        adjusted.sort(key=lambda item: (-item.priority, item.url))
        return adjusted if limit is None else adjusted[:limit]
