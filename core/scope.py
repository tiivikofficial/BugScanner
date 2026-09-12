"""Deterministic target-scope enforcement for authorized scans.

Scope rules are allow-only: a target must match an explicitly configured host
or CIDR. This module intentionally does not discover or expand scope.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeRule:
    pattern: str
    include_subdomains: bool = False


class ScopeError(ValueError):
    """Raised when a target is invalid or outside the configured scope."""


class ScopePolicy:
    def __init__(self, rules: list[ScopeRule] | None = None):
        self.rules = tuple(rules or ())

    @classmethod
    def from_strings(cls, values: list[str]) -> "ScopePolicy":
        rules = []
        for value in values:
            value = value.strip().lower()
            if not value:
                continue
            if value.startswith("*."):
                rules.append(ScopeRule(value[2:], include_subdomains=True))
            else:
                rules.append(ScopeRule(value, include_subdomains=False))
        return cls(rules)

    @staticmethod
    def _host(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ScopeError("Only valid http(s) targets are supported")
        return parsed.hostname.rstrip(".").lower()

    @staticmethod
    def _matches_ip(host: str, pattern: str) -> bool:
        try:
            address = ipaddress.ip_address(host)
            network = ipaddress.ip_network(pattern, strict=False)
            return address in network
        except ValueError:
            return False

    def allowed(self, target: str) -> bool:
        if not self.rules:
            return False
        host = self._host(target)
        for rule in self.rules:
            pattern = rule.pattern
            if self._matches_ip(host, pattern):
                return True
            if host == pattern:
                return True
            if rule.include_subdomains and host.endswith("." + pattern):
                return True
            if "*" in pattern and fnmatch(host, pattern):
                return True
        return False

    def check(self, target: str) -> str:
        host = self._host(target)
        if not self.allowed(target):
            raise ScopeError(f"Target '{host}' is outside the configured allowlist")
        return host
