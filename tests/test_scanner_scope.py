import pytest

from core.scanner import BugScanner
from core.scope import ScopeError


BASE_CONFIG = {
    "rate_limiting": {
        "default_rps": 10,
        "min_rps": 0.1,
        "max_rps": 100,
        "backoff_multiplier": 0.5,
        "pause_on_503": True,
    },
    "scanning": {
        "timeout": 5,
        "verify_ssl": True,
        "user_agent": "BugScanner/test",
        "max_redirects": 5,
    },
}


def make_config(allowed_targets=None, include_subdomains=False):
    config = {**BASE_CONFIG}
    config["rate_limiting"] = dict(BASE_CONFIG["rate_limiting"])
    config["scanning"] = dict(BASE_CONFIG["scanning"])
    config["scope"] = {
        "allowed_targets": allowed_targets or [],
        "include_subdomains": include_subdomains,
    }
    return config


def test_scope_is_backward_compatible_when_allowlist_is_empty():
    scanner = BugScanner(config=make_config())
    assert scanner.scope_enforced is False
    assert scanner._scope_allows("https://example.com") is True


def test_scope_blocks_root_target_before_network_activity():
    scanner = BugScanner(config=make_config(["allowed.example.com"]))
    assert scanner.scope_enforced is True
    with pytest.raises(ScopeError):
        scanner._require_scope("https://outside.example.com")


def test_scope_allows_exact_target():
    scanner = BugScanner(config=make_config(["allowed.example.com"]))
    assert scanner._scope_allows("https://allowed.example.com/path") is True
    assert scanner._scope_allows("https://sub.allowed.example.com/path") is False


def test_scope_allows_configured_subdomains():
    scanner = BugScanner(
        config=make_config(["allowed.example.com"], include_subdomains=True)
    )
    assert scanner._scope_allows("https://sub.allowed.example.com/path") is True
    assert scanner._scope_allows("https://other.example.com/path") is False


def test_scope_filters_discovered_urls():
    scanner = BugScanner(config=make_config(["allowed.example.com"]))
    urls = [
        "https://allowed.example.com/a",
        "https://outside.example.com/b",
        "https://allowed.example.com/c",
    ]
    assert scanner._filter_in_scope_urls(urls) == [
        "https://allowed.example.com/a",
        "https://allowed.example.com/c",
    ]
