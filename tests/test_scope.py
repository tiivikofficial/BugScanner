import pytest

from core.scope import ScopeError, ScopePolicy


def test_exact_host():
    policy = ScopePolicy.from_strings(["example.com"])
    assert policy.allowed("https://example.com/login")
    assert not policy.allowed("https://api.example.com")


def test_wildcard_subdomain():
    policy = ScopePolicy.from_strings(["*.example.com"])
    assert policy.allowed("https://api.example.com")
    assert not policy.allowed("https://example.com")


def test_cidr():
    policy = ScopePolicy.from_strings(["192.0.2.0/24"])
    assert policy.allowed("https://192.0.2.10")
    assert not policy.allowed("https://192.0.3.10")


def test_out_of_scope_raises():
    with pytest.raises(ScopeError):
        ScopePolicy.from_strings(["example.com"]).check("https://other.example")
