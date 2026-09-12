import pytest

from core.asset_inventory import AssetInventory, AssetType
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


def test_asset_inventory_normalizes_and_deduplicates_urls():
    inventory = AssetInventory()
    inventory.add("HTTPS://Example.COM/path#fragment", AssetType.ENDPOINT, "discovery")
    inventory.add("https://example.com/path", AssetType.ENDPOINT, "manual")

    assets = inventory.all()
    assert len(assets) == 1
    assert assets[0].value == "https://example.com/path"
    assert assets[0].sources == ("discovery", "manual")


def test_asset_inventory_keeps_asset_types_distinct():
    inventory = AssetInventory()
    inventory.add("example.com", AssetType.HOST, "recon")
    inventory.add("https://example.com/", AssetType.URL, "recon")

    assert len(inventory.all()) == 2
    assert len(inventory.by_type(AssetType.HOST)) == 1
    assert len(inventory.by_type(AssetType.URL)) == 1
