"""Deterministic asset inventory for authorized scan results.

The inventory is an in-memory normalization layer: it does not discover new
hosts and it never expands the configured scan scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urlunparse


class AssetType(str, Enum):
    HOST = "host"
    URL = "url"
    ENDPOINT = "endpoint"
    IP = "ip"


@dataclass(frozen=True)
class Asset:
    key: str
    value: str
    asset_type: AssetType
    sources: tuple[str, ...] = ()
    metadata: tuple[tuple[str, str], ...] = ()


class AssetInventory:
    """Normalize and deduplicate assets while preserving discovery sources."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}

    @staticmethod
    def normalize_url(value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Asset must be a valid http(s) URL")
        host = parsed.hostname.lower().rstrip(".")
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        path = parsed.path or "/"
        return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))

    @classmethod
    def key_for(cls, value: str, asset_type: AssetType) -> str:
        if asset_type in {AssetType.URL, AssetType.ENDPOINT}:
            return f"{asset_type.value}:{cls.normalize_url(value)}"
        return f"{asset_type.value}:{value.strip().lower().rstrip('.') }"

    def add(
        self,
        value: str,
        asset_type: AssetType,
        source: str = "unknown",
        metadata: dict[str, str] | None = None,
    ) -> Asset:
        key = self.key_for(value, asset_type)
        current = self._assets.get(key)
        sources = set(current.sources if current else ())
        sources.add(source)
        merged = dict(current.metadata if current else ())
        merged.update(metadata or {})
        asset = Asset(
            key=key,
            value=cls_value(value, asset_type),
            asset_type=asset_type,
            sources=tuple(sorted(sources)),
            metadata=tuple(sorted(merged.items())),
        )
        self._assets[key] = asset
        return asset

    def add_many(self, values: list[str], asset_type: AssetType, source: str) -> list[Asset]:
        return [self.add(value, asset_type, source) for value in values]

    def all(self) -> list[Asset]:
        return sorted(self._assets.values(), key=lambda item: item.key)

    def by_type(self, asset_type: AssetType) -> list[Asset]:
        return [asset for asset in self.all() if asset.asset_type == asset_type]

    def to_dict(self) -> list[dict]:
        return [
            {
                "key": asset.key,
                "value": asset.value,
                "type": asset.asset_type.value,
                "sources": list(asset.sources),
                "metadata": dict(asset.metadata),
            }
            for asset in self.all()
        ]


def cls_value(value: str, asset_type: AssetType) -> str:
    if asset_type in {AssetType.URL, AssetType.ENDPOINT}:
        return AssetInventory.normalize_url(value)
    return value.strip().lower().rstrip(".")
