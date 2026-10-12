"""Typed domain objects shared by the subscription pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True, slots=True)
class ProxyURI:
    """Parsed proxy URI. Keep the raw URI only for serialization/boundaries."""
    raw: str
    scheme: str
    username: str | None
    host: str | None
    port: int | None
    query: dict[str, list[str]] = field(default_factory=dict)
    fragment: str = ""
    path: str = ""

    @classmethod
    def parse(cls, value: str | "ProxyURI") -> "ProxyURI":
        if isinstance(value, cls):
            return value
        raw = value.strip()
        parsed = urlsplit(raw)
        # VMess encodes its fields in the URI payload, so its endpoint is resolved
        # by the VMess decoder at the adapter boundary.
        try:
            port = parsed.port
        except ValueError:
            port = None
        return cls(
            raw=raw,
            scheme=parsed.scheme.lower(),
            username=parsed.username,
            host=parsed.hostname.lower() if parsed.hostname else None,
            port=port,
            query=parse_qs(parsed.query, keep_blank_values=True),
            fragment=parsed.fragment,
            path=parsed.path,
        )

    @property
    def canonical(self) -> str:
        return self.raw.partition("#")[0].strip()

    def first(self, key: str, default: str = "") -> str:
        values = self.query.get(key, [])
        return str(values[0]) if values else default


@dataclass(slots=True)
class ResultTest:
    tcp_ping: bool = False
    proxy_get: bool = False
    xray_started: bool = False
    http_statuses: list[int] = field(default_factory=list)
    elapsed_ms: int | None = None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.proxy_get

    def as_legacy_tuple(self) -> tuple[bool, str]:
        return self.ok, self.reason or ("proxy-get-ok" if self.ok else "proxy-get-failed")
