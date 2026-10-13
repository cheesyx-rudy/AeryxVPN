"""Optional hybrid IP/CIDR blocklist filter for the LIKVID pipeline."""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

import requests
from loguru import logger

MAX_BLOCKLIST_BYTES = 25 * 1024 * 1024
DEFAULT_TIMEOUT = 20


def parse_networks(text: str) -> list:
    networks = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        # Accept one IP/CIDR per line; strip common inline comments.
        token = line.split("#", 1)[0].strip().split()[0] if line.split("#", 1)[0].strip() else ""
        if not token:
            continue
        try:
            networks.add(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def _valid_https_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.netloc)


def load_networks(url: str, cache_path: Path, timeout: int = DEFAULT_TIMEOUT) -> tuple[list, str]:
    """Download a blocklist, falling back to a previously saved valid copy."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if url:
        if not _valid_https_url(url):
            raise ValueError("Blocklist URL must use HTTPS")
        try:
            with requests.get(
                url,
                headers={"User-Agent": "LIKVID-VPN-Blocklist/1.0"},
                timeout=timeout,
                stream=True,
            ) as response:
                response.raise_for_status()
                chunks, size = [], 0
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_BLOCKLIST_BYTES:
                        raise ValueError("Blocklist exceeds configured size limit")
                    chunks.append(chunk)
            text = b"".join(chunks).decode("utf-8-sig", errors="replace")
            networks = parse_networks(text)
            if not networks:
                raise ValueError("Downloaded blocklist contains no valid IP/CIDR entries")
            old = parse_networks(cache_path.read_text(encoding="utf-8", errors="replace")) if cache_path.exists() else []
            if old and len(networks) < int(len(old) * 0.5):
                raise ValueError(f"Blocklist entry count dropped unexpectedly: {len(old)} -> {len(networks)}")
            tmp = cache_path.with_suffix(cache_path.suffix + ".tmp")
            tmp.write_text("\n".join(n.with_prefixlen for n in networks) + "\n", encoding="utf-8")
            tmp.replace(cache_path)
            return networks, "downloaded"
        except Exception as exc:
            if cache_path.exists():
                cached = parse_networks(cache_path.read_text(encoding="utf-8", errors="replace"))
                if cached:
                    logger.warning("Blocklist download failed; using cached list: {}", exc)
                    return cached, "cached_fallback"
            raise RuntimeError(f"Could not load blocklist and no valid cache exists: {exc}") from exc

    if cache_path.exists():
        cached = parse_networks(cache_path.read_text(encoding="utf-8", errors="replace"))
        if cached:
            return cached, "cached_no_url"
    return [], "disabled_no_url"


def resolve_host_ips(host: str) -> set:
    """Resolve a hostname to IPs; resolution failures never cause rejection."""
    try:
        return {
            ipaddress.ip_address(item[4][0].split("%", 1)[0])
            for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        return set()


def build_network_index(networks: list) -> dict[tuple[int, int], set[int]]:
    """Index network addresses by IP version and prefix length for fast membership checks."""
    index: dict[tuple[int, int], set[int]] = {}
    for network in networks:
        index.setdefault((network.version, network.prefixlen), set()).add(int(network.network_address))
    return index


def find_blocked_ips(host: str, network_index: dict[tuple[int, int], set[int]]) -> list[str]:
    try:
        addresses = {ipaddress.ip_address(host.strip("[]").split("%", 1)[0])}
    except ValueError:
        addresses = resolve_host_ips(host)
    matched = set()
    for address in addresses:
        bits = address.max_prefixlen
        value = int(address)
        for prefix in range(bits + 1):
            mask = ((1 << prefix) - 1) << (bits - prefix) if prefix else 0
            network_address = value & mask
            if network_address in network_index.get((address.version, prefix), ()):
                matched.add(address.compressed)
                break
    return sorted(matched)
