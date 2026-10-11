#!/usr/bin/env python3
import argparse, base64, json, re, socket, ipaddress, urllib.parse, urllib.request
from pathlib import Path
from datetime import datetime, timezone, timedelta

BASE_DIR = Path(__file__).resolve().parent
SOURCES_FILE = BASE_DIR / "proxy_sources.txt"
OUTPUT_FILE = BASE_DIR / "proxies.txt"
MAX_BYTES = 20 * 1024 * 1024
MAX_CONFIGS = 1000
GEO_BATCH_SIZE = 100

URI_RE = re.compile(
    r"(?i)\b(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|anytls|socks5?|http)://[^\s<>\"']+"
)

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 kafka-sub-proxy-parser/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("source is larger than 20 MiB")
    return data.decode("utf-8", errors="replace")

def extract_uris(text, depth=0):
    if depth > 3:
        return []
    found = [x.rstrip(".,;:)]}>\"'") for x in URI_RE.findall(text)]
    compact = re.sub(r"\s+", "", text)
    if depth < 3 and len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            decoded = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", errors="replace")
            if decoded != text:
                found.extend(extract_uris(decoded, depth + 1))
        except Exception:
            pass
    if depth < 2:
        try:
            found.extend(extract_uris(json.dumps(json.loads(text), ensure_ascii=False), depth + 1))
        except Exception:
            pass
    return found

def is_mlkem_encryption_proxy(uri):
    """Return True for VLESS/VMess configs using VLESS ML-KEM encryption.

    Karing may fail to initialize these nodes with errors such as
    `mlkem: invalid polynomial encoding`, so they are excluded from the
    generated proxy list. This targets the VLESS encryption parameter
    `mlkem768x25519plus...`, not ordinary REALITY/ML-KEM key-exchange fields.
    """
    raw = uri.split("#", 1)[0]
    try:
        parsed = urllib.parse.urlsplit(raw)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query.items():
            if key.lower() == "encryption":
                for value in values:
                    value = urllib.parse.unquote(str(value or "")).strip().lower()
                    if value.startswith("mlkem768x25519plus"):
                        return True

        if parsed.scheme.lower() == "vmess":
            payload = parsed.netloc + parsed.path
            payload = urllib.parse.unquote(payload).strip()
            decoded = base64.urlsafe_b64decode(
                payload + "=" * (-len(payload) % 4)
            ).decode("utf-8", errors="replace")
            obj = json.loads(decoded)
            if isinstance(obj, dict):
                value = str(obj.get("encryption") or "").strip().lower()
                if value.startswith("mlkem768x25519plus"):
                    return True
    except Exception:
        pass
    return False

def _flag(country_code):
    code = (country_code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def _host_from_uri(uri):
    """Return the host from a supported proxy URI, including VMess JSON links."""
    try:
        parsed = urllib.parse.urlsplit(uri.split("#", 1)[0])
        if parsed.scheme.lower() == "vmess":
            payload = (parsed.netloc + parsed.path).strip()
            payload = urllib.parse.unquote(payload)
            obj = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if isinstance(obj, dict):
                host = obj.get("add") or obj.get("address") or obj.get("server")
                return str(host).strip() if host else None
        return parsed.hostname
    except Exception:
        return None


def _public_ip_for_host(host):
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
        return str(ip) if ip.is_global else None
    except ValueError:
        pass
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for answer in answers:
            candidate = answer[4][0].split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(candidate)
                if ip.is_global:
                    return str(ip)
            except ValueError:
                continue
    except Exception as exc:
        print(f"[GEO DNS ERROR] {host}: {exc}")
    return None


def _lookup_countries(ip_addresses):
    """Look up countries in batches to avoid one API request per config."""
    result = {}
    ips = list(dict.fromkeys(ip_addresses))
    for start in range(0, len(ips), GEO_BATCH_SIZE):
        batch = ips[start:start + GEO_BATCH_SIZE]
        if not batch:
            continue
        endpoint = "http://ip-api.com/batch?fields=status,message,query,country,countryCode"
        body = json.dumps([{"query": ip} for ip in batch]).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "LIKVID-VPN-subscription-parser/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                rows = json.loads(response.read().decode("utf-8", errors="replace"))
            for row in rows if isinstance(rows, list) else []:
                if row.get("status") == "success" and row.get("query") and row.get("country"):
                    result[row["query"]] = (row.get("countryCode", ""), row["country"])
            print(f"[GEO] looked up {len(batch)} IP addresses")
        except Exception as exc:
            print(f"[GEO ERROR] batch {start // GEO_BATCH_SIZE + 1}: {exc}")
    return result


def add_country_labels(proxies):
    """Store a stable country label in each snapshot entry; numbering is added later."""
    hosts = [_host_from_uri(uri) for uri in proxies]
    host_to_ip = {}
    for host in dict.fromkeys(h for h in hosts if h):
        host_to_ip[host] = _public_ip_for_host(host)
    countries = _lookup_countries(ip for ip in host_to_ip.values() if ip)

    labelled = []
    counts = {}
    for uri, host in zip(proxies, hosts):
        ip = host_to_ip.get(host) if host else None
        country_code, country = countries.get(ip, ("", "Unknown")) if ip else ("", "Unknown")
        flag = _flag(country_code)
        if country == "Unknown":
            flag = "🌐"
        counts[country] = counts.get(country, 0) + 1
        label = f"{flag} Cluster {country}"
        labelled.append(uri.split("#", 1)[0] + "#" + urllib.parse.quote(label, safe=""))
    summary = ", ".join(f"{name}: {count}" for name, count in sorted(counts.items()))
    print(f"[GEO] country distribution: {summary or 'no configs'}")
    return labelled


def rename_uri(uri, number):
    # The snapshot stores the country label without a number so cleanup keeps
    # the original numbering and does not need to contact the geolocation API.
    existing = uri.split("#", 1)[1] if "#" in uri else ""
    try:
        label = urllib.parse.unquote(existing)
    except Exception:
        label = ""
    if not label or "Cluster " not in label:
        label = "🌐 Cluster Unknown"
    label = re.sub(r"\s+#?\d+$", "", label).strip()
    label = f"{label} #{number}"
    return uri.split("#", 1)[0] + "#" + urllib.parse.quote(label, safe="")

def load_dead_numbers():
    dead_file = BASE_DIR / "dead.txt"
    if not dead_file.exists():
        return set()
    numbers = set()
    for line in dead_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.isdigit() and int(line) > 0:
            numbers.add(int(line))
    return numbers

def write_snapshot(proxies):
    (BASE_DIR / "parsed_proxies.txt").write_text(
        "\n".join(proxies) + ("\n" if proxies else ""),
        encoding="utf-8"
    )

def read_snapshot():
    path = BASE_DIR / "parsed_proxies.txt"
    if not path.exists():
        raise SystemExit("parsed_proxies.txt not found")
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]

def apply_dead_numbers(proxies, dead_numbers):
    if not dead_numbers:
        return proxies, 0
    result = []
    removed = 0
    for number, uri in enumerate(proxies, start=1):
        if number in dead_numbers:
            removed += 1
            print(f"[DEAD] removed proxy #{number}")
            continue
        result.append(uri)
    return result, removed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("fresh", "cleanup"), default="fresh")
    args = parser.parse_args()

    snapshot = BASE_DIR / "parsed_proxies.txt"
    dead_file = BASE_DIR / "dead.txt"

    # Fresh mode fetches/parses sources and replaces the frozen snapshot.
    # Cleanup mode NEVER fetches sources: it uses the snapshot from the
    # corresponding fresh run and removes the numbers listed in dead.txt.
    if args.mode == "cleanup":
        dead_numbers = load_dead_numbers()
        if not snapshot.exists():
            raise SystemExit("parsed_proxies.txt not found; run --mode fresh first")
        if not dead_numbers:
            raise SystemExit("dead.txt is empty; add failed Happ proxy numbers first")
        unique = read_snapshot()
        print(f"[MODE] cleanup: using frozen snapshot ({len(unique)} proxy URLs)")
        print(f"[DEAD] loaded {len(dead_numbers)} manually marked proxy numbers")
        unique, removed = apply_dead_numbers(unique, dead_numbers)
        print(f"[DEAD] removed {removed} dead proxies")
    else:
        if not SOURCES_FILE.exists():
            raise SystemExit("proxy_sources.txt not found")

        sources = [
            x.strip() for x in SOURCES_FILE.read_text(encoding="utf-8").splitlines()
            if x.strip() and not x.lstrip().startswith("#")
        ]
        unique, seen = [], set()
        mlkem_skipped = 0

        for source in sources:
            try:
                items = extract_uris(fetch(source))
                added = 0
                source_mlkem = 0
                for uri in items:
                    key = uri.split("#", 1)[0]
                    if key in seen:
                        continue
                    seen.add(key)

                    if is_mlkem_encryption_proxy(uri):
                        mlkem_skipped += 1
                        source_mlkem += 1
                        continue

                    unique.append(uri)
                    added += 1

                if source_mlkem:
                    print(f"[SOURCE] {source} -> {added} new proxy URLs (skipped {source_mlkem} ML-KEM)")
                else:
                    print(f"[SOURCE] {source} -> {added} new proxy URLs")
            except Exception as e:
                print(f"[SOURCE ERROR] {source}: {e}")

        print(f"[FILTER] skipped {mlkem_skipped} ML-KEM encryption proxies")
        if len(unique) > MAX_CONFIGS:
            print(f"[LIMIT] found {len(unique)} configs; keeping first {MAX_CONFIGS}")
            unique = unique[:MAX_CONFIGS]

        # Freeze order and country labels together. Cleanup uses this snapshot,
        # so dead.txt numbers stay aligned and no geolocation calls are needed.
        unique = add_country_labels(unique)
        write_snapshot(unique)
        print(f"[SNAPSHOT] saved {len(unique)} proxy URLs to parsed_proxies.txt")

    output = [rename_uri(uri, index) for index, uri in enumerate(unique, start=1)]

    updated = (datetime.now(timezone.utc) + timedelta(hours=3)).strftime("%d.%m.%Y %H:%M")

    header = (
        "#subscription-userinfo: upload=0; download=0; total=0; expire=2524608000\n"
        "#profile-title: LIKVID VPN\n"
        "#profile-update-interval: 1\n"
        f"#announce: вся важная информация в канале @LIKVID_VPN // авторы @rudy_bd @cheesyx // обновлено: {updated} | конфигов: {len(output)}"
    )

    result = header + "\n" + "\n".join(output)

    tmp = OUTPUT_FILE.with_suffix(".tmp")
    tmp.write_text(result + ("\n" if output else ""), encoding="utf-8")
    tmp.replace(OUTPUT_FILE)
    print(f"[TOTAL] {len(output)} unique proxy URLs")
    print(f"[DONE] wrote {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
