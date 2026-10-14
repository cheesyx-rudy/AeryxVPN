#!/usr/bin/env python3
import argparse, base64, json, re, socket, ipaddress, urllib.parse, subprocess, tempfile, time, shutil, os, concurrent.futures
from pathlib import Path
from datetime import datetime, timezone, timedelta
from time import perf_counter
import requests
import urllib.request
from loguru import logger
from domain import ProxyURI, ResultTest
from settings import settings

BASE_DIR = Path(__file__).resolve().parent
SOURCES_FILE = BASE_DIR / "proxy_sources.txt"
OUTPUT_FILE = BASE_DIR / "proxies.txt"
MAX_BYTES = 20 * 1024 * 1024
MAX_CONFIGS = 1000
GEO_BATCH_SIZE = 100
XRAY_TEST_TIMEOUT = settings.test_timeout
XRAY_WORKERS = settings.workers
MIN_VALID_CONFIGS = settings.min_valid_configs
PING_TYPE = settings.ping_type
PING_MODE = settings.ping_mode
PING_URL = settings.ping_url
PING_TIMEOUT = settings.ping_timeout
EXPECTED_STATUS_CODES = {204}
TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)

# Happ routing profile source of truth. Keep the JSON file and embedded deeplink
# synchronized on every subscription build so existing Happ profiles can be
# overwritten when users refresh the subscription.
ROUTING_JSON_FILE = BASE_DIR / "routing" / "LIKVID-RU-WHITELIST.JSON"
ROUTING_DEEPLINK_FILE = BASE_DIR / "routing" / "LIKVID-RU-WHITELIST.DEEPLINK"

def build_happ_routing_link():
    if not ROUTING_JSON_FILE.exists():
        raise SystemExit(f"Happ routing profile not found: {ROUTING_JSON_FILE}")
    raw_profile = ROUTING_JSON_FILE.read_text(encoding="utf-8").strip()
    # Recover from older runs that accidentally wrote the two literal
    # characters "\\n" instead of a real newline at the end of the file.
    if raw_profile.endswith(r"\n"):
        raw_profile = raw_profile[:-2].rstrip()
    profile = json.loads(raw_profile)
    if not isinstance(profile, dict):
        raise SystemExit("Happ routing profile must be a JSON object")

    # Force refresh of geo files when a user refreshes the subscription.
    # Happ itself rate-limits geo file downloads (documented by Happ).
    profile["LastUpdated"] = str(int(datetime.now(timezone.utc).timestamp()))

    encoded = base64.b64encode(
        json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    link = f"happ://routing/onadd/{encoded}"

    ROUTING_JSON_FILE.write_text(
        f"{json.dumps(profile, ensure_ascii=False, indent=2)}\n",
        encoding="utf-8"
    )
    ROUTING_DEEPLINK_FILE.write_text(f"{link}\n", encoding="utf-8")
    return link

URI_RE = re.compile(
    r"(?i)\b(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|anytls|socks5?|http)://[^\s<>\"']+"
)

def fetch(url):
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0 LIKVID-VPN/1.0"}, timeout=30, stream=True)
    try:
        response.raise_for_status()
        chunks, size = [], 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("source is larger than 20 MiB")
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        response.close()

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

def _query(parsed):
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def _q(query, key, default=""):
    values = query.get(key, [])
    return str(values[0]) if values else default


def _truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _tls_settings(query, default_server_name=""):
    tls = {}
    server_name = _q(query, "sni", default_server_name)
    if server_name:
        tls["serverName"] = server_name
    fp = _q(query, "fp")
    if fp:
        tls["fingerprint"] = fp
    alpn = _q(query, "alpn")
    if alpn:
        tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
    if _truthy(_q(query, "allowInsecure")):
        tls["allowInsecure"] = True
    return tls


def _vmess_object(uri):
    parsed = urllib.parse.urlsplit(uri.split("#", 1)[0])
    payload = urllib.parse.unquote(parsed.netloc + parsed.path).strip()
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("VMess payload must be a JSON object")
    return obj


def _stream_settings(network, security, query, host, vmess=None):
    vmess = vmess or {}
    net = (network or "tcp").lower()
    sec = (security or "none").lower()
    stream = {"network": net, "security": sec}
    if sec == "tls":
        tlsq = dict(query)
        if not _q(tlsq, "sni") and vmess.get("sni"):
            tlsq["sni"] = [str(vmess["sni"])]
        if not _q(tlsq, "fp") and vmess.get("fp"):
            tlsq["fp"] = [str(vmess["fp"])]
        if not _q(tlsq, "alpn") and vmess.get("alpn"):
            tlsq["alpn"] = [str(vmess["alpn"])]
        stream["tlsSettings"] = _tls_settings(tlsq, host)
    elif sec == "reality":
        reality = {
            "serverName": _q(query, "sni", str(vmess.get("sni") or host)),
            "fingerprint": _q(query, "fp", str(vmess.get("fp") or "chrome")),
            "publicKey": _q(query, "pbk"),
            "shortId": _q(query, "sid"),
        }
        spider = _q(query, "spx")
        if spider:
            reality["spiderX"] = spider
        if not reality["publicKey"]:
            raise ValueError("REALITY public key (pbk) is missing")
        stream["realitySettings"] = reality
    elif sec not in {"none", ""}:
        raise ValueError(f"unsupported Xray security mode: {sec}")

    if net == "ws":
        path = _q(query, "path", str(vmess.get("path") or "/"))
        headers = {}
        ws_host = _q(query, "host", str(vmess.get("host") or ""))
        if ws_host:
            headers["Host"] = ws_host
        stream["wsSettings"] = {"path": path or "/", "headers": headers}
    elif net == "grpc":
        service = _q(query, "serviceName", _q(query, "path", str(vmess.get("path") or "")))
        grpc = {"serviceName": service}
        authority = _q(query, "authority", _q(query, "host", str(vmess.get("host") or "")))
        if authority:
            grpc["authority"] = authority
        if _q(query, "mode").lower() == "multi":
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc
    elif net in {"httpupgrade", "http-upgrade"}:
        stream["network"] = "httpupgrade"
        host_header = _q(query, "host", str(vmess.get("host") or ""))
        settings = {"path": _q(query, "path", str(vmess.get("path") or "/"))}
        if host_header:
            settings["host"] = host_header
        stream["httpupgradeSettings"] = settings
    elif net == "xhttp":
        settings = {"path": _q(query, "path", str(vmess.get("path") or "/"))}
        xhost = _q(query, "host", str(vmess.get("host") or ""))
        if xhost:
            settings["host"] = xhost
        mode = _q(query, "mode", str(vmess.get("mode") or ""))
        if mode:
            settings["mode"] = mode
        stream["xhttpSettings"] = settings
    elif net not in {"tcp", "kcp", "http"}:
        raise ValueError(f"unsupported Xray transport: {net}")
    elif net == "tcp":
        header_type = _q(query, "headerType", str(vmess.get("type") or "none"))
        if header_type and header_type != "none":
            stream["tcpSettings"] = {"header": {"type": header_type}}
    return stream


def build_xray_outbound(uri):
    """Convert supported share links to a single Xray outbound config.

    Xray cannot validate Hysteria2, TUIC, or AnyTLS links; those are rejected
    rather than incorrectly marked healthy by a TCP-only test.
    """
    parsed = urllib.parse.urlsplit(uri.split("#", 1)[0])
    scheme = parsed.scheme.lower()
    query = _query(parsed)
    if scheme == "vmess":
        obj = _vmess_object(uri)
        host = str(obj.get("add") or obj.get("address") or "").strip()
        port = int(obj.get("port", 0))
        uid = str(obj.get("id") or obj.get("uuid") or "")
        if not host or not uid or not 1 <= port <= 65535:
            raise ValueError("VMess host, UUID, or port is missing")
        user = {"id": uid, "alterId": int(obj.get("aid") or 0), "security": str(obj.get("scy") or obj.get("cipher") or "auto")}
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
        stream = _stream_settings(str(obj.get("net") or "tcp"), "tls" if str(obj.get("tls") or "").lower() in {"tls", "true", "1"} else "none", query, host, obj)
    elif scheme == "vless":
        host, port = parsed.hostname, parsed.port
        uid = urllib.parse.unquote(parsed.username or "")
        if not host or not uid or not port:
            raise ValueError("VLESS host, UUID, or port is missing")
        user = {"id": uid, "encryption": _q(query, "encryption", "none")}
        flow = _q(query, "flow")
        if flow:
            user["flow"] = flow
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
        stream = _stream_settings(_q(query, "type", "tcp"), _q(query, "security", "none"), query, host)
    elif scheme == "trojan":
        host, port = parsed.hostname, parsed.port
        password = urllib.parse.unquote(parsed.username or "")
        if not host or not password or not port:
            raise ValueError("Trojan host, password, or port is missing")
        outbound = {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port, "password": password}]}}
        stream = _stream_settings(_q(query, "type", "tcp"), _q(query, "security", "tls"), query, host)
    elif scheme == "ss":
        netloc = parsed.netloc
        if "@" in netloc:
            credentials, hostport = netloc.rsplit("@", 1)
            if ":" not in credentials:
                decoded = base64.urlsafe_b64decode(credentials + "=" * (-len(credentials) % 4)).decode("utf-8")
                method, password = decoded.split(":", 1)
            else:
                method, password = credentials.split(":", 1)
            hp = urllib.parse.urlsplit("//" + hostport)
            host, port = hp.hostname, hp.port
        else:
            decoded = base64.urlsafe_b64decode(netloc + "=" * (-len(netloc) % 4)).decode("utf-8")
            credentials, hostport = decoded.rsplit("@", 1)
            method, password = credentials.split(":", 1)
            hp = urllib.parse.urlsplit("//" + hostport)
            host, port = hp.hostname, hp.port
        if not host or not port or not method or not password:
            raise ValueError("Shadowsocks method/password/host/port is missing")
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}}
        stream = {"network": "tcp", "security": "none"}
    elif scheme in {"socks", "socks5"}:
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            raise ValueError("SOCKS host/port is missing")
        server = {"address": host, "port": port}
        if parsed.username is not None:
            server["users"] = [{"user": urllib.parse.unquote(parsed.username), "pass": urllib.parse.unquote(parsed.password or "")}]
        outbound = {"protocol": "socks", "settings": {"servers": [server]}}
        stream = None
    elif scheme in {"http", "https"}:
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            raise ValueError("HTTP proxy host/port is missing")
        server = {"address": host, "port": port}
        if parsed.username is not None:
            server["users"] = [{"user": urllib.parse.unquote(parsed.username), "pass": urllib.parse.unquote(parsed.password or "")}]
        outbound = {"protocol": "http", "settings": {"servers": [server]}}
        stream = {"network": "tcp", "security": "tls"} if scheme == "https" else None
        if stream and parsed.hostname:
            stream["tlsSettings"] = {"serverName": parsed.hostname}
    else:
        raise ValueError(f"Xray cannot validate protocol {scheme!r}; use a protocol-specific core")

    if stream:
        outbound["streamSettings"] = stream
    return outbound


def _reserve_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _test_one_with_xray(uri, xray_binary):
    process = None
    try:
        outbound = build_xray_outbound(uri)
        port = _reserve_local_port()
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [outbound],
        }
        with tempfile.TemporaryDirectory(prefix="likvid-xray-") as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
            check = subprocess.run([xray_binary, "run", "-test", "-config", str(config_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
            if check.returncode != 0:
                return False, f"xray-config: {check.stdout.strip()[-240:] or 'configuration rejected'}"
            log_path = Path(tmp) / "xray.log"
            with log_path.open("wb") as log_file:
                process = subprocess.Popen([xray_binary, "run", "-config", str(config_path)], stdout=log_file, stderr=subprocess.STDOUT)
                # Wait for the local SOCKS inbound to become ready instead of
                # racing the first HTTP request against Xray startup.
                ready = False
                ready_deadline = time.monotonic() + 2.5
                while time.monotonic() < ready_deadline:
                    if process.poll() is not None:
                        break
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.08)
                if not ready:
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-240:]
                    return False, f"xray-start: {tail.strip() or f'SOCKS inbound not ready; exit {process.poll()}'}"
                errors = []
                # Selectable probe semantics inspired by common proxy clients:
                # proxy_get / proxy_head validate a real request through Xray;
                # tcp checks only direct endpoint reachability; icmp uses system ping.
                # TCP/ICMP are diagnostics, not proof that the proxy tunnel works.
                parsed_endpoint = _host_from_uri(uri)
                if PING_TYPE == "tcp":
                    try:
                        ep = urllib.parse.urlsplit(uri.split("#", 1)[0])
                        if ep.scheme.lower() == "vmess":
                            obj = _vmess_object(uri)
                            host, remote_port = str(obj.get("add", "")), int(obj.get("port", 0))
                        else:
                            host, remote_port = ep.hostname, ep.port
                        with socket.create_connection((host, remote_port), timeout=PING_TIMEOUT):
                            return True, "tcp-reachable (endpoint only)"
                    except Exception as exc:
                        return False, f"tcp-probe: {exc}"
                if PING_TYPE == "icmp":
                    host = parsed_endpoint
                    if not host:
                        return False, "icmp-probe: endpoint host missing"
                    cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, int(PING_TIMEOUT))), host]
                    try:
                        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=PING_TIMEOUT + 2)
                        return (result.returncode == 0, "icmp-reachable" if result.returncode == 0 else "icmp-unreachable")
                    except Exception as exc:
                        return False, f"icmp-probe: {exc}"
                if PING_TYPE not in {"proxy_get", "proxy_head"}:
                    return False, f"ping-type: unsupported mode {PING_TYPE}"
                if PING_MODE not in {"keepalive", "double"}:
                    return False, f"ping-mode: unsupported mode {PING_MODE}"

                # A single requests.Session reuses HTTP connections (KeepAlive).
                # The SOCKS hostname scheme ensures DNS is resolved by the proxy.
                probe_count = 2
                proxy_url = f"socks5h://127.0.0.1:{port}"
                statuses = []
                try:
                    with requests.Session() as session:
                        session.trust_env = False
                        session.proxies.update({"http": proxy_url, "https": proxy_url})
                        for _ in range(probe_count):
                            request_method = session.head if PING_TYPE == "proxy_head" else session.get
                            with request_method(
                                PING_URL,
                                timeout=(min(3.0, PING_TIMEOUT), PING_TIMEOUT),
                                allow_redirects=True,
                                stream=True,
                                headers={"User-Agent": "LIKVID-VPN-validator/1.0", "Connection": "keep-alive"},
                            ) as response:
                                statuses.append(response.status_code)
                                # Close response body promptly; Session retains reusable connections when possible.
                                response.close()
                    if len(statuses) == probe_count and all(code in EXPECTED_STATUS_CODES for code in statuses):
                        return True, f"proxy-get-ok; statuses={statuses}; keepalive"
                    errors.append(f"expected HTTP {sorted(EXPECTED_STATUS_CODES)}, received {statuses}")
                except requests.RequestException as exc:
                    errors.append(f"request: {type(exc).__name__}: {exc}"[-160:])
                return False, f"tunnel: {'; '.join(errors)}"
    except subprocess.TimeoutExpired:
        return False, "xray-timeout: config test exceeded timeout"
    except Exception as exc:
        return False, f"xray: {type(exc).__name__}: {exc}"
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=1.5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass


def validate_with_xray(proxies, xray_binary, workers=XRAY_WORKERS):
    """Keep only configs that Xray can start and that pass a real HTTP probe."""
    if not xray_binary or not Path(xray_binary).exists():
        raise SystemExit("Xray binary not found. Install Xray-core and pass --xray-binary /path/to/xray")
    try:
        version = subprocess.run([xray_binary, "version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
        logger.info("Xray version: {}", version.stdout.strip().splitlines()[0] if version.stdout.strip() else "version unknown")
    except Exception as exc:
        raise SystemExit(f"Unable to execute Xray binary: {exc}")

    results = [None] * len(proxies)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        future_map = {pool.submit(_test_one_with_xray, uri, xray_binary): i for i, uri in enumerate(proxies)}
        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            i = future_map[future]
            try:
                results[i] = future.result()
            except Exception as exc:
                results[i] = (False, f"validator exception: {exc}")
            completed += 1
            if completed % 25 == 0 or completed == len(proxies):
                logger.info("Xray checked {}/{}", completed, len(proxies))

    accepted, rejected, reasons = [], 0, {}
    for uri, result in zip(proxies, results):
        ok, reason = result or (False, "validator returned no result")
        if ok:
            accepted.append(uri)
        else:
            rejected += 1
            category = reason.split(":", 1)[0]
            reasons[category] = reasons.get(category, 0) + 1
    logger.info("Xray tunnel validation: {}/{} passed; {} rejected", len(accepted), len(proxies), rejected)
    if reasons:
        logger.info("Xray rejection summary: {}", ", ".join(f"{key}={value}" for key, value in sorted(reasons.items())))
    # Fail closed, but don't replace a known-good subscription with an empty
    # or implausibly small result caused by a runner/network outage.
    if len(proxies) >= 20 and len(accepted) < MIN_VALID_CONFIGS:
        raise SystemExit(f"Safety stop: only {len(accepted)} configs passed out of {len(proxies)}. Existing snapshot/subscription will not be overwritten.")
    return accepted, rejected


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
        logger.warning("GEO DNS ERROR for {}: {}", host, exc)
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
            logger.info("GEO looked up {} IP addresses", len(batch))
        except Exception as exc:
            logger.warning("GEO batch {} failed: {}", start // GEO_BATCH_SIZE + 1, exc)
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
        labelled.append(f"{uri.split(chr(35), 1)[0]}#{urllib.parse.quote(label, safe='')}")
    summary = ", ".join(f"{name}: {count}" for name, count in sorted(counts.items()))
    logger.info("GEO country distribution: {}", summary or "no configs")
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
    return f"{uri.split(chr(35), 1)[0]}#{urllib.parse.quote(label, safe='')}"

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
            logger.info("Removed manually marked proxy #{}", number)
            continue
        result.append(uri)
    return result, removed

def main():
    global PING_TYPE, PING_MODE, PING_URL, PING_TIMEOUT
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("fresh", "cleanup"), default="fresh")
    parser.add_argument("--xray-binary", default=os.environ.get("XRAY_BINARY", ""), help="path to Xray-core binary; required for fresh mode")
    parser.add_argument("--xray-workers", type=int, default=XRAY_WORKERS, help="parallel Xray tunnel checks")
    parser.add_argument("--ping-type", choices=("proxy_get", "proxy_head", "tcp", "icmp"),
                        default=PING_TYPE, help="probe method: proxy_get/head test the tunnel; tcp/icmp only test endpoint reachability")
    parser.add_argument("--ping-mode", choices=("keepalive", "double"), default=PING_MODE,
                        help="one request or two consecutive requests (proxy GET/HEAD only)")
    parser.add_argument("--ping-url", default=PING_URL, help="HTTP(S) test URL for proxy GET/HEAD")
    parser.add_argument("--ping-timeout", type=float, default=PING_TIMEOUT, help="probe timeout in seconds")
    args = parser.parse_args()
    PING_TYPE, PING_MODE, PING_URL, PING_TIMEOUT = args.ping_type, args.ping_mode, args.ping_url, args.ping_timeout

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
        logger.info("Cleanup mode: using frozen snapshot ({} proxy URLs)", len(unique))
        logger.info("Loaded {} manually marked proxy numbers", len(dead_numbers))
        unique, removed = apply_dead_numbers(unique, dead_numbers)
        logger.info("Removed {} dead proxies", removed)
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
                    logger.info("Source {} -> {} new proxy URLs (skipped {} ML-KEM)", source, added, source_mlkem)
                else:
                    logger.info("Source {} -> {} new proxy URLs", source, added)
            except Exception as e:
                logger.warning("Source {} failed: {}", source, e)

        logger.info("Skipped {} ML-KEM encryption proxies", mlkem_skipped)
        if not unique:
            raise SystemExit("No proxy URLs extracted; refusing to overwrite the current subscription")

        # Validate through the actual Xray core and an HTTP request routed via
        # each temporary local SOCKS tunnel. Unsupported protocols fail closed.
        unique, xray_rejected = validate_with_xray(unique, args.xray_binary, args.xray_workers)
        logger.info("Xray removed {} configs that failed core/tunnel checks", xray_rejected)
        if not unique:
            raise SystemExit("No configs passed Xray tunnel validation; existing outputs are preserved")
        if len(unique) > MAX_CONFIGS:
            logger.info("Found {} configs; keeping first {}", len(unique), MAX_CONFIGS)
            unique = unique[:MAX_CONFIGS]

        # Freeze order and country labels together. Cleanup uses this snapshot,
        # so dead.txt numbers stay aligned and no geolocation calls are needed.
        unique = add_country_labels(unique)
        write_snapshot(unique)
        logger.info("Saved {} proxy URLs to parsed_proxies.txt", len(unique))

    output = [rename_uri(uri, index) for index, uri in enumerate(unique, start=1)]

    updated = (datetime.now(timezone.utc) + timedelta(hours=3)).strftime("%d.%m.%Y %H:%M")

    header = (
        "#subscription-userinfo: upload=0; download=0; total=0; expire=2524608000\n"
        "#profile-title: LIKVID VPN\n"
        "#profile-update-interval: 1\n"
        "#profile-web-page-url: https://t.me/likvid_vpn\n"
        "#support-url: https://t.me/cheesyx\n"
        f"#announce: вся важная информация в канале @LIKVID_VPN // авторы @rudy_bd @cheesyx // обновлено: {updated} | конфигов: {len(output)}"
    )

    # Happ recognizes this deeplink when it appears in the subscription body.
    # Put it after metadata headers and before proxy URIs; ordinary URI extraction
    # ignores happ:// links, while Happ uses it to attach/activate routing.
    happ_routing_link = build_happ_routing_link()
    result = "\n".join((header, happ_routing_link, *output))

    tmp = OUTPUT_FILE.with_suffix(".tmp")
    tmp.write_text(result + ("\n" if output else ""), encoding="utf-8")
    tmp.replace(OUTPUT_FILE)
    logger.info("Total unique proxy URLs: {}", len(output))
    logger.info("Wrote {}", OUTPUT_FILE)

if __name__ == "__main__":
    main()
