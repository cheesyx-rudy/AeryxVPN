#!/usr/bin/env python3
"""YAML-driven ETL pipeline for LIKVID-VPN subscriptions."""
import argparse, concurrent.futures, json, os, socket, sys, time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit
import requests
import yaml
from loguru import logger
from domain import ProxyURI, ResultTest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
import proxy_parser as legacy
import blocklist_filter


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict) or not isinstance(cfg.get("stages"), list):
        raise ValueError("YAML must contain a root mapping and stages list")
    names = [s.get("name") for s in cfg["stages"] if s.get("enabled", True)]
    allowed = {"collect", "filter_unsupported", "normalize", "deduplicate", "cluster_analysis", "blocklist_filter", "xray_probe", "stability_check"}
    unknown = set(names) - allowed
    if unknown:
        raise ValueError(f"Unknown stage(s): {', '.join(sorted(unknown))}")
    return cfg


def ident(uri):
    return ProxyURI.parse(uri).canonical


def cluster_key(uri):
    """Build endpoint identity from typed URI fields, with VMess adapter support."""
    parsed = ProxyURI.parse(uri)
    try:
        if parsed.scheme == "vmess":
            outbound = legacy._vmess_object(parsed.raw)
            host = str(outbound.get("add") or outbound.get("address") or "").lower()
            port = int(outbound.get("port") or 0)
            network = str(outbound.get("net") or "tcp").lower()
            security = "tls" if str(outbound.get("tls") or "").lower() in {"tls", "true", "1"} else "none"
        else:
            host, port = (parsed.host or "").lower(), parsed.port or 0
            network = parsed.first("type", "tcp").lower()
            security = parsed.first("security", "none").lower()
        return "|".join((parsed.scheme, host, str(port), network, security))
    except Exception:
        return "|".join(("invalid", parsed.canonical))


def run_proxy_test(uri, xray_binary):
    """Run one Xray probe and return structured diagnostics."""
    started = time.perf_counter()
    parsed = ProxyURI.parse(uri)
    host, port = parsed.host, parsed.port
    if parsed.scheme == "vmess":
        vmess = legacy._vmess_object(parsed.raw)
        host = str(vmess.get("add") or vmess.get("address") or "")
        try:
            port = int(vmess.get("port") or 0)
        except (TypeError, ValueError):
            port = None
    tcp_ping = False
    if host and port:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                tcp_ping = True
        except OSError:
            pass

    try:
        ok, reason = legacy._test_one_with_xray(parsed.raw, xray_binary)
    except Exception as exc:
        ok, reason = False, f"validator-exception: {type(exc).__name__}: {exc}"

    statuses = []
    for token in reason.replace("[", " ").replace("]", " ").replace(",", " ").split():
        if token.isdigit() and 100 <= int(token) <= 599:
            statuses.append(int(token))
    return ResultTest(
        tcp_ping=tcp_ping,
        proxy_get=bool(ok),
        xray_started=not reason.startswith(("xray-config:", "xray-start:", "xray-timeout:")),
        http_statuses=statuses,
        elapsed_ms=round((time.perf_counter() - started) * 1000),
        reason=reason,
    )


def collect(cfg):
    source_cfg = cfg.get("sources", {})
    path = Path(source_cfg.get("path", "usual-sub/legacy/proxy_sources.txt"))
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        raise FileNotFoundError(f"Sources list not found: {path}")
    urls = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    result, seen = [], set()
    byte_limit = int(source_cfg.get("max_source_bytes", 20 * 1024 * 1024))
    timeout = int(source_cfg.get("fetch_timeout_seconds", 30))
    for url in urls:
        try:
            chunks, size = [], 0
            with requests.get(url, headers={"User-Agent": "LIKVID-VPN-ETL/1.0"}, timeout=timeout, stream=True) as response:
                response.raise_for_status()
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > byte_limit:
                        raise ValueError("source exceeds configured byte limit")
                    chunks.append(chunk)
            raw = b"".join(chunks).decode("utf-8", errors="replace")
            for raw_uri in legacy.extract_uris(raw):
                parsed_uri = ProxyURI.parse(raw_uri)
                if parsed_uri.raw not in seen:
                    seen.add(parsed_uri.raw)
                    result.append(parsed_uri)
            logger.info("Collected source {}: {} cumulative links", url, len(result))
        except Exception as exc:
            logger.warning("Collect source {} failed: {}: {}", url, type(exc).__name__, exc)
    return result


def write_lines(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(f"{chr(10).join(str(line).rstrip() for line in lines)}\n", encoding="utf-8")
    tmp.replace(path)


def run(config_path, xray_binary):
    cfg = load_config(config_path); pipeline = cfg.get("pipeline", {}); outcfg = cfg.get("outputs", {})
    records, rejected, report = [], [], {"pipeline": pipeline.get("name", "likvid"), "started_at": datetime.now(timezone.utc).isoformat(), "stages": [], "clusters": []}
    enabled = [s for s in cfg["stages"] if s.get("enabled", True)]
    for st in enabled:
        name, before, t0 = st["name"], len(records), time.monotonic()
        if name == "collect": records = collect(cfg)
        elif name == "filter_unsupported":
            keep=[]
            for uri in records:
                if st.get("skip_mlkem", True) and legacy.is_mlkem_encryption_proxy(uri.raw):
                    rejected.append({"uri": uri.raw, "stage": name, "reason": "unsupported ML-KEM config"})
                else:
                    keep.append(uri)
            records = keep
        elif name == "normalize":
            records = [ProxyURI.parse(uri.raw.strip()) for uri in records if uri.raw.strip()]
        elif name == "deduplicate":
            seen=set(); keep=[]
            for uri in records:
                key = ident(uri) if st.get("identity") == "uri_without_fragment" else uri.canonical
                if key in seen:
                    rejected.append({"uri": uri.raw, "stage": name, "reason": "duplicate URI"})
                else:
                    seen.add(key)
                    keep.append(uri)
            records=keep
        elif name == "cluster_analysis":
            groups=defaultdict(list)
            for u in records: groups[cluster_key(u)].append(u)
            threshold=int(st.get("warn_after",3))
            for key, members in groups.items():
                if len(members)>=threshold:
                    report["clusters"].append({"key":key,"count":len(members)})
                    logger.info("{} similar configs share endpoint profile {}; testing independently", len(members), key)
        elif name == "blocklist_filter":
            url = str(st.get("url_env", "LIKVID_BLOCKLIST_URL"))
            url = os.environ.get(url, "").strip()
            cache_path = ROOT / str(st.get("cache_path", "usual-sub/legacy/blocklist_cache.txt"))
            try:
                networks, blocklist_status = blocklist_filter.load_networks(
                    url, cache_path, int(st.get("timeout_seconds", 20))
                )
            except Exception as exc:
                raise RuntimeError(f"Blocklist stage failed safely: {exc}") from exc
            blocked = []
            keep = []
            network_index = blocklist_filter.build_network_index(networks)
            if not networks:
                logger.warning("Blocklist filtering skipped: no URL and no valid cache")
            else:
                for uri in records:
                    host = uri.host
                    if uri.scheme == "vmess":
                        try:
                            vmess = legacy._vmess_object(uri.raw)
                            host = str(vmess.get("add") or vmess.get("address") or host or "")
                        except Exception:
                            pass
                    matches = blocklist_filter.find_blocked_ips(host or "", network_index)
                    if matches:
                        rejected.append({
                            "uri": uri.raw,
                            "stage": name,
                            "reason": "blocked_ip",
                            "matched_ips": matches,
                            "blocklist_status": blocklist_status,
                        })
                        blocked.append(uri)
                    else:
                        keep.append(uri)
                records = keep
            report.setdefault("blocklist", {}).update({
                "status": blocklist_status,
                "network_count": len(networks),
                "filtered_configs": len(blocked),
                "url_configured": bool(url),
            })
            logger.info("Blocklist filter: status={} networks={} rejected={} remaining={}",
                        blocklist_status, len(networks), len(blocked), len(records))
        elif name == "xray_probe":
            if not xray_binary or not Path(xray_binary).exists(): raise RuntimeError("Xray binary missing; set XRAY_BINARY or --xray-binary")
            if st.get("core", "xray") != "xray" or st.get("mode", "proxy_get") != "proxy_get" or st.get("request_mode", "keepalive") != "keepalive":
                raise ValueError("This profile requires Xray + proxy_get + keepalive")
            legacy.PING_TYPE="proxy_get"; legacy.PING_MODE="keepalive"
            legacy.PING_URL=str(st.get("test_url","https://www.gstatic.com/generate_204")); legacy.PING_TIMEOUT=float(st.get("timeout_seconds",8))
            legacy.EXPECTED_STATUS_CODES={int(code) for code in st.get("accepted_status_codes", [204])}
            if not legacy.EXPECTED_STATUS_CODES: raise ValueError("accepted_status_codes must not be empty")
            workers=max(1,int(st.get("workers",8))); attempts=max(1,int(st.get("attempts",2))); delay=max(0,float(st.get("retry_delay_seconds",0.5)))
            final={}; pending=list(records)
            for attempt in range(1,attempts+1):
                if not pending: break
                if attempt>1 and delay: time.sleep(delay)
                results=[None]*len(pending)
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {pool.submit(run_proxy_test, uri, xray_binary): index for index, uri in enumerate(pending)}
                    for f in concurrent.futures.as_completed(futures):
                        i=futures[f]
                        try:
                            results[i] = f.result()
                        except Exception as exc:
                            results[i] = ResultTest(reason=f"validator-exception: {type(exc).__name__}: {exc}")
                failed=[]
                for uri, result in zip(pending, results):
                    result = result or ResultTest(reason="missing validation result")
                    final[uri.raw] = (result, attempt)
                    if not result.ok:
                        failed.append(uri)
                logger.info("Xray attempt {}/{}: {}/{} passed", attempt, attempts, len(pending) - len(failed), len(pending))
                pending=failed
            good=[]; failed_groups=defaultdict(list)
            for uri in records:
                result, attempt = final.get(uri.raw, (ResultTest(reason="no result"), attempts))
                if result.ok:
                    good.append(uri)
                else:
                    item = {"uri": uri.raw, "stage": name, "reason": result.reason, "attempts": attempt, "cluster": cluster_key(uri)}
                    rejected.append(item)
                    failed_groups[item["cluster"]].append(item)
            for key, items in failed_groups.items():
                if len(items)>=int(st.get("cluster_failure_warning",3)):
                    logger.warning("{} variants in cluster {} failed all probes", len(items), key)
            records=good
        elif name == "stability_check":
            # Probe stage retries failed nodes; only nodes with a successful tunnel GET remain.
            pass
        report["stages"].append({"name":name,"input":before,"output":len(records),"elapsed_seconds":round(time.monotonic()-t0,2)})
        logger.info("Stage {}: {} -> {}", name, before, len(records))
    if not any(s["name"]=="collect" for s in enabled): raise ValueError("Pipeline requires collect stage")
    initial=max(1,report["stages"][0]["output"] if report["stages"] else len(records)); ratio=len(records)/initial
    if pipeline.get("fail_on_empty",True) and not records: raise RuntimeError("Safety stop: zero working configs; existing subscription preserved")
    min_count=int(pipeline.get("min_output_configs",5)); min_ratio=float(pipeline.get("min_output_ratio",0.03))
    if len(records)<min_count or ratio<min_ratio: raise RuntimeError(f"Safety stop: only {len(records)}/{initial} configs passed ({ratio:.1%}); outputs preserved")
    records = legacy.add_country_labels([uri.raw for uri in records])[:int(outcfg.get("max_configs", 1000))]
    paths={k:Path(v) for k,v in outcfg.items() if k in {"working","rejected","report","subscription"}}
    paths={k:(v if v.is_absolute() else ROOT/v) for k,v in paths.items()}
    # Prepare all content first. Replace subscription atomically only after safety checks pass.
    write_lines(paths.get("working",ROOT/"usual-sub/legacy/parsed_proxies.txt"),records)
    write_lines(paths.get("rejected",ROOT/"usual-sub/legacy/rejected_proxies.txt"),[json.dumps(x,ensure_ascii=False) for x in rejected])
    report.update({"accepted":len(records),"rejected":len(rejected),"finished_at":datetime.now(timezone.utc).isoformat()})
    reasons=defaultdict(int)
    for item in rejected: reasons[str(item.get("reason","unknown")).split(":",1)[0]]+=1
    report["rejection_reasons"]=dict(reasons)
    rp=paths.get("report",ROOT/"usual-sub/legacy/validation_report.json"); rp.parent.mkdir(parents=True,exist_ok=True); rp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    output=[legacy.rename_uri(u,i) for i,u in enumerate(records,1)]
    updated=(datetime.now(timezone.utc)+timedelta(hours=3)).strftime("%d.%m.%Y %H:%M")
    header_lines = [
        "#profile-title: LIKVID VPN",
        "#support-url: https://t.me/cheesyx",
        "#profile-web-page-url: https://t.me/LIKVID_VPN",
        "#profile-update-interval: 1",
        f"#announce: вся важная информация в канале @LIKVID_VPN // авторы @rudy_bd @cheesyx // обновлено: {updated} | конфигов: {len(output)}",
        legacy.build_happ_routing_link(),
        *output,
    ]
    result = f"{chr(10).join(header_lines)}\n"
    sp=paths.get("subscription",ROOT/"usual-sub/legacy/proxies.txt"); sp.parent.mkdir(parents=True,exist_ok=True); tmp=sp.with_suffix(sp.suffix+".tmp"); tmp.write_text(result,encoding="utf-8"); tmp.replace(sp)
    logger.info("Done: accepted={} rejected={} report={}", len(output), len(rejected), rp)
    return 0

if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--config",default="configs/strict.yaml"); ap.add_argument("--xray-binary",default=os.environ.get("XRAY_BINARY","")); args=ap.parse_args()
    cp=Path(args.config); cp=cp if cp.is_absolute() or cp.exists() else ROOT/cp
    try: raise SystemExit(run(cp,args.xray_binary))
    except Exception as e: logger.exception("Pipeline failed: {}: {}", type(e).__name__, e); raise SystemExit(1)
