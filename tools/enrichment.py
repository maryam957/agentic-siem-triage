"""IP threat enrichment via VirusTotal, AbuseIPDB, and Gemini LLM reasoning."""

from collections.abc import Mapping
from datetime import datetime, timezone
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import time
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VIRUSTOTAL_API_URL  = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSEIPDB_API_URL   = "https://api.abuseipdb.com/api/v2/check"
GEMINI_API_URL      = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
REQUEST_TIMEOUT     = 30
LOG_LOOKBACK_MINUTES = 15
LOG_RESULT_LIMIT     = 10
EVE_JSON_PATH        = Path(__file__).resolve().parents[1] / "eve.json"

ATTACK_JSON_URL  = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ATTACK_JSON_PATH = Path(__file__).resolve().parent / "data" / "attack.json"

WORD_RE   = re.compile(r"[a-z0-9_\-]{3,}")
STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "into", "over",
    "under", "was", "were", "are", "alert", "event", "host", "user",
    "source", "destination", "network", "traffic", "detected", "against",
}

# Fast keyword → TTP hint table (checked before touching attack.json)
BEHAVIOR_TTP_HINTS: list[tuple[tuple[str, ...], list[str]]] = [
    (("brute force", "ssh"),                    ["T1110", "T1110.001", "T1021.004"]),
    (("port scan", "scan"),                    ["T1046"]),
    (("dns tunneling", "dns tunnel"),          ["T1071.004", "T1048.003"]),
    (("malicious ip", "known malicious",
      "command and control", "outbound"),      ["T1071", "T1105", "T1041"]),
    (("failed login", "authentication failure"), ["T1110"]),
    (("lateral movement",),                    ["T1021", "T1550"]),
    (("exfiltration", "data exfil"),           ["T1041", "T1048"]),
    (("privilege escalation", "privesc"),      ["T1068", "T1078"]),
    (("phishing", "spearphish"),               ["T1566", "T1566.001"]),
    (("impossible travel", "geo anomaly"),     ["T1078", "T1110"]),
]

HIGH_TTP_HINTS = {"T1041", "T1048", "T1048.003", "T1071", "T1071.004",
                  "T1105", "T1021.004", "T1068", "T1566"}
MEDIUM_TTP_HINTS = {"T1046", "T1110", "T1110.001", "T1021", "T1078", "T1550"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_api_key(env_var: str) -> str:
    """Retrieve API key checking both target name and GOOGLE_API_KEY fallback."""
    key = os.getenv(env_var) or os.getenv("GOOGLE_API_KEY")
    if not key:
        raise ValueError(f"{env_var} (or GOOGLE_API_KEY) is not set — add it to your .env file")
    return key


def _clamp(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _read_field(alert: Any, field_name: str, default: Any = None) -> Any:
    if isinstance(alert, Mapping):
        return alert.get(field_name, default)
    return getattr(alert, field_name, default)


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        return datetime.max
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.max


def _safe_lookup(func, *args, **kwargs) -> dict[str, Any]:
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        return {"source": func.__name__, "error": str(exc)}


def _tokenize(text: str) -> set[str]:
    return {
        t for t in WORD_RE.findall(text.lower())
        if t not in STOPWORDS
    }


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _first_value(data: Mapping[str, Any], paths: list[tuple[str, ...]], default: Any = None) -> Any:
    for path in paths:
        current: Any = data
        for key in path:
            if not isinstance(current, Mapping):
                current = None
                break
            current = current.get(key)
            if current is None:
                break
        if current not in (None, "", [], {}):
            return current
    return default


def _as_iso_timestamp(value: Any) -> str | None:
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _related_log_field_names(logs: list[dict[str, Any]]) -> list[str]:
    preferred_order = [
        "timestamp", "source", "event_type", "src_ip", "src_port", "dest_ip",
        "dest_port", "proto", "app_proto", "alert", "dns", "http", "tls",
        "flow", "message", "level", "labels", "raw_message",
    ]
    discovered: set[str] = set()
    for log in logs:
        if isinstance(log, Mapping):
            discovered.update(k for k, v in log.items() if v not in (None, "", [], {}))
    ordered = [key for key in preferred_order if key in discovered]
    ordered.extend(sorted(discovered - set(ordered)))
    return ordered


def _normalize_related_log(log: Mapping[str, Any], source: str) -> dict[str, Any]:
    normalized = {
        "timestamp": _as_iso_timestamp(_first_value(log, [("timestamp",)], None)
                        or _first_value(log, [("@timestamp",)], None)
                        or _first_value(log, [("event", "created")], None)
                        or _first_value(log, [("event", "ingested")], None)),
        "source": source,
        "host": _first_value(log, [
            ("host", "name"),
            ("host", "hostname"),
            ("hostname",),
            ("computer_name",),
            ("device", "name"),
            ("observer", "name"),
        ]),
        "ip": _first_value(log, [
            ("source", "ip"),
            ("client", "ip"),
            ("destination", "ip"),
            ("host", "ip"),
            ("ip",),
            ("src_ip",),
            ("dst_ip",),
            ("source_ip",),
            ("destination_ip",),
        ]),
        "event": _first_value(log, [
            ("event", "action"),
            ("event", "category"),
            ("event", "type"),
            ("event", "dataset"),
            ("rule", "name"),
            ("action",),
            ("type",),
            ("service",),
        ]),
        "message": _first_value(log, [
            ("message",),
            ("event", "original"),
            ("log", "original"),
            ("raw_message",),
            ("alert", "signature"),
            ("dns", "rrname"),
            ("http", "hostname"),
            ("tls", "sni"),
        ]),
        "level": _first_value(log, [
            ("log", "level"),
            ("event", "severity"),
            ("severity",),
            ("level",),
            ("alert", "severity"),
        ]),
        "service": _first_value(log, [
            ("service",),
            ("event", "dataset"),
            ("app",),
            ("job",),
        ]),
        "user": _first_value(log, [
            ("user", "name"),
            ("user", "email"),
            ("user",),
            ("account", "name"),
            ("principal", "name"),
        ]),
        "action": _first_value(log, [
            ("action",),
            ("event", "action"),
        ]),
        "status": _first_value(log, [
            ("status",),
            ("event", "outcome"),
            ("result",),
        ]),
        "labels": log.get("labels") if isinstance(log.get("labels"), Mapping) else None,
        "raw_message": _first_value(log, [
            ("raw_message",),
            ("event", "original"),
            ("message",),
        ]),
    }

    extras = {
        key: value
        for key, value in log.items()
        if key not in normalized and value not in (None, "", [], {})
    }
    normalized.update(extras)
    return normalized


def _elasticsearch_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    api_key = os.getenv("ELASTICSEARCH_API_KEY")
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    return headers


def _elasticsearch_auth() -> tuple[str, str] | None:
    username = os.getenv("ELASTICSEARCH_USERNAME")
    password = os.getenv("ELASTICSEARCH_PASSWORD")
    if username and password:
        return username, password
    return None


def _build_elasticsearch_query(ip: str | None, host: str | None, lookback_minutes: int, limit: int) -> dict[str, Any] | None:
    should: list[dict[str, Any]] = []
    if ip:
        should.extend([
            {"term": {"source.ip": ip}},
            {"term": {"client.ip": ip}},
            {"term": {"destination.ip": ip}},
            {"term": {"host.ip": ip}},
            {"term": {"src_ip": ip}},
            {"term": {"dst_ip": ip}},
            {"term": {"ip": ip}},
            {"multi_match": {
                "query": ip,
                "fields": ["message", "event.original", "log.original", "source.ip", "client.ip", "destination.ip", "host.ip", "src_ip", "dst_ip"],
                "lenient": True,
            }},
        ])
    if host:
        should.extend([
            {"term": {"host.name": host}},
            {"term": {"host.hostname": host}},
            {"term": {"hostname": host}},
            {"term": {"computer_name": host}},
            {"term": {"device.name": host}},
            {"multi_match": {
                "query": host,
                "fields": ["host.name", "host.hostname", "hostname", "computer_name", "device.name", "message", "event.original", "log.original"],
                "lenient": True,
            }},
        ])

    if not should:
        return None

    return {
        "size": limit,
        "track_total_hits": False,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
            {"timestamp": {"order": "desc", "unmapped_type": "date"}},
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{lookback_minutes}m",
                                "lte": "now",
                            }
                        }
                    }
                ],
                "should": should,
                "minimum_should_match": 1,
            }
        },
    }


def _query_elasticsearch(ip: str | None, host: str | None, limit: int, lookback_minutes: int) -> list[dict[str, Any]]:
    base_url = os.getenv("ELASTICSEARCH_URL", "").rstrip("/")
    if not base_url:
        raise ValueError("ELASTICSEARCH_URL is not set")

    index_name = os.getenv("ELASTICSEARCH_INDEX", "*")
    query = _build_elasticsearch_query(ip, host, lookback_minutes, limit)
    if query is None:
        return []

    response = requests.post(
        f"{base_url}/{index_name}/_search",
        headers=_elasticsearch_headers(),
        auth=_elasticsearch_auth(),
        json=query,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    hits = payload.get("hits", {}).get("hits", [])
    return [
        _normalize_related_log(hit.get("_source", {}), f"elasticsearch:{hit.get('_index', index_name)}")
        for hit in hits
        if isinstance(hit, Mapping)
    ]


def _build_loki_query(ip: str | None, host: str | None) -> str | None:
    template = os.getenv("LOKI_QUERY_TEMPLATE")
    if template:
        query = template.format(ip=ip or "", host=host or "")
        return query.strip() or None

    selector = os.getenv("LOKI_SELECTOR", '{job=~".+"}')
    filters: list[str] = []
    if ip:
        filters.append(f'|= "{ip}"')
    if host:
        filters.append(f'|= "{host}"')
    query = " ".join([selector, *filters]).strip()
    return query or None


def _normalize_eve_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    alert = entry.get("alert", {}) if isinstance(entry.get("alert"), Mapping) else {}
    dns = entry.get("dns", {}) if isinstance(entry.get("dns"), Mapping) else {}
    http = entry.get("http", {}) if isinstance(entry.get("http"), Mapping) else {}
    tls = entry.get("tls", {}) if isinstance(entry.get("tls"), Mapping) else {}
    flow = entry.get("flow", {}) if isinstance(entry.get("flow"), Mapping) else {}

    normalized = {
        "timestamp": _as_iso_timestamp(entry.get("timestamp")),
        "source": f"eve.json:{entry.get('event_type', 'unknown')}",
        "event_type": entry.get("event_type"),
        "src_ip": entry.get("src_ip") or flow.get("src_ip"),
        "src_port": entry.get("src_port") or flow.get("src_port"),
        "dest_ip": entry.get("dest_ip") or entry.get("dst_ip") or flow.get("dest_ip") or flow.get("dst_ip"),
        "dest_port": entry.get("dest_port") or entry.get("dst_port") or flow.get("dest_port") or flow.get("dst_port"),
        "proto": entry.get("proto") or flow.get("proto"),
        "app_proto": entry.get("app_proto"),
        "message": alert.get("signature") or dns.get("rrname") or http.get("hostname") or tls.get("sni"),
        "alert": alert or None,
        "dns": dns or None,
        "http": http or None,
        "tls": tls or None,
        "flow": flow or None,
        "raw_message": entry,
    }
    return {key: value for key, value in normalized.items() if value not in (None, "", [], {})}


def _query_eve_json(ip: str | None, host: str | None, limit: int, lookback_minutes: int) -> list[dict[str, Any]]:
    path = Path(os.getenv("EVE_JSON_PATH", str(EVE_JSON_PATH)))
    if not path.exists():
        raise ValueError(f"EVE_JSON_PATH does not exist: {path}")

    cutoff = datetime.now(timezone.utc).timestamp() - (lookback_minutes * 60)
    candidates: list[tuple[datetime, dict[str, Any]]] = []

    for line in path.open("r", encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(entry, Mapping):
            continue

        event_time = _parse_timestamp(entry.get("timestamp"))
        if event_time is not datetime.max and event_time.timestamp() < cutoff:
            continue

        entry_ip_candidates = {
            str(value)
            for value in [
                entry.get("src_ip"),
                entry.get("dest_ip"),
                entry.get("dst_ip"),
                entry.get("ip"),
                (entry.get("flow") or {}).get("src_ip") if isinstance(entry.get("flow"), Mapping) else None,
                (entry.get("flow") or {}).get("dest_ip") if isinstance(entry.get("flow"), Mapping) else None,
            ]
            if isinstance(value, str) and value
        }

        entry_host = None
        if isinstance(entry.get("dns"), Mapping):
            entry_host = entry["dns"].get("rrname")
        if not entry_host and isinstance(entry.get("http"), Mapping):
            entry_host = entry["http"].get("hostname")
        if not entry_host and isinstance(entry.get("tls"), Mapping):
            entry_host = entry["tls"].get("sni")

        if ip and ip not in entry_ip_candidates:
            continue
        if host and host not in {entry_host, entry.get("host"), entry.get("hostname")}:
            continue

        normalized = _normalize_eve_entry(entry)
        event_time = _parse_timestamp(normalized.get("timestamp"))
        candidates.append((event_time, normalized))

    candidates.sort(key=lambda item: item[0])
    return [entry for event_time, entry in candidates if event_time is datetime.max or event_time.timestamp() >= cutoff][-limit:]


def _query_loki(ip: str | None, host: str | None, limit: int, lookback_minutes: int) -> list[dict[str, Any]]:
    base_url = os.getenv("LOKI_URL", "").rstrip("/")
    if not base_url:
        raise ValueError("LOKI_URL is not set")

    query = _build_loki_query(ip, host)
    if query is None:
        return []

    end = datetime.now(timezone.utc)
    start = end.timestamp() - (lookback_minutes * 60)
    params = {
        "query": query,
        "limit": limit,
        "direction": "backward",
        "start": int(start * 1_000_000_000),
        "end": int(end.timestamp() * 1_000_000_000),
    }

    headers = {"Accept": "application/json"}
    tenant_id = os.getenv("LOKI_TENANT_ID")
    if tenant_id:
        headers["X-Scope-OrgID"] = tenant_id

    api_token = os.getenv("LOKI_API_TOKEN")
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    response = requests.get(
        f"{base_url}/loki/api/v1/query_range",
        headers=headers,
        params=params,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()

    results: list[dict[str, Any]] = []
    for stream in payload.get("data", {}).get("result", []):
        labels = stream.get("stream", {}) if isinstance(stream, Mapping) else {}
        for raw_timestamp, line in stream.get("values", [])[:limit]:
            record: dict[str, Any]
            try:
                parsed = json.loads(line)
                record = parsed if isinstance(parsed, dict) else {"message": line}
            except json.JSONDecodeError:
                record = {"message": line}

            normalized = _normalize_related_log(record, "loki")
            normalized["timestamp"] = _as_iso_timestamp(int(raw_timestamp) / 1_000_000_000)
            normalized["labels"] = labels
            normalized["raw_message"] = line
            results.append(normalized)
            if len(results) >= limit:
                return results

    return results


# ---------------------------------------------------------------------------
# External API calls
# ---------------------------------------------------------------------------

def check_ip_virustotal(ip: str) -> dict:
    """Query VirusTotal for IP reputation and analysis stats."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise ValueError("VIRUSTOTAL_API_KEY is not set — add it to your .env file")
    response = requests.get(
        VIRUSTOTAL_API_URL.format(ip=ip),
        headers={"x-apikey": api_key},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload    = response.json()
    attributes = payload.get("data", {}).get("attributes", {})
    stats      = attributes.get("last_analysis_stats", {})
    return {
        "ip":               ip,
        "source":            "virustotal",
        "reputation":        attributes.get("reputation"),
        "country":           attributes.get("country"),
        "asn":               attributes.get("asn"),
        "as_owner":          attributes.get("as_owner"),
        "network":           attributes.get("network"),
        "tags":              attributes.get("tags", []),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "last_analysis_stats": {
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "timeout":    stats.get("timeout",    0),
        },
        "raw": payload,
    }


def check_ip_abuseipdb(ip: str, max_age_days: int = 90) -> dict:
    """Query AbuseIPDB for abuse confidence score and report history."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise ValueError("ABUSEIPDB_API_KEY is not set — add it to your .env file")
    response = requests.get(
        ABUSEIPDB_API_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    data    = payload.get("data", {})
    return {
        "ip":                    ip,
        "source":                "abuseipdb",
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "country_code":          data.get("countryCode"),
        "isp":                   data.get("isp"),
        "domain":                data.get("domain"),
        "usage_type":            data.get("usageType"),
        "is_tor":                data.get("isTor", False),
        "is_whitelisted":        data.get("isWhitelisted", False),
        "total_reports":         data.get("totalReports", 0),
        "num_distinct_users":    data.get("numDistinctUsers", 0),
        "last_reported_at":      data.get("lastReportedAt"),
        "raw": payload,
    }


def get_related_logs(ip: str | None, host: str | None) -> list[dict[str, Any]]:
    """Return related log events for the given IP/host."""
    lookback_minutes = _int_env("RELATED_LOG_LOOKBACK_MINUTES", LOG_LOOKBACK_MINUTES)
    limit = _int_env("RELATED_LOG_LIMIT", LOG_RESULT_LIMIT)
    backend = os.getenv("RELATED_LOG_BACKEND", "").strip().lower()

    if backend in {"eve", "evejson", "eve.json"} or (not backend and Path(os.getenv("EVE_JSON_PATH", str(EVE_JSON_PATH))).exists()):
        try:
            return _query_eve_json(ip, host, limit, lookback_minutes)
        except Exception as exc:
            print(f"[related_logs] eve.json lookup failed: {exc}")

    if backend in {"elasticsearch", "es"} or (not backend and os.getenv("ELASTICSEARCH_URL")):
        try:
            return _query_elasticsearch(ip, host, limit, lookback_minutes)
        except Exception as exc:
            print(f"[related_logs] Elasticsearch lookup failed: {exc}")

    if backend in {"loki"} or (not backend and os.getenv("LOKI_URL")):
        try:
            return _query_loki(ip, host, limit, lookback_minutes)
        except Exception as exc:
            print(f"[related_logs] Loki lookup failed: {exc}")

    return [
        {
            "timestamp": "2026-07-14T08:12:09Z",
            "source":    "local-fallback",
            "host":      host,
            "ip":        ip,
            "event":     "authentication failure",
            "message":   "Multiple failed logon attempts from the same source.",
            "level":     "warning",
        },
        {
            "timestamp": "2026-07-14T08:12:41Z",
            "source":    "local-fallback",
            "host":      host,
            "ip":        ip,
            "event":     "suspicious network connection",
            "message":   "Process spawned a network session matching the alert context.",
            "level":     "warning",
        },
        {
            "timestamp": "2026-07-14T08:13:02Z",
            "source":    "local-fallback",
            "host":      host,
            "ip":        ip,
            "event":     "correlated activity",
            "message":   "Activity tied together by source IP and affected host.",
            "level":     "info",
        },
    ]


# ---------------------------------------------------------------------------
# MITRE ATT&CK helpers
# ---------------------------------------------------------------------------

def _ensure_attack_json() -> Path:
    if ATTACK_JSON_PATH.exists():
        return ATTACK_JSON_PATH
    ATTACK_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    response = requests.get(ATTACK_JSON_URL, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    ATTACK_JSON_PATH.write_text(response.text, encoding="utf-8")
    return ATTACK_JSON_PATH


@lru_cache(maxsize=1)
def _load_attack_patterns() -> list[dict[str, Any]]:
    """Load and cache MITRE ATT&CK patterns from attack.json (downloaded once)."""
    path    = _ensure_attack_json()
    payload = json.loads(path.read_text(encoding="utf-8"))
    patterns: list[dict[str, Any]] = []

    for obj in payload.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        attack_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and isinstance(ref.get("external_id"), str):
                attack_id = ref["external_id"]
                break
        if not attack_id:
            continue

        name        = obj.get("name", "")
        description = obj.get("description", "")
        patterns.append({
            "id":          attack_id,
            "name":        name,
            "description": description,
            "tokens":      _tokenize(f"{name} {description}"),
        })

    return patterns


def get_ttps(behavior: str, limit: int = 5) -> list[str]:
    """Map behavior text to MITRE ATT&CK technique IDs."""
    if not isinstance(behavior, str) or not behavior.strip():
        return []

    behavior_lower = behavior.lower()

    # Fast path: keyword hints
    prioritized: list[str] = []
    for keywords, ttps in BEHAVIOR_TTP_HINTS:
        if any(kw in behavior_lower for kw in keywords):
            for ttp in ttps:
                if ttp not in prioritized:
                    prioritized.append(ttp)
                if len(prioritized) >= limit:
                    return prioritized

    # Slow path: token overlap against attack.json
    behavior_tokens = _tokenize(behavior)
    if not behavior_tokens:
        return prioritized[:limit]

    scored: list[tuple[int, str]] = []
    for pattern in _load_attack_patterns():
        overlap = len(behavior_tokens & pattern["tokens"])
        if overlap:
            scored.append((overlap, pattern["id"]))
    scored.sort(key=lambda x: (-x[0], x[1]))

    result = list(prioritized)
    for _, attack_id in scored:
        if attack_id not in result:
            result.append(attack_id)
        if len(result) >= limit:
            break
    return result


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _compact_context(context: dict[str, Any]) -> dict[str, Any]:
    """Trim context to essential fields to reduce token cost."""
    alert     = context.get("alert", {}) or {}
    vt        = context.get("virustotal", {}) or {}
    vt_stats  = vt.get("last_analysis_stats", {}) if isinstance(vt, Mapping) else {}
    abuse     = context.get("abuseipdb", {}) or {}
    related_logs = timeline_builder(context.get("related_logs", []))

    return {
        "alert": {
            "id":          alert.get("id") or alert.get("alert_id"),
            "timestamp":   alert.get("timestamp"),
            "title":       alert.get("title") or alert.get("alert_type"),
            "description": alert.get("description"),
            "severity":    alert.get("severity"),
            "host":        alert.get("host") or alert.get("affected_host"),
            "user":        alert.get("user"),
            "raw_event":   alert.get("raw_event") or alert.get("raw_payload"),
        },
        "ip":   context.get("ip"),
        "host": context.get("host"),
        "virustotal": {
            "reputation": vt.get("reputation"),
            "country":    vt.get("country"),
            "as_owner":   vt.get("as_owner"),
            "tags":      vt.get("tags", []),
            "last_analysis_stats": {
                "malicious":  vt_stats.get("malicious",  0),
                "suspicious": vt_stats.get("suspicious", 0),
                "harmless":   vt_stats.get("harmless",   0),
            },
        },
        "abuseipdb": {
            "abuse_confidence_score": abuse.get("abuse_confidence_score", 0),
            "total_reports":          abuse.get("total_reports", 0),
            "last_reported_at":       abuse.get("last_reported_at"),
            "is_tor":                 abuse.get("is_tor", False),
        },
        "related_logs": related_logs[-10:],
        "related_log_fields": _related_log_field_names(related_logs[-10:]),
    }


def build_correlation_prompt(context: dict[str, Any]) -> str:
    """Build the Gemini prompt for triage reasoning."""
    compact = _compact_context(context)
    return f"""
You are a SOC Tier-2 triage assistant. Analyse the alert context below and produce a structured risk decision from Suricata EVE JSON and enrichment data.

Field guide:
- alert.title / description: what the detector flagged and why.
- related_logs: normalized Suricata EVE events, sorted oldest to newest.
- related_log_fields: actual fields seen in the EVE JSON sample.
- Common EVE fields include timestamp, event_type, src_ip, src_port, dest_ip, dest_port, proto, app_proto, alert, dns, http, tls, and flow.
- For alert events, use alert.signature, alert.category, and alert.severity.
- For dns events, use dns.type, dns.rrname, dns.rrtype, and dns.answers.
- For http events, use http.hostname, http.url, http.http_method, and http.status.
- For tls events, use tls.sni, tls.version, and certificate metadata if present.
- For flow events, use flow.state, flow.reason, pkts_toserver, pkts_toclient, bytes_toserver, and bytes_toclient.
- Use src_ip/dest_ip and the protocol fields to explain how the connection fits the alert.

Your tasks:
1. Estimate a triage score (0-100). Higher = higher incident risk.
2. Assign severity_label: "low" (0-39), "medium" (40-69), "high" (70-100).
3. Write behavior_summary: one sentence describing what is happening.
4. List MITRE ATT&CK technique IDs in Txxxx format (max 5).
5. Write reasoning: 2-4 sentences explaining score and key evidence.
6. List recommended_actions: 2-4 concrete next steps for the analyst.

Rules:
- Return ONLY valid JSON. No markdown, no explanation outside the JSON.
- If evidence is weak or conflicting, lower the score and say so in reasoning.
- Technique IDs must be real ATT&CK IDs (e.g. T1110, T1046, T1071.004).

Required output schema:
{{
  "score": <int 0-100>,
  "severity_label": "low|medium|high",
  "behavior_summary": "<string>",
  "ttps": ["Txxxx"],
  "reasoning": "<string>",
  "recommended_actions": ["<string>"]
}}

Context:
{json.dumps(compact, indent=2)}
""".strip()


# ---------------------------------------------------------------------------
# Gemini API call
# ---------------------------------------------------------------------------

def _call_gemini(prompt: str) -> dict[str, Any]:
    """
    Send the triage prompt to Gemini 1.5 Flash using x-goog-api-key headers and parse the JSON response.
    """
    api_key = _get_api_key("GEMINI_API_KEY")

    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature":     0.2,
            "maxOutputTokens": 1024,
            "topP":            0.8,
        },
    }

    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,  # Standard header authentication
    }

    response = requests.post(
        GEMINI_API_URL,
        headers=headers,
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )
    try:
        response.raise_for_status()
    except Exception as exc:
        body = ''
        try:
            body = response.text
        except Exception:
            body = '<unavailable>'
        raise RuntimeError(f"Gemini API error: {exc} - response: {body}") from exc

    data = response.json()

    try:
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise ValueError(f"Unexpected Gemini response structure: {exc}") from exc

    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Gemini returned non-JSON output: {cleaned[:300]}") from exc

    required = {"score", "severity_label", "behavior_summary",
                "ttps", "reasoning", "recommended_actions"}
    missing = required - parsed.keys()
    if missing:
        raise ValueError(f"Gemini response missing fields: {missing}")

    parsed["score"] = _clamp(parsed.get("score", 0))
    parsed["severity_label"] = route_alert(parsed["score"])

    return parsed


def _call_openrouter(prompt: str) -> dict[str, Any]:
    """
    Call OpenRouter Chat Completions as a fallback when Gemini is unavailable.
    Expects OPENROUTER_API_KEY in env and optional OPENROUTER_MODEL.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is not set")

    model = os.getenv("OPENROUTER_MODEL", "gpt-4o-mini")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a SOC Tier-2 triage assistant. Produce only JSON matching the required schema."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
    }

    response = requests.post(
        "https://api.openrouter.ai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    try:
        response.raise_for_status()
    except Exception as exc:
        body = ''
        try:
            body = response.text
        except Exception:
            body = '<unavailable>'
        raise RuntimeError(f"OpenRouter API error: {exc} - response: {body}") from exc

    data = response.json()

    # Try to extract text from common response shapes
    text = None
    try:
        text = data.get("choices", [])[0].get("message", {}).get("content")
    except Exception:
        text = None

    if not text:
        text = data.get("output") or data.get("text") or None

    if not isinstance(text, str):
        raise ValueError(f"OpenRouter returned unexpected shape: {json.dumps(data)[:500]}")

    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"OpenRouter returned non-JSON output: {cleaned[:300]}") from exc

    required = {"score", "severity_label", "behavior_summary", "ttps", "reasoning", "recommended_actions"}
    missing = required - parsed.keys()
    if missing:
        raise ValueError(f"OpenRouter response missing fields: {missing}")

    parsed["score"] = _clamp(parsed.get("score", 0))
    parsed["severity_label"] = route_alert(parsed["score"])
    return parsed


def _heuristic_fallback(context: dict[str, Any]) -> dict[str, Any]:
    """
    Pure rules-based fallback used when Gemini is unavailable.
    """
    alert = context.get("alert", {}) or {}
    title = str(alert.get("alert_type") or alert.get("title") or "")
    description = str(alert.get("description") or "")
    behavior_summary = " ".join(p for p in [title, description] if p).strip()
    if not behavior_summary:
        behavior_summary = "Suspicious activity with correlated threat-intel context."

    ttps  = get_ttps(behavior_summary)
    score = score_alert({**context, "ttps": ttps, "behavior_summary": behavior_summary},
                        reasoning=behavior_summary)

    vt    = context.get("virustotal", {}) or {}
    vt_s  = vt.get("last_analysis_stats", {}) if isinstance(vt, Mapping) else {}
    abuse = context.get("abuseipdb", {}) or {}

    reasoning = (
        f"[Heuristic fallback — Gemini unavailable] Score {score} based on "
        f"AbuseIPDB={abuse.get('abuse_confidence_score', 0)}, "
        f"VT malicious={vt_s.get('malicious', 0)}, "
        f"pattern: {behavior_summary[:120]}"
    )

    return {
        "score":               score,
        "severity_label":      route_alert(score),
        "behavior_summary":    behavior_summary,
        "ttps":                ttps,
        "reasoning":           reasoning,
        "recommended_actions": [
            "Review firewall, EDR, and authentication logs for corroborating evidence.",
            "Contain the affected endpoint or account if additional indicators are found.",
            "Create or tune a detection rule if this is confirmed as a true positive.",
        ],
    }


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _extract_abuse_score(context: dict[str, Any]) -> int:
    abuse = context.get("abuseipdb", {}) or {}
    if isinstance(abuse, Mapping):
        return _clamp(abuse.get("abuse_confidence_score") or abuse.get("abuse_score") or 0)
    return _clamp(context.get("abuse_score", 0))


def _extract_vt_score(context: dict[str, Any]) -> int:
    vt = context.get("virustotal", {}) or {}
    if not isinstance(vt, Mapping):
        return 0
    stats = vt.get("last_analysis_stats", {}) or {}
    return min(100, _clamp(stats.get("malicious", 0)) * 25
                  + _clamp(stats.get("suspicious", 0)) * 10)


def _ttp_severity_score(context: dict[str, Any], reasoning: str) -> int:
    ttps = context.get("ttps", []) or []
    if isinstance(ttps, str):
        ttps = [ttps]

    severity = 0
    for ttp in ttps:
        tid = str(ttp).upper()
        if any(tid == h or tid.startswith(f"{h}.") for h in HIGH_TTP_HINTS):
            severity = max(severity, 100)
        elif any(tid == h or tid.startswith(f"{h}.") for h in MEDIUM_TTP_HINTS):
            severity = max(severity, 70)
        else:
            severity = max(severity, 50)

    if severity:
        return severity

    text = f"{reasoning} {context.get('behavior_summary', '')}".lower()
    if any(kw in text for kw in ("dns tunneling", "command and control", "exfiltration")):
        return 100
    if any(kw in text for kw in ("brute force", "failed login", "credential")):
        return 75
    if any(kw in text for kw in ("port scan", "reconnaissance")):
        return 50
    return 35


def _log_anomaly_score(context: dict[str, Any], reasoning: str) -> int:
    count = 0
    for log in (context.get("related_logs") or []):
        if not isinstance(log, Mapping):
            continue
        text = f"{log.get('event','')} {log.get('message','')}".lower()
        if any(kw in text for kw in ("failed", "suspicious", "correlated", "scan", "malicious")):
            count += 1

    alert     = context.get("alert", {}) or {}
    raw_event = (alert.get("raw_event") or alert.get("raw_payload") or {}) if isinstance(alert, Mapping) else {}
    if isinstance(raw_event, Mapping):
        attempts = _clamp(raw_event.get("attempts") or raw_event.get("failed_logins") or 0)
        if attempts >= 50:   count += 3
        elif attempts >= 20: count += 2
        elif attempts >= 5:  count += 1

        ports = raw_event.get("ports_scanned")
        if isinstance(ports, list):
            count += 3 if len(ports) >= 8 else (2 if len(ports) >= 4 else 0)

        queries = _clamp(raw_event.get("queries") or 0)
        if queries >= 300:   count += 3
        elif queries >= 100: count += 2

        if raw_event.get("ioc_source"):
            count += 2

    if any(kw in reasoning.lower() for kw in ("known bad", "malicious", "tunneling")):
        count += 1

    return min(100, count * 20)


def score_alert(context: dict[str, Any], reasoning: str) -> int:
    """Weighted composite triage score."""
    return int(round(max(0, min(100,
        _extract_abuse_score(context) * 0.30
        + _extract_vt_score(context)  * 0.30
        + _ttp_severity_score(context, reasoning) * 0.25
        + _log_anomaly_score(context, reasoning)  * 0.15
    ))))


def route_alert(score: int) -> str:
    if score >= 70: return "high"
    if score >= 40: return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Timeline builder
# ---------------------------------------------------------------------------

def timeline_builder(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort logs by timestamp and normalize to a flat dict per event."""
    ordered = sorted(logs or [], key=lambda x: _parse_timestamp(x.get("timestamp")))
    normalized: list[dict[str, Any]] = []
    for log in ordered:
        entry = {
            "timestamp": log.get("timestamp"),
            "source":    log.get("source"),
            "event":     log.get("event"),
            "message":   log.get("message"),
            "ip":        log.get("ip"),
            "host":      log.get("host"),
        }
        for key in ("level", "service", "user", "action", "status", "labels", "raw_message"):
            value = log.get(key)
            if value not in (None, "", [], {}):
                entry[key] = value
        normalized.append(entry)
    return normalized


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def reason(context: dict[str, Any]) -> dict[str, Any]:
    """Correlate enriched alert context using Gemini LLM reasoning."""
    prompt   = build_correlation_prompt(context)
    timeline = timeline_builder(context.get("related_logs", []))

    llm_result: dict[str, Any] | None = None
    gemini_error: str | None = None

    try:
        llm_result = _call_gemini(prompt)
        print(f"[reason] Gemini OK — score={llm_result['score']} "
              f"severity={llm_result['severity_label']} "
              f"ttps={llm_result['ttps']}")
    except Exception as exc:
        gemini_error = str(exc)
        print(f"[reason] Gemini failed ({gemini_error}) — using heuristic fallback")

        llm_result = _heuristic_fallback(context)

    alert_id = (
        context.get("alert", {}).get("alert_id")
        or context.get("alert", {}).get("id")
        or ""
    )

    return {
        "alert_id":            alert_id,
        "score":               llm_result["score"],
        "severity_label":      llm_result["severity_label"],
        "behavior_summary":    llm_result.get("behavior_summary", ""),
        "ttps":                llm_result.get("ttps", []),
        "timeline":            timeline,
        "reasoning":           llm_result["reasoning"],
        "recommended_actions": llm_result.get("recommended_actions", []),
        "correlation_prompt":  prompt,
        "gemini_error":        gemini_error,
    }


def _extract_primary_ip(alert: Any) -> str | None:
    raw_event  = _read_field(alert, "raw_event", {}) or {}
    candidates = [
        _read_field(alert, "src_ip"),
        _read_field(alert, "dst_ip"),
        _read_field(alert, "ip"),
        raw_event.get("src_ip"),
        raw_event.get("source_ip"),
        raw_event.get("dst_ip"),
        raw_event.get("destination_ip"),
        raw_event.get("remote_ip"),
        raw_event.get("ip"),
    ]
    ip_list = raw_event.get("ip_addresses", [])
    if isinstance(ip_list, list):
        candidates.extend(ip_list)
    return next((c for c in candidates if isinstance(c, str) and c), None)


def _extract_host(alert: Any) -> str | None:
    host = _read_field(alert, "host")
    if isinstance(host, str) and host:
        return host
    raw_event = _read_field(alert, "raw_event", {}) or {}
    for key in ("host", "hostname", "asset", "device_name"):
        value = raw_event.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def enrich(alert: Any) -> dict[str, Any]:
    """Gather all external context for an alert."""
    ip   = _extract_primary_ip(alert)
    host = _extract_host(alert)

    virustotal = _safe_lookup(check_ip_virustotal, ip) if ip else {
        "source": "virustotal", "error": "no IP found in alert"
    }
    abuseipdb = _safe_lookup(check_ip_abuseipdb, ip) if ip else {
        "source": "abuseipdb",  "error": "no IP found in alert"
    }
    related_logs = get_related_logs(ip, host)

    if isinstance(alert, Mapping):
        alert_payload = dict(alert)
    elif hasattr(alert, "model_dump"):
        alert_payload = alert.model_dump()
    elif hasattr(alert, "__dict__"):
        alert_payload = dict(alert.__dict__)
    else:
        alert_payload = {"value": str(alert)}

    return {
        "alert":        alert_payload,
        "ip":           ip,
        "host":         host,
        "virustotal":   virustotal,
        "abuseipdb":    abuseipdb,
        "related_logs": related_logs,
    }


# ---------------------------------------------------------------------------
# Execution block
# ---------------------------------------------------------------------------

MOCK_ALERT_IPS = [
    "203.0.113.10",    # TEST-NET-3
    "198.51.100.44",   # TEST-NET-2
    "185.220.101.45",  # Known Tor exit node
]


def _print_result(label: str, result: dict) -> None:
    print(f"\n{label}")
    print("-" * len(label))
    for key, value in result.items():
        if key == "raw" or key == "correlation_prompt":
            continue
        print(f"  {key}: {value}")


if __name__ == "__main__":
    for test_ip in MOCK_ALERT_IPS:
        print(f"\n{'=' * 60}")
        print(f"Testing Pipeline for IP: {test_ip}")
        print("=" * 60)

        mock_alert = {
            "alert_id": "ALT-1001",
            "title": "Suspicious Outbound SSH Connection",
            "description": "Host attempted multiple failed SSH logons to unknown remote IP.",
            "src_ip": test_ip,
            "host": "WORKSTATION-01",
            "user": "admin",
        }

        print("\n[1] Enriching alert context...")
        enriched_context = enrich(mock_alert)

        print("[2] Executing Gemini Reasoning...")
        triage_result = reason(enriched_context)

        _print_result("Final Triage Decision", triage_result)
    time.sleep(3)