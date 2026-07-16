"""IP threat enrichment via VirusTotal, AbuseIPDB, and related logs."""

from collections.abc import Mapping
from datetime import datetime
from functools import lru_cache
import json
import os
from pathlib import Path
import re
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 30
ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ATTACK_JSON_PATH = Path(__file__).resolve().parent / "data" / "attack.json"
WORD_RE = re.compile(r"[a-z0-9_\-]{3,}")
STOPWORDS = {
  "the", "and", "for", "with", "from", "that", "this", "into", "over", "under", "was", "were", "are",
  "alert", "event", "host", "user", "source", "destination", "network", "traffic", "detected", "against",
}
BEHAVIOR_TTP_HINTS: list[tuple[tuple[str, ...], list[str]]] = [
  (("brute force", "ssh"), ["T1110", "T1110.001", "T1021.004"]),
  (("port scan", "scan"), ["T1046"]),
  (("dns tunneling", "dns tunnel"), ["T1071.004", "T1048.003"]),
  (("malicious ip", "known malicious", "command and control", "outbound"), ["T1071", "T1105", "T1041"]),
  (("failed login", "authentication failure"), ["T1110"]),
]


def _get_api_key(env_var: str) -> str:
  key = os.getenv(env_var)
  if not key:
    raise ValueError(f"{env_var} is not set; add it to your .env file")
  return key


def check_ip_virustotal(ip: str) -> dict:
  """Query VirusTotal for IP reputation and analysis stats."""
  api_key = _get_api_key("VIRUSTOTAL_API_KEY")
  response = requests.get(
    VIRUSTOTAL_API_URL.format(ip=ip),
    headers={"x-apikey": api_key},
    timeout=REQUEST_TIMEOUT,
  )
  response.raise_for_status()
  payload = response.json()
  attributes = payload.get("data", {}).get("attributes", {})

  stats = attributes.get("last_analysis_stats", {})
  return {
    "ip": ip,
    "source": "virustotal",
    "reputation": attributes.get("reputation"),
    "country": attributes.get("country"),
    "asn": attributes.get("asn"),
    "as_owner": attributes.get("as_owner"),
    "network": attributes.get("network"),
    "tags": attributes.get("tags", []),
    "last_analysis_date": attributes.get("last_analysis_date"),
    "last_analysis_stats": {
      "malicious": stats.get("malicious", 0),
      "suspicious": stats.get("suspicious", 0),
      "harmless": stats.get("harmless", 0),
      "undetected": stats.get("undetected", 0),
      "timeout": stats.get("timeout", 0),
    },
    "raw": payload,
  }


def check_ip_abuseipdb(ip: str, max_age_days: int = 90) -> dict:
  """Query AbuseIPDB for abuse confidence score and report history."""
  api_key = _get_api_key("ABUSEIPDB_API_KEY")
  response = requests.get(
    ABUSEIPDB_API_URL,
    headers={"Key": api_key, "Accept": "application/json"},
    params={"ipAddress": ip, "maxAgeInDays": max_age_days},
    timeout=REQUEST_TIMEOUT,
  )
  response.raise_for_status()
  payload = response.json()
  data = payload.get("data", {})

  return {
    "ip": ip,
    "source": "abuseipdb",
    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
    "country_code": data.get("countryCode"),
    "isp": data.get("isp"),
    "domain": data.get("domain"),
    "usage_type": data.get("usageType"),
    "is_tor": data.get("isTor", False),
    "is_whitelisted": data.get("isWhitelisted", False),
    "total_reports": data.get("totalReports", 0),
    "num_distinct_users": data.get("numDistinctUsers", 0),
    "last_reported_at": data.get("lastReportedAt"),
    "raw": payload,
  }


def _read_field(alert: Any, field_name: str, default: Any = None) -> Any:
  if isinstance(alert, Mapping):
    return alert.get(field_name, default)
  return getattr(alert, field_name, default)


def _extract_primary_ip(alert: Any) -> str | None:
  raw_event = _read_field(alert, "raw_event", {}) or {}
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

  ip_addresses = raw_event.get("ip_addresses", [])
  if isinstance(ip_addresses, list):
    candidates.extend(ip_addresses)

  for candidate in candidates:
    if isinstance(candidate, str) and candidate:
      return candidate
  return None


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


def get_related_logs(ip: str | None, host: str | None) -> list[dict[str, Any]]:
  """Return hardcoded related log examples for the given IP or host."""
  return [
    {
      "timestamp": "2026-07-14T08:12:09Z",
      "source": "Windows Security",
      "host": host,
      "ip": ip,
      "event": "authentication failure",
      "message": "Multiple failed logon attempts from the same source were observed.",
    },
    {
      "timestamp": "2026-07-14T08:12:41Z",
      "source": "EDR",
      "host": host,
      "ip": ip,
      "event": "suspicious network connection",
      "message": "Process spawned a network session that matches the alert context.",
    },
    {
      "timestamp": "2026-07-14T08:13:02Z",
      "source": "SIEM Correlation",
      "host": host,
      "ip": ip,
      "event": "correlated activity",
      "message": "Related activity tied together by source IP and affected host.",
    },
  ]


def _safe_lookup(func, *args, **kwargs) -> dict[str, Any]:
  try:
    return func(*args, **kwargs)
  except Exception as exc:
    return {
      "source": func.__name__,
      "error": str(exc),
    }


def _tokenize(text: str) -> set[str]:
  tokens = {
    token
    for token in WORD_RE.findall(text.lower())
    if token not in STOPWORDS
  }
  return tokens


def _parse_timestamp(value: Any) -> datetime:
  if not isinstance(value, str) or not value:
    return datetime.max

  normalized = value.replace("Z", "+00:00")
  try:
    return datetime.fromisoformat(normalized)
  except ValueError:
    return datetime.max


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
  path = _ensure_attack_json()
  payload = json.loads(path.read_text(encoding="utf-8"))

  objects = payload.get("objects", [])
  patterns: list[dict[str, Any]] = []

  for obj in objects:
    if obj.get("type") != "attack-pattern":
      continue
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
      continue

    external_refs = obj.get("external_references", [])
    attack_id = None
    for ref in external_refs:
      if ref.get("source_name") == "mitre-attack" and isinstance(ref.get("external_id"), str):
        attack_id = ref["external_id"]
        break

    if not attack_id:
      continue

    name = obj.get("name", "")
    description = obj.get("description", "")
    patterns.append(
      {
        "id": attack_id,
        "name": name,
        "description": description,
        "tokens": _tokenize(f"{name} {description}"),
      }
    )

  return patterns


def get_ttps(behavior: str, limit: int = 5) -> list[str]:
  """Map behavior text to likely MITRE ATT&CK technique IDs from attack.json."""
  if not isinstance(behavior, str) or not behavior.strip():
    return []

  behavior_lower = behavior.lower()
  prioritized: list[str] = []
  for keywords, ttps in BEHAVIOR_TTP_HINTS:
    if any(keyword in behavior_lower for keyword in keywords):
      for ttp in ttps:
        if ttp not in prioritized:
          prioritized.append(ttp)
        if len(prioritized) >= limit:
          return prioritized

  behavior_tokens = _tokenize(behavior)
  if not behavior_tokens:
    return prioritized[:limit]

  scored: list[tuple[int, str]] = []
  for pattern in _load_attack_patterns():
    overlap = len(behavior_tokens.intersection(pattern["tokens"]))
    if overlap == 0:
      continue
    scored.append((overlap, pattern["id"]))

  scored.sort(key=lambda item: (-item[0], item[1]))

  ordered_ids: list[str] = list(prioritized)
  for _, attack_id in scored:
    if attack_id not in ordered_ids:
      ordered_ids.append(attack_id)
    if len(ordered_ids) >= limit:
      break

  return ordered_ids


def timeline_builder(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
  """Order logs by timestamp and normalize each event to a plain dict."""
  ordered_logs = sorted(logs or [], key=lambda item: _parse_timestamp(item.get("timestamp")))

  timeline: list[dict[str, Any]] = []
  for log in ordered_logs:
    timeline.append(
      {
        "timestamp": log.get("timestamp"),
        "source": log.get("source"),
        "event": log.get("event"),
        "message": log.get("message"),
        "ip": log.get("ip"),
        "host": log.get("host"),
      }
    )
  return timeline


def build_correlation_prompt(context: dict[str, Any]) -> str:
  """Build a Gemini prompt that defines each field and requests strict JSON output."""
  compact_context = _compact_context_for_prompt(context)
  return f"""
You are a SOC Tier-2 triage assistant. Correlate this alert context and produce a concise risk decision.

Field definitions:
- alert: Primary SIEM alert object.
  - id/alert_id: unique alert identifier.
  - title/alert_type: short label for suspicious behavior.
  - description: analyst-friendly summary of what happened.
  - severity: original platform severity (low/medium/high/critical or numeric).
  - timestamp: when the alert was generated.
  - host/affected_host: impacted endpoint or server.
  - user: related identity if known.
  - raw_event/raw_payload: detector-specific telemetry (IPs, ports, attempts, bytes, protocol).
- ip: primary observable selected for enrichment.
- host: normalized host value used for correlation.
- virustotal: external reputation data.
  - reputation: aggregate score; lower can indicate risk.
  - last_analysis_stats.malicious/suspicious: count of engines flagging the IP.
  - tags/as_owner/country: infrastructure context.
- abuseipdb: abuse intelligence.
  - abuse_confidence_score (0-100): higher means more abuse reports.
  - total_reports/last_reported_at/is_tor: confidence boosters for maliciousness.
- related_logs: nearby telemetry events used for sequence reconstruction.

Your output goals:
1) Estimate triage score (0-100), where higher = higher incident risk.
2) Provide a severity_label in [low, medium, high].
3) Summarize behavior in one sentence for ATT&CK mapping.
4) Return likely MITRE ATT&CK technique IDs (Txxxx format only).
5) Give short reasoning and concrete next actions.

Return valid JSON only with this exact schema:
{{
  "score": <int 0-100>,
  "severity_label": "low|medium|high",
  "behavior_summary": "<string>",
  "ttps": ["Txxxx", "Txxxx"],
  "reasoning": "<2-4 sentence explanation>",
  "recommended_actions": ["<action>", "<action>"]
}}

Context JSON:
{json.dumps(compact_context, indent=2)}

If evidence is weak or conflicting, reduce confidence and mention uncertainty explicitly in reasoning.
""".strip()


def _compact_context_for_prompt(context: dict[str, Any]) -> dict[str, Any]:
  """Keep prompt context concise to reduce token usage and model drift."""
  alert = context.get("alert", {}) or {}
  vt = context.get("virustotal", {}) or {}
  vt_stats = vt.get("last_analysis_stats", {}) if isinstance(vt, Mapping) else {}
  abuse = context.get("abuseipdb", {}) or {}

  return {
    "alert": {
      "id": alert.get("id") or alert.get("alert_id"),
      "timestamp": alert.get("timestamp"),
      "title": alert.get("title") or alert.get("alert_type"),
      "description": alert.get("description"),
      "severity": alert.get("severity"),
      "host": alert.get("host") or alert.get("affected_host"),
      "user": alert.get("user"),
      "raw_event": alert.get("raw_event") or alert.get("raw_payload"),
    },
    "ip": context.get("ip"),
    "host": context.get("host"),
    "virustotal": {
      "reputation": vt.get("reputation"),
      "country": vt.get("country"),
      "as_owner": vt.get("as_owner"),
      "tags": vt.get("tags", []),
      "last_analysis_stats": {
        "malicious": vt_stats.get("malicious", 0),
        "suspicious": vt_stats.get("suspicious", 0),
        "harmless": vt_stats.get("harmless", 0),
      },
    },
    "abuseipdb": {
      "abuse_confidence_score": abuse.get("abuse_confidence_score", 0),
      "total_reports": abuse.get("total_reports", 0),
      "last_reported_at": abuse.get("last_reported_at"),
      "is_tor": abuse.get("is_tor", False),
    },
    "related_logs": timeline_builder(context.get("related_logs", []))[-10:],
  }


def _normalize_severity_label(score: int) -> str:
  if score >= 70:
    return "high"
  if score >= 40:
    return "medium"
  return "low"


def _heuristic_reasoning(context: dict[str, Any]) -> dict[str, Any]:
  alert = context.get("alert", {}) or {}
  title = str(alert.get("alert_type") or alert.get("title") or "").lower()
  description = str(alert.get("description") or "")

  vt = context.get("virustotal", {}) or {}
  vt_stats = vt.get("last_analysis_stats", {}) if isinstance(vt, Mapping) else {}
  vt_malicious = int(vt_stats.get("malicious", 0) or 0)
  vt_suspicious = int(vt_stats.get("suspicious", 0) or 0)

  abuse = context.get("abuseipdb", {}) or {}
  abuse_score = int(abuse.get("abuse_confidence_score", 0) or 0)

  severity = alert.get("severity")
  severity_seed = 0
  if isinstance(severity, int):
    severity_seed = {1: 20, 2: 40, 3: 60}.get(severity, 35)
  elif isinstance(severity, str):
    severity_seed = {
      "low": 20,
      "medium": 40,
      "high": 60,
      "critical": 75,
    }.get(severity.lower(), 35)

  score = severity_seed + (vt_malicious * 6) + (vt_suspicious * 3) + int(abuse_score * 0.25)

  if "brute force" in title:
    score += 12
  if "port scan" in title:
    score += 8
  if "malicious ip" in title or "known malicious" in title:
    score += 20
  if "dns tunneling" in title:
    score += 18

  score = max(0, min(100, score))
  severity_label = _normalize_severity_label(score)

  behavior_summary = " ".join(
    part for part in [
      str(alert.get("title") or alert.get("alert_type") or "").strip(),
      description.strip(),
    ] if part
  )

  if not behavior_summary:
    behavior_summary = "Suspicious activity observed with correlated threat-intel context."

  ttps = get_ttps(behavior_summary)

  reasoning = (
    f"Score {score} is based on alert severity, external reputation, and behavioral indicators. "
    f"VirusTotal malicious={vt_malicious}, suspicious={vt_suspicious}; AbuseIPDB score={abuse_score}. "
    f"Observed pattern: {behavior_summary[:180]}"
  )

  recommended_actions = [
    "Validate source and destination activity in firewall, EDR, and authentication logs.",
    "Contain affected endpoint or account if additional malicious evidence appears.",
    "Create or tune a detection rule for this behavior pattern if true positive.",
  ]

  return {
    "score": score,
    "severity_label": severity_label,
    "behavior_summary": behavior_summary,
    "ttps": ttps,
    "reasoning": reasoning,
    "recommended_actions": recommended_actions,
  }


def reason(context: dict[str, Any]) -> dict[str, Any]:
  """Return a TriageResult-compatible partial from correlated context."""
  llm_prompt = build_correlation_prompt(context)
  model_output = _heuristic_reasoning(context)
  timeline = timeline_builder(context.get("related_logs", []))

  return {
    "alert_id": context.get("alert", {}).get("alert_id") or context.get("alert", {}).get("id", ""),
    "score": model_output["score"],
    "severity_label": model_output["severity_label"],
    "ttps": model_output["ttps"],
    "timeline": timeline,
    "reasoning": model_output["reasoning"],
    "recommended_actions": model_output["recommended_actions"],
    "correlation_prompt": llm_prompt,
  }


def enrich(alert: Any) -> dict[str, Any]:
  """Combine threat intel and context around a single alert."""
  ip = _extract_primary_ip(alert)
  host = _extract_host(alert)

  virustotal = _safe_lookup(check_ip_virustotal, ip) if ip else {"source": "virustotal", "error": "no IP found in alert"}
  abuseipdb = _safe_lookup(check_ip_abuseipdb, ip) if ip else {"source": "abuseipdb", "error": "no IP found in alert"}
  related_logs = get_related_logs(ip, host)

  alert_payload: dict[str, Any]
  if isinstance(alert, Mapping):
    alert_payload = dict(alert)
  elif hasattr(alert, "model_dump"):
    alert_payload = alert.model_dump()
  elif hasattr(alert, "__dict__"):
    alert_payload = dict(alert.__dict__)
  else:
    alert_payload = {"value": str(alert)}

  return {
    "alert": alert_payload,
    "ip": ip,
    "host": host,
    "virustotal": virustotal,
    "abuseipdb": abuseipdb,
    "related_logs": related_logs,
  }


# IPs from alerts/sample_alerts.json plus a known Tor exit node for VT coverage.
MOCK_ALERT_IPS = [
  "203.0.113.10",      # ALT-2026-002 impossible travel (TEST-NET-3)
  "198.51.100.44",     # ALT-2026-002 impossible travel (TEST-NET-2)
  "185.220.101.45",    # known Tor exit node — VT returns results immediately
]


def _print_result(label: str, result: dict) -> None:
  print(f"\n{label}")
  print("-" * len(label))
  for key, value in result.items():
    if key == "raw":
      continue
    print(f"  {key}: {value}")


if __name__ == "__main__":
  for test_ip in MOCK_ALERT_IPS:
    print(f"\n{'=' * 60}")
    print(f"Testing IP: {test_ip}")
    print("=" * 60)

    try:
      vt = check_ip_virustotal(test_ip)
      _print_result("VirusTotal", vt)
    except Exception as exc:
      print(f"VirusTotal error: {exc}")

    try:
      abuse = check_ip_abuseipdb(test_ip)
      _print_result("AbuseIPDB", abuse)
    except Exception as exc:
      print(f"AbuseIPDB error: {exc}")
