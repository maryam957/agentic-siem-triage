"""IP threat enrichment via VirusTotal, AbuseIPDB, and related logs."""

from collections.abc import Mapping
import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 30


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
