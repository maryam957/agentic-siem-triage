"""IP threat enrichment via VirusTotal and AbuseIPDB."""

import os

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
