"""API integrations and enrichment tools."""

import requests


def lookup_ip_reputation(ip: str, api_key: str | None = None) -> dict:
  """Placeholder IP reputation lookup."""
  return {
    "ip": ip,
    "reputation": "unknown",
    "source": "stub",
    "note": "Wire to VirusTotal or AbuseIPDB in feature/security-layer",
  }


def enrich_alert_context(alert_id: str, host: str | None) -> dict:
  """Gather external context for an alert."""
  return {
    "alert_id": alert_id,
    "host": host,
    "asset_criticality": "medium",
    "open_incidents": 0,
  }


def post_to_webhook(url: str, payload: dict) -> requests.Response:
  """POST triage result to an external webhook (e.g. SOAR)."""
  return requests.post(url, json=payload, timeout=30)
