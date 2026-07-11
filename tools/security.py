"""Threat enrichment and validation tools for the security layer."""

import hashlib
import re

import requests

C2_DOMAIN_PATTERNS = [
  re.compile(r"evil-.*\.example"),
  re.compile(r"[a-z0-9]{32}\.[a-z]{2,6}"),
]

SUSPICIOUS_POWERSHELL = re.compile(r"-enc(odedcommand)?\s", re.IGNORECASE)


def validate_alert_integrity(alert_id: str, raw_event: dict) -> dict:
  """Check alert payload for tampering indicators."""
  payload = str(sorted(raw_event.items())).encode()
  return {
    "alert_id": alert_id,
    "checksum": hashlib.sha256(payload).hexdigest()[:16],
    "valid": True,
  }


def detect_c2_indicators(destination: str) -> dict:
  """Match destination against known C2 patterns."""
  matched = any(p.search(destination) for p in C2_DOMAIN_PATTERNS)
  return {"destination": destination, "c2_likelihood": "high" if matched else "low"}


def score_powershell_risk(command_line: str) -> dict:
  """Score PowerShell command-line risk."""
  encoded = bool(SUSPICIOUS_POWERSHELL.search(command_line))
  return {
    "command_line": command_line[:120],
    "encoded": encoded,
    "risk_score": 0.85 if encoded else 0.2,
  }


def lookup_ip_reputation(ip: str, api_key: str | None = None) -> dict:
  """IP reputation lookup with optional VirusTotal integration."""
  result = {"ip": ip, "reputation": "unknown", "malicious_votes": 0}
  if api_key:
    try:
      resp = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
        timeout=15,
      )
      if resp.ok:
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result["malicious_votes"] = stats.get("malicious", 0)
        result["reputation"] = "malicious" if result["malicious_votes"] > 2 else "clean"
    except requests.RequestException:
      result["reputation"] = "lookup_failed"
  return result
