from dataclasses import dataclass
from typing import Optional

@dataclass
class RawAlert:
    alert_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    alert_type: str       # e.g. "ET SCAN Nmap"
    severity: int         # 1-3 from Suricata
    affected_host: str
    raw_payload: dict

@dataclass
class EnrichedContext:
    alert: RawAlert
    ip_reputation: dict   # VirusTotal response
    abuse_score: int      # AbuseIPDB score 0-100
    related_logs: list    # last 24hr logs for this IP
    whois_info: dict

@dataclass
class TriageResult:
    alert_id: str
    score: int            # 0-100
    severity_label: str   # "low" / "medium" / "high"
    ttps: list            # MITRE ATT&CK IDs e.g. ["T1046", "T1110"]
    timeline: list        # ordered list of events
    reasoning: str        # LLM explanation
    recommended_actions: list