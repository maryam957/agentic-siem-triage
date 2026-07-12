from dataclasses import dataclass
from typing import Optional

@dataclass
class RawAlert:
    id: str
    timestamp: str
    source: str
    severity: str
    title: str
    description: str
    host: Optional[str]
    user: str
    mitre_tactics: list[str]
    raw_event: dict

@dataclass
class EnrichedContext:
    alert: RawAlert
    ip_reputation: dict   # VirusTotal response
    abuse_score: int      # AbuseIPDB score 0-100
    related_logs: list    # last 24hr logs for this alert or entity
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