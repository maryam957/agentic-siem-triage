from dataclasses import dataclass
from typing import Optional
from pydantic import BaseModel

@dataclass
class RawAlert:
    alert_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    alert_type: str
    severity: int
    affected_host: str
    raw_payload: dict

@dataclass
class EnrichedContext:
    alert: RawAlert
    ip_reputation: dict
    abuse_score: int
    related_logs: list
    whois_info: dict

class TriageResult(BaseModel):        # ← Pydantic, not dataclass
    alert_id: str
    score: int
    severity_label: str
    ttps: list = []
    timeline: list = []
    reasoning: str = ""
    recommended_actions: list = []