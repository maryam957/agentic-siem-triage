"""Shared data contracts for the SIEM triage pipeline."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"
  CRITICAL = "critical"


class TriageDecision(str, Enum):
  ESCALATE = "escalate"
  INVESTIGATE = "investigate"
  FALSE_POSITIVE = "false_positive"
  BENIGN = "benign"


class Alert(BaseModel):
  id: str
  timestamp: datetime
  source: str
  severity: Severity
  title: str
  description: str
  host: str | None = None
  user: str | None = None
  mitre_tactics: list[str] = Field(default_factory=list)
  raw_event: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
  alert_id: str
  decision: TriageDecision
  confidence: float = Field(ge=0.0, le=1.0)
  reasoning: str
  recommended_actions: list[str] = Field(default_factory=list)
  enriched_context: dict[str, Any] = Field(default_factory=dict)


class PipelineState(BaseModel):
  alert: Alert
  triage: TriageResult | None = None
  human_override: TriageDecision | None = None
  report_path: str | None = None
