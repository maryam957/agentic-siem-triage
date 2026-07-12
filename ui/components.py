"""Pipeline visualization and HITL review components."""

PIPELINE_STAGES = [
  {"id": "ingest", "label": "Ingest", "status": "complete"},
  {"id": "enrich", "label": "Enrich", "status": "complete"},
  {"id": "triage", "label": "Triage", "status": "active"},
  {"id": "review", "label": "Human Review", "status": "pending"},
  {"id": "report", "label": "Report", "status": "pending"},
]

ALERT_QUEUE = [
  {"id": "ALT-2026-001", "severity": "high", "title": "Suspicious PowerShell execution", "decision": None},
  {"id": "ALT-2026-002", "severity": "medium", "title": "Impossible travel sign-in", "decision": None},
  {"id": "ALT-2026-003", "severity": "critical", "title": "C2 beacon detected", "decision": "escalate"},
]
