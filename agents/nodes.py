"""
Node functions for the LangGraph workflow.
"""

import json
from schemas.models import RawAlert, TriageResult


SEVERITY_SCORES = {
    "low": 25,
    "medium": 55,
    "high": 80,
    "critical": 95,
}


def ingest_alert(state):
    """
    Load a RawAlert from a JSON file and store it in the graph state.

    Expected state:
    {
        "alert_path": "alerts/sample_alerts.json"
    }
    """
    alert_path = state["alert_path"]

    with open(alert_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        if not data:
            raise ValueError(f"Alert file '{alert_path}' does not contain any alerts.")
        data = data[0]

    alert = RawAlert(
        id=data["id"],
        timestamp=data["timestamp"],
        source=data["source"],
        severity=data["severity"],
        title=data["title"],
        description=data["description"],
        host=data["host"],
        user=data["user"],
        mitre_tactics=data["mitre_tactics"],
        raw_event=data["raw_event"],
    )

    state["alert"] = alert
    return state


def generate_report(state):
    """
    Generate a simple markdown report from the alert.

    This is a placeholder implementation for Day 3.
    Later, this node will use the real AI-generated TriageResult.
    """
    alert = state["alert"]
    severity_label = alert.severity.lower()

    triage = TriageResult(
        alert_id=alert.id,
        score=SEVERITY_SCORES.get(severity_label, 0),
        severity_label=severity_label,
        ttps=[],
        timeline=[
            f"{alert.timestamp} - Alert received from {alert.source}",
            f"{alert.timestamp} - Analyst context: {alert.title}",
        ],
        reasoning=alert.description,
        recommended_actions=[
            "Investigate source IP",
            "Review related logs"
        ],
    )

    state["triage_result"] = triage

    markdown = f"""# Triage Report

## Alert ID
{triage.alert_id}

## Severity
{triage.severity_label}

## Score
{triage.score}/100

## MITRE ATT&CK
{", ".join(triage.ttps) if triage.ttps else "None"}

## Timeline
"""

    for event in triage.timeline:
        markdown += f"- {event}\n"

    markdown += f"""

## Reasoning
{triage.reasoning}

## Recommended Actions
"""

    for action in triage.recommended_actions:
        markdown += f"- {action}\n"

    print(markdown)

    return state