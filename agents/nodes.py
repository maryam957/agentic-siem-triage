"""
Node functions for the LangGraph workflow.
"""

import json

from schemas.models import RawAlert, TriageResult
from tools.enrichment import enrich


def ingest_alert(state):
    """
    Load a RawAlert from a JSON file.
    Supports a file containing either one alert or a list of alerts.
    """

    alert_path = state["alert_path"]

    with open(alert_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Use the first alert if the file contains a list
    if isinstance(data, list):
        data = data[0]

    raw = data.get("raw_event", {})

    severity_map = {
        "low": 1,
        "medium": 2,
        "high": 3,
    }

    alert = RawAlert(
        alert_id=data.get("id", ""),
        timestamp=data.get("timestamp", ""),
        src_ip=raw.get("src_ip", ""),
        dst_ip=raw.get("dst_ip", ""),
        src_port=raw.get("src_port", 0),
        dst_port=raw.get("dst_port", 0),
        protocol=raw.get("protocol", "Unknown"),
        alert_type=data.get("title", ""),
        severity=severity_map.get(
            str(data.get("severity", "medium")).lower(),
            2,
        ),
        affected_host=data.get("host", ""),
        raw_payload=raw,
    )

    state["alert"] = alert

    return state


def enrichment_node(state):
    """
    Enrich the alert using external threat intelligence.
    """

    alert = state["alert"]

    enriched = enrich(alert)

    state["enriched"] = enriched

    return state


def scoring_node(state):
    """
    Temporary scoring node.

    Day 4 requirement:
    Return a hardcoded score of 50.
    """

    alert = state["alert"]

    triage = TriageResult(
        alert_id=alert.alert_id,
        score=50,
        severity_label="medium",
        ttps=[],
        timeline=[
            f"{alert.timestamp} - Alert received"
        ],
        reasoning="Hardcoded score placeholder.",
        recommended_actions=[
            "Investigate source IP",
            "Review related logs"
        ],
    )

    state["triage_result"] = triage

    return state


def generate_report(state):
    """
    Generate a markdown report from the TriageResult.
    """

    triage = state["triage_result"]

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