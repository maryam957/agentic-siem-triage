"""
Node functions for the LangGraph workflow.
"""

import json
from pathlib import Path

from schemas.models import RawAlert, TriageResult
from tools.enrichment import enrich, reason


REPORTS_DIR = Path(__file__).resolve().parents[1] / "reports"


def ingest_alert(state):
    """
    Load a RawAlert from a JSON file.
    Supports a file containing either one alert or a list of alerts.
    """

    data = state.get("alert_data")
    if data is None:
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
    alert = state["alert"]

    enriched = enrich(alert)

    state["enriched"] = enriched

    print(
        f"Enriched {alert.alert_id}: source_ip={enriched['ip']} host={enriched['host']} "
        f"related_logs={len(enriched['related_logs'])}"
    )

    return state


def scoring_node(state):
    alert = state["alert"]
    enriched = state.get("enriched", {})

    triage_partial = reason(enriched)

    triage = TriageResult(
        alert_id=triage_partial.get("alert_id") or alert.alert_id,
        score=int(triage_partial.get("score", 50)),
        severity_label=triage_partial.get("severity_label", "medium"),
        ttps=triage_partial.get("ttps", []),
        timeline=triage_partial.get("timeline", [f"{alert.timestamp} - Alert received"]),
        reasoning=triage_partial.get("reasoning", "No reasoning generated."),
        recommended_actions=triage_partial.get(
            "recommended_actions",
            ["Investigate source IP", "Review related logs"],
        ),
    )

    state["triage_result"] = triage
    state["correlation_prompt"] = triage_partial.get("correlation_prompt")

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
        if isinstance(event, dict):
            markdown += (
                f"- {event.get('timestamp', 'unknown time')} | "
                f"{event.get('source', 'unknown source')} | "
                f"{event.get('event', 'unknown event')}"
            )
            if event.get("message"):
                markdown += f" - {event['message']}"
            markdown += "\n"
        else:
            markdown += f"- {event}\n"

    markdown += f"""

## Reasoning
{triage.reasoning}

## Recommended Actions
"""

    for action in triage.recommended_actions:
        markdown += f"- {action}\n"

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"{triage.alert_id}.md"
    report_path.write_text(markdown, encoding="utf-8")

    state["report_path"] = str(report_path)

    print(f"Generated report: {report_path}")

    return state