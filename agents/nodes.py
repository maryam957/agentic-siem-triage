"""
Node functions for the LangGraph workflow.
"""

import json

from schemas.models import RawAlert, TriageResult
from tools.enrichment import enrich, reason


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
    alert = state["alert"]

    enriched = enrich(alert)

    state["enriched"] = enriched

    print("\n" + "=" * 70)
    print("🔍 ENRICHMENT RESULT")
    print("=" * 70)

    print(f"Source IP      : {enriched['ip']}")
    print(f"Host           : {enriched['host']}")

    print("\nVirusTotal")
    print("-" * 70)
    vt = enriched["virustotal"]
    for key, value in vt.items():
        if key != "raw":
            print(f"{key:22}: {value}")

    print("\nAbuseIPDB")
    print("-" * 70)
    abuse = enriched["abuseipdb"]
    for key, value in abuse.items():
        if key != "raw":
            print(f"{key:22}: {value}")

    print("\nRelated Logs")
    print("-" * 70)
    for i, log in enumerate(enriched["related_logs"], start=1):
        print(f"[{i}] {log['timestamp']}")
        print(f"    Source : {log['source']}")
        print(f"    Event  : {log['event']}")
        print(f"    Message: {log['message']}")
        print()

    print("=" * 70)

    print(f"Source IP      : {enriched['ip']}")
    print(f"Host           : {enriched['host']}")

    print("\nVirusTotal")
    print("-" * 70)
    vt = enriched["virustotal"]
    for key, value in vt.items():
        if key != "raw":
            print(f"{key:22}: {value}")

    print("\nAbuseIPDB")
    print("-" * 70)
    abuse = enriched["abuseipdb"]
    for key, value in abuse.items():
        if key != "raw":
            print(f"{key:22}: {value}")

    print("\nRelated Logs")
    print("-" * 70)
    for i, log in enumerate(enriched["related_logs"], start=1):
        print(f"[{i}] {log['timestamp']}")
        print(f"    Source : {log['source']}")
        print(f"    Event  : {log['event']}")
        print(f"    Message: {log['message']}")
        print()

    print("=" * 70)

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

    print(markdown)

    return state