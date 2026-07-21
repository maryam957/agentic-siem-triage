from dataclasses import asdict
import json
from pathlib import Path

import requests

from agents.graph import graph

BACKEND_URL = "http://localhost:8000"
ALERTS_PATH = Path("alerts/sample_alerts.json")

if __name__ == "__main__":
    alerts = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
    results = []

    for alert in alerts:
        result = graph.invoke(
            {
                "alert_data": alert,
            }
        )
        results.append(result)

        triage = result.get("triage_result")
        if triage is not None:
            try:
                response = requests.post(
                    f"{BACKEND_URL}/alert",
                    json=asdict(triage),
                    timeout=10,
                )
                response.raise_for_status()
                print(f"Alert posted to dashboard: {response.json()}")
            except requests.exceptions.RequestException as exc:
                print(f"Could not post alert to dashboard ({BACKEND_URL}): {exc}")
        else:
            print(f"No triage_result found for {alert.get('id', 'unknown alert')}; nothing posted to dashboard.")

    print(f"\nPipeline completed successfully for {len(results)} alerts!")