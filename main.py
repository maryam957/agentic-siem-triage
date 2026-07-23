import json
import time
from pathlib import Path

import requests

from agents.graph import graph

BACKEND_URL = "http://localhost:8000"
ALERTS_PATH = Path("alerts/sample_alerts.json")

if __name__ == "__main__":
    alerts = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
    results = []

    for alert in alerts:
        result = graph.invoke({"alert_data": alert})
        results.append(result)

        triage = result.get("triage_result")

        if triage is None:
            print(f"No triage_result for {alert.get('id', 'unknown')} — nothing posted.")
            time.sleep(3)
            continue

        # TriageResult is now Pydantic — use model_dump(), not asdict()
        try:
            payload = triage.model_dump()
        except AttributeError:
            # fallback if somehow still a dataclass
            from dataclasses import asdict
            payload = asdict(triage)

        try:
            response = requests.post(
                f"{BACKEND_URL}/alert",
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            print(f"Posted to dashboard: {response.json()}")
        except requests.exceptions.RequestException as exc:
            print(f"Could not post to dashboard: {exc}")

        time.sleep(3)

    print(f"\nPipeline complete — {len(results)} alerts processed.")