from dataclasses import asdict

import requests

from agents.graph import graph

BACKEND_URL = "http://localhost:8000"

if __name__ == "__main__":
    result = graph.invoke(
        {
            "alert_path": "alerts/sample_alerts.json"
        }
    )

    print("\nPipeline completed successfully!")

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
        print("No triage_result found in pipeline output; nothing posted to dashboard.")