import json
from pathlib import Path
import unittest

from fastapi.testclient import TestClient

from agents.graph import graph
from backend.app import app, pending_alerts


ROOT = Path(__file__).resolve().parents[1]
ALERTS_PATH = ROOT / "alerts" / "sample_alerts.json"
REPORTS_DIR = ROOT / "reports"


class IntegrationTests(unittest.TestCase):
  def setUp(self):
    pending_alerts.clear()
    for report_file in REPORTS_DIR.glob("ALT-2026-*.md"):
      report_file.unlink()

  def test_pipeline_runs_end_to_end_for_all_mock_alerts(self):
    alerts = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))

    results = []
    for alert in alerts:
      result = graph.invoke({"alert_data": alert})
      results.append(result)

      triage = result["triage_result"]
      report_path = REPORTS_DIR / f"{triage.alert_id}.md"
      self.assertTrue(report_path.exists())

    self.assertEqual(len(results), 15)

    low_routes = [result["triage_result"].severity_label for result in results if result["triage_result"].severity_label == "low"]
    high_routes = [result["triage_result"].severity_label for result in results if result["triage_result"].severity_label == "high"]

    self.assertGreater(len(low_routes), 0)
    self.assertGreater(len(high_routes), 0)

  def test_dashboard_review_shows_only_medium_alerts(self):
    client = TestClient(app)

    pending_alerts.extend(
      [
        type("Alert", (), {"alert_id": "L-1", "score": 25, "severity_label": "low"})(),
        type("Alert", (), {"alert_id": "M-1", "score": 55, "severity_label": "medium"})(),
        type("Alert", (), {"alert_id": "H-1", "score": 88, "severity_label": "high"})(),
      ]
    )

    response = client.get("/review")
    self.assertEqual(response.status_code, 200)
    body = response.text
    self.assertIn("M-1", body)
    self.assertNotIn("L-1", body)
    self.assertNotIn("H-1", body)

  def test_alerts_endpoint_returns_full_payload(self):
    client = TestClient(app)
    pending_alerts.append(
      type(
        "Alert",
        (),
        {
          "alert_id": "Z-1",
          "score": 72,
          "severity_label": "high",
          "ttps": ["T1046"],
          "timeline": ["2026-07-21T00:00:00Z - Alert received"],
          "reasoning": "Reasoning text",
          "recommended_actions": ["Action one"],
        },
      )()
    )

    response = client.get("/alerts")
    self.assertEqual(response.status_code, 200)
    payload = response.json()
    self.assertEqual(payload[0]["alert_id"], "Z-1")
    self.assertEqual(payload[0]["ttps"], ["T1046"])
    self.assertEqual(payload[0]["reasoning"], "Reasoning text")
    self.assertEqual(payload[0]["recommended_actions"], ["Action one"])


if __name__ == "__main__":
  unittest.main()