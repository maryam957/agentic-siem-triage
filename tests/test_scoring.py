import json
from pathlib import Path
import unittest

from tools.enrichment import route_alert, score_alert


ROOT = Path(__file__).resolve().parents[1]
ALERTS_PATH = ROOT / "alerts" / "sample_alerts.json"


def _load_sample_alerts():
  return json.loads(ALERTS_PATH.read_text(encoding="utf-8"))


def _related_logs(count: int) -> list[dict[str, str]]:
  return [
    {
      "timestamp": f"2026-07-14T08:12:{index:02d}Z",
      "source": "SIEM Correlation",
      "event": "suspicious network connection",
      "message": "Correlated suspicious activity for scoring tests.",
    }
    for index in range(count)
  ]


class ScoreAlertTests(unittest.TestCase):
  def test_route_alert_boundaries(self):
    self.assertEqual(route_alert(39), "low")
    self.assertEqual(route_alert(40), "medium")
    self.assertEqual(route_alert(69), "medium")
    self.assertEqual(route_alert(70), "high")

  def test_all_mock_alerts_route_sensibly(self):
    alerts = {alert["id"]: alert for alert in _load_sample_alerts()}

    scenarios = {
      "ALT-2026-001": {"route": "high", "abuse": 80, "vt_malicious": 3, "vt_suspicious": 0, "ttps": ["T1110", "T1021.004"], "anomalies": 5},
      "ALT-2026-002": {"route": "high", "abuse": 78, "vt_malicious": 3, "vt_suspicious": 0, "ttps": ["T1110", "T1021.004"], "anomalies": 5},
      "ALT-2026-003": {"route": "medium", "abuse": 60, "vt_malicious": 0, "vt_suspicious": 0, "ttps": ["T1110"], "anomalies": 5},
      "ALT-2026-004": {"route": "medium", "abuse": 50, "vt_malicious": 0, "vt_suspicious": 0, "ttps": ["T1046"], "anomalies": 5},
      "ALT-2026-005": {"route": "medium", "abuse": 52, "vt_malicious": 0, "vt_suspicious": 0, "ttps": ["T1046"], "anomalies": 5},
      "ALT-2026-006": {"route": "low", "abuse": 10, "vt_malicious": 0, "vt_suspicious": 0, "ttps": ["T1046"], "anomalies": 1},
      "ALT-2026-007": {"route": "high", "abuse": 70, "vt_malicious": 2, "vt_suspicious": 0, "ttps": ["T1071", "T1041"], "anomalies": 6},
      "ALT-2026-008": {"route": "high", "abuse": 60, "vt_malicious": 3, "vt_suspicious": 0, "ttps": ["T1071.004", "T1048.003"], "anomalies": 8},
      "ALT-2026-009": {"route": "high", "abuse": 75, "vt_malicious": 2, "vt_suspicious": 0, "ttps": ["T1071", "T1105"], "anomalies": 6},
      "ALT-2026-010": {"route": "medium", "abuse": 55, "vt_malicious": 0, "vt_suspicious": 0, "ttps": ["T1110"], "anomalies": 5},
      "ALT-2026-011": {"route": "high", "abuse": 90, "vt_malicious": 2, "vt_suspicious": 0, "ttps": ["T1110"], "anomalies": 6},
      "ALT-2026-012": {"route": "medium", "abuse": 50, "vt_malicious": 0, "vt_suspicious": 0, "ttps": ["T1110"], "anomalies": 4},
      "ALT-2026-013": {"route": "high", "abuse": 90, "vt_malicious": 3, "vt_suspicious": 0, "ttps": ["T1071", "T1105"], "anomalies": 7},
      "ALT-2026-014": {"route": "high", "abuse": 80, "vt_malicious": 2, "vt_suspicious": 0, "ttps": ["T1071", "T1105"], "anomalies": 6},
      "ALT-2026-015": {"route": "high", "abuse": 85, "vt_malicious": 3, "vt_suspicious": 0, "ttps": ["T1071", "T1105"], "anomalies": 7},
    }

    for alert_id, scenario in scenarios.items():
      with self.subTest(alert_id=alert_id):
        alert = dict(alerts[alert_id])
        alert["raw_event"] = {}

        context = {
          "alert": alert,
          "abuseipdb": {"abuse_confidence_score": scenario["abuse"]},
          "virustotal": {
            "last_analysis_stats": {
              "malicious": scenario["vt_malicious"],
              "suspicious": scenario["vt_suspicious"],
            }
          },
          "ttps": scenario["ttps"],
          "behavior_summary": f"{alert['title']} - {alert['description']}",
          "related_logs": _related_logs(scenario["anomalies"]),
        }

        score = score_alert(context, context["behavior_summary"])
        self.assertEqual(route_alert(score), scenario["route"])


if __name__ == "__main__":
  unittest.main()