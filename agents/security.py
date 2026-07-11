"""Security enrichment agent node."""

from schemas import TriageDecision, TriageResult
from tools.security import detect_c2_indicators, score_powershell_risk, validate_alert_integrity

from . import AgentState


def enrich_security_context(state: AgentState) -> AgentState:
  """Run security-layer enrichment on the current alert."""
  alert = state["alert"]
  context: dict = {"integrity": validate_alert_integrity(alert.id, alert.raw_event)}

  if "destination" in alert.raw_event:
    context["c2"] = detect_c2_indicators(alert.raw_event["destination"])

  if "command_line" in alert.raw_event:
    context["powershell"] = score_powershell_risk(alert.raw_event["command_line"])

  decision = TriageDecision.INVESTIGATE
  confidence = 0.6
  if context.get("c2", {}).get("c2_likelihood") == "high":
    decision = TriageDecision.ESCALATE
    confidence = 0.92

  state["triage"] = TriageResult(
    alert_id=alert.id,
    decision=decision,
    confidence=confidence,
    reasoning="Security layer enrichment complete",
    enriched_context=context,
  )
  state["messages"].append(f"Security enrichment applied to {alert.id}")
  return state
