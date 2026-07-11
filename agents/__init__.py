"""LangGraph agent nodes for SIEM alert triage."""

from typing import TypedDict

from schemas import Alert, TriageResult


class AgentState(TypedDict):
  alert: Alert
  triage: TriageResult | None
  messages: list[str]


def ingest_alert(state: AgentState) -> AgentState:
  """Load and validate the incoming alert."""
  state["messages"] = state.get("messages", [])
  state["messages"].append(f"Ingested alert {state['alert'].id}")
  return state


def triage_alert(state: AgentState) -> AgentState:
  """Placeholder triage node — wire to LLM in feature branches."""
  state["messages"].append(f"Triaging alert {state['alert'].id}")
  return state


def generate_report(state: AgentState) -> AgentState:
  """Placeholder report node."""
  state["messages"].append("Report generation pending")
  return state
