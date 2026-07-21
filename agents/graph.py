"""
LangGraph workflow definition.

Flow:
START
    ↓
ingest_alert
    ↓
enrichment_node
    ↓
scoring_node
    ↓
generate_report
    ↓
END
"""

from typing import TypedDict

from langgraph.graph import StateGraph, START, END

from agents.nodes import (
    ingest_alert,
    enrichment_node,
    scoring_node,
    generate_report,
)

from schemas.models import (
    RawAlert,
    EnrichedContext,
    TriageResult,
)


class PipelineState(TypedDict, total=False):
    """
    Shared state passed between LangGraph nodes.
    """

    alert_path: str
    alert_data: dict
    alert: RawAlert
    enriched: EnrichedContext
    triage_result: TriageResult


def build_graph():
    """
    Build and compile the LangGraph workflow.
    """

    workflow = StateGraph(PipelineState)

    # Add nodes
    workflow.add_node("ingest_alert", ingest_alert)
    workflow.add_node("enrichment", enrichment_node)
    workflow.add_node("scoring", scoring_node)
    workflow.add_node("generate_report", generate_report)

    # Define execution flow
    workflow.add_edge(START, "ingest_alert")
    workflow.add_edge("ingest_alert", "enrichment")
    workflow.add_edge("enrichment", "scoring")
    workflow.add_edge("scoring", "generate_report")
    workflow.add_edge("generate_report", END)

    return workflow.compile()


# Compiled graph instance
graph = build_graph()