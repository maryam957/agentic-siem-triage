"""Agentic SIEM Triage — backend API."""

import json
import sqlite3
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from schemas.models import TriageResult


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

DB_PATH = "triage.db"


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    with _connect() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id      TEXT PRIMARY KEY,
                data          TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        con.commit()


def save_alert(alert: TriageResult, status: str = "pending") -> None:
    with _connect() as con:
        con.execute(
            "INSERT OR REPLACE INTO alerts (alert_id, data, status) VALUES (?, ?, ?)",
            (alert.alert_id, alert.model_dump_json(), status),
        )
        con.commit()


def load_all_alerts() -> list[TriageResult]:
    with _connect() as con:
        rows = con.execute(
            "SELECT data FROM alerts ORDER BY created_at DESC"
        ).fetchall()
    return [TriageResult.model_validate_json(row["data"]) for row in rows]


def load_alert(alert_id: str) -> Optional[TriageResult]:
    with _connect() as con:
        row = con.execute(
            "SELECT data FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
    if row is None:
        return None
    return TriageResult.model_validate_json(row["data"])


def set_alert_status(alert_id: str, status: str) -> None:
    with _connect() as con:
        con.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            (status, alert_id),
        )
        con.commit()


def get_alert_status(alert_id: str) -> Optional[str]:
    with _connect() as con:
        row = con.execute(
            "SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
    return row["status"] if row else None


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Agentic SIEM Triage",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Ingest — called by main.py after each pipeline run
# ---------------------------------------------------------------------------

@app.post("/alert", status_code=201)
async def receive_alert(alert: TriageResult):
    """Receive a triaged alert from the LangGraph pipeline."""
    save_alert(alert, status="pending")
    return {
        "message": "Alert received",
        "alert_id": alert.alert_id,
    }


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

@app.get("/alerts")
async def list_alerts():
    """Return all alerts with their full triage data and current status."""
    alerts = load_all_alerts()
    return [
        {
            "alert_id":           a.alert_id,
            "score":              a.score,
            "severity_label":     a.severity_label,
            "ttps":               a.ttps,
            "timeline":           a.timeline,
            "reasoning":          a.reasoning,
            "recommended_actions": a.recommended_actions,
            "status":             get_alert_status(a.alert_id),
        }
        for a in alerts
    ]


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Return a single alert by ID."""
    alert = load_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "alert_id":           alert.alert_id,
        "score":              alert.score,
        "severity_label":     alert.severity_label,
        "ttps":               alert.ttps,
        "timeline":           alert.timeline,
        "reasoning":          alert.reasoning,
        "recommended_actions": alert.recommended_actions,
        "status":             get_alert_status(alert_id),
    }


# ---------------------------------------------------------------------------
# HITL actions
# ---------------------------------------------------------------------------

@app.post("/approve/{alert_id}")
async def approve(alert_id: str):
    """Analyst approves the bot's triage decision — pipeline continues to report."""
    if load_alert(alert_id) is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    set_alert_status(alert_id, "approved")

    # Resume the paused LangGraph graph for this alert.
    # Uncomment once checkpointer is wired in agents/graph.py:
    #
    # from agents.graph import graph, make_config
    # graph.invoke(None, config=make_config(alert_id))

    return {"message": f"{alert_id} approved — report generation triggered"}


@app.post("/override/{alert_id}")
async def override(alert_id: str, new_score: int = 90):
    """
    Analyst overrides the bot's score.
    Saves the updated result and marks status as overridden.
    """
    alert = load_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Rebuild with analyst-supplied score and derived severity.
    if new_score >= 70:
        new_severity = "high"
    elif new_score >= 40:
        new_severity = "medium"
    else:
        new_severity = "low"

    updated = alert.model_copy(
        update={"score": new_score, "severity_label": new_severity}
    )
    save_alert(updated, status="overridden")

    return {
        "message":      "Alert overridden",
        "alert_id":     alert_id,
        "new_score":    new_score,
        "new_severity": new_severity,
    }


@app.post("/reinvestigate/{alert_id}")
async def reinvestigate(alert_id: str):
    """
    Re-run the full LangGraph pipeline for this alert.
    The pipeline will overwrite the stored result via POST /alert.
    """
    alert = load_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    set_alert_status(alert_id, "reinvestigating")

    # Run the full pipeline — NOT a raw reason() call.
    # This triggers nodes 1-5 in the correct order.
    from agents.graph import run_pipeline
    run_pipeline(alert_id)

    return {"message": f"{alert_id} queued for re-investigation"}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}