"""Human-in-the-loop (HITL) dashboard for Agentic SIEM."""

from typing import List

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from schemas.models import TriageResult
from tools.enrichment import reason

app = FastAPI(
    title="Agentic SIEM Triage",
    version="0.1.0"
)

# -------------------------------------------------------------------
# Temporary in-memory storage
# -------------------------------------------------------------------

pending_alerts: List[TriageResult] = []


# -------------------------------------------------------------------
# Receive a triaged alert
# -------------------------------------------------------------------

@app.post("/alert")
async def receive_alert(alert: TriageResult):
    pending_alerts.append(alert)

    return {
        "message": "Alert received successfully",
        "pending_alerts": len(pending_alerts)
    }


# -------------------------------------------------------------------
# Dashboard
# -------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return """
    <html>
    <head>
        <title>Agentic SIEM Dashboard</title>
    </head>
    <body style="font-family:Arial;padding:30px">
        <h1>Agentic SIEM Dashboard</h1>

        <p>
            <a href="/review">View Pending Alerts</a>
        </p>
    </body>
    </html>
    """


# -------------------------------------------------------------------
# Review Queue
# -------------------------------------------------------------------

@app.get("/review", response_class=HTMLResponse)
async def review():

    rows = ""

    for alert in pending_alerts:

        if alert.severity_label != "medium":
            continue

        rows += f"""
        <tr>
            <td>{alert.alert_id}</td>
            <td>{alert.score}</td>
            <td>{alert.severity_label}</td>

            <td>

                <form action="/approve/{alert.alert_id}" method="post" style="display:inline;">
                    <button>Approve</button>
                </form>

                <form action="/override/{alert.alert_id}" method="post" style="display:inline;">
                    <button>Override</button>
                </form>

                <form action="/reinvestigate/{alert.alert_id}" method="post" style="display:inline;">
                    <button>Reinvestigate</button>
                </form>

            </td>

        </tr>
        """

    if rows == "":
        rows = """
        <tr>
            <td colspan="4">
                No medium severity alerts awaiting review.
            </td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>Pending Alerts</title>

        <style>

            body {{
                font-family: Arial;
                margin:40px;
            }}

            table {{
                border-collapse: collapse;
                width:100%;
            }}

            th, td {{
                border:1px solid #ccc;
                padding:10px;
                text-align:left;
            }}

            th {{
                background:#f5f5f5;
            }}

            button {{
                padding:6px 12px;
                margin-right:5px;
                cursor:pointer;
            }}

        </style>

    </head>

    <body>

        <h2>Pending Medium Severity Alerts</h2>

        <table>

            <tr>
                <th>Alert ID</th>
                <th>Score</th>
                <th>Severity</th>
                <th>Actions</th>
            </tr>

            {rows}

        </table>

    </body>

    </html>
    """


# -------------------------------------------------------------------
# Approve
# -------------------------------------------------------------------

@app.post("/approve/{alert_id}")
async def approve(alert_id: str):

    global pending_alerts

    pending_alerts = [
        a for a in pending_alerts
        if a.alert_id != alert_id
    ]

    return {
        "message": f"{alert_id} approved"
    }


# -------------------------------------------------------------------
# Override
# -------------------------------------------------------------------

@app.post("/override/{alert_id}")
async def override(alert_id: str):

    for alert in pending_alerts:

        if alert.alert_id == alert_id:

            alert.severity_label = "high"
            alert.score = 90

            return {
                "message": "Alert overridden",
                "alert": alert.alert_id
            }

    return {
        "error": "Alert not found"
    }


# -------------------------------------------------------------------
# Reinvestigate
# -------------------------------------------------------------------

@app.post("/reinvestigate/{alert_id}")
async def reinvestigate(alert_id: str):

    for i, alert in enumerate(pending_alerts):

        if alert.alert_id == alert_id:

            context = {
                "alert": {
                    "alert_id": alert.alert_id,
                    "severity": alert.severity_label,
                },
                "related_logs": alert.timeline,
            }

            result = reason(context)

            pending_alerts[i] = TriageResult(
                alert_id=result["alert_id"],
                score=result["score"],
                severity_label=result["severity_label"],
                ttps=result["ttps"],
                timeline=result["timeline"],
                reasoning=result["reasoning"],
                recommended_actions=result["recommended_actions"],
            )

            return {
                "message": "Alert re-investigated",
                "new_score": result["score"]
            }

    return {
        "error": "Alert not found"
    }


# -------------------------------------------------------------------
# Health Check
# -------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok"
    }