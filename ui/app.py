"""Human-in-the-loop triage dashboard."""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from ui.components import ALERT_QUEUE, PIPELINE_STAGES
from ui.static import PIPELINE_CSS

app = FastAPI(title="Agentic SIEM Triage", version="0.2.0")


def _render_pipeline() -> str:
  stages = "".join(
    f'<div class="stage {s["status"]}">{s["label"]}</div>' for s in PIPELINE_STAGES
  )
  return f'<div class="pipeline">{stages}</div>'


def _render_alerts() -> str:
  cards = []
  for alert in ALERT_QUEUE:
    badge = alert["severity"].upper()
    decision = (
      f'<span style="color:#28a745">Agent: {alert["decision"]}</span>'
      if alert["decision"]
      else '<span style="color:#856404">Awaiting review</span>'
    )
    actions = ""
    if not alert["decision"]:
      actions = """
        <div class="actions">
          <button class="btn btn-escalate">Escalate</button>
          <button class="btn btn-investigate">Investigate</button>
          <button class="btn btn-fp">False Positive</button>
        </div>"""
    cards.append(
      f'<div class="card"><span class="badge {alert["severity"]}">{badge}</span>'
      f' <strong>{alert["id"]}</strong> — {alert["title"]}<br>{decision}{actions}</div>'
    )
  return "\n".join(cards)


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
  return f"""
  <!DOCTYPE html>
  <html>
  <head>
    <title>SIEM Triage Dashboard</title>
    <style>
      body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }}
      h1 {{ color: #1a1a2e; }}
      .card {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
      .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }}
      .high {{ background: #fee; color: #c00; }}
      .medium {{ background: #ffeaa7; color: #856404; }}
      .critical {{ background: #f8d7da; color: #721c24; }}
      {PIPELINE_CSS}
    </style>
  </head>
  <body>
    <h1>Agentic SIEM Triage</h1>
    <p>Pipeline status and human-in-the-loop alert review.</p>
    {_render_pipeline()}
    <h2>Alert Queue</h2>
    {_render_alerts()}
  </body>
  </html>
  """


@app.get("/api/pipeline")
async def pipeline_status() -> dict:
  return {"stages": PIPELINE_STAGES}


@app.get("/api/alerts")
async def alert_queue() -> dict:
  return {"alerts": ALERT_QUEUE}


@app.get("/health")
async def health() -> dict:
  return {"status": "ok", "version": "0.2.0"}
