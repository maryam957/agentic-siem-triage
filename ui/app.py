"""Human-in-the-loop triage dashboard."""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Agentic SIEM Triage", version="0.1.0")


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
  return """
  <!DOCTYPE html>
  <html>
  <head>
    <title>SIEM Triage Dashboard</title>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
      h1 { color: #1a1a2e; }
      .card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
      .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }
      .high { background: #fee; color: #c00; }
      .medium { background: #ffeaa7; color: #856404; }
      .critical { background: #f8d7da; color: #721c24; }
    </style>
  </head>
  <body>
    <h1>Agentic SIEM Triage</h1>
    <p>Human-in-the-loop alert review dashboard. Pipeline UI coming in <code>feature/pipeline-ui</code>.</p>
    <div class="card">
      <span class="badge high">HIGH</span>
      <strong> ALT-2026-001</strong> — Suspicious PowerShell execution
    </div>
    <div class="card">
      <span class="badge medium">MEDIUM</span>
      <strong> ALT-2026-002</strong> — Impossible travel sign-in
    </div>
    <div class="card">
      <span class="badge critical">CRITICAL</span>
      <strong> ALT-2026-003</strong> — C2 beacon detected
    </div>
  </body>
  </html>
  """


@app.get("/health")
async def health() -> dict:
  return {"status": "ok"}
