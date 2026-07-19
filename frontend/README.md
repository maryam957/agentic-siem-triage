# Agentic SIEM Triage — Frontend

React dashboard for reviewing AI-triaged security alerts. Talks to the
existing FastAPI backend over REST (default: `http://localhost:8000`).

## Setup

```bash
cd frontend
npm install
npm run dev
```

`npm run dev` now starts **three** things together (via `concurrently`),
so you don't need separate terminals for `uvicorn` or `python main.py`:

1. **backend** — the FastAPI server (`uvicorn ui.app:app --reload --port 8000`)
2. **frontend** — the Vite dev server (`http://localhost:5173`)
3. **seed** — waits for the backend's `/health` endpoint to respond, then
   runs `python main.py` once. `main.py` now runs the LangGraph pipeline
   and POSTs its `TriageResult` to `http://localhost:8000/alert`, so an
   alert appears in the queue automatically the first time you start
   everything.

Output from each process is prefixed and color-coded (`backend` /
`frontend` / `seed`) in the same terminal. The seed process exits after
it posts (or fails to post) — that's expected; it's a one-shot step, not
a long-running server.

Requirements:
- Node deps: `npm install` (already covers `concurrently` and `wait-on`)
- Python deps for the backend and pipeline: install once from the
  project root with `pip install -r requirements.txt`, and make sure
  `uvicorn` and `python` resolve correctly in whatever shell you run
  `npm run dev` from (active virtualenv, etc.)

If you only want one piece running, use `npm run dev:frontend`,
`npm run dev:backend`, or `npm run seed` individually. Re-running
`npm run seed` (or restarting `npm run dev`) will push another alert
through the pipeline and onto the dashboard each time.

## Structure

```
src/
├── api/
│   └── api.js              # Axios client: getAlerts, approveAlert, overrideAlert, reinvestigateAlert
├── components/
│   ├── Dashboard.jsx        # Page layout, state, data fetching
│   ├── AlertTable.jsx        # Left-side alert queue table
│   ├── AlertDetails.jsx      # Right-side detail panel
│   ├── SeverityBadge.jsx     # Severity pill
│   ├── StatsCard.jsx         # Top stat tiles
│   ├── Timeline.jsx          # Alert event timeline
│   ├── ActionButtons.jsx     # Approve / Override / Reinvestigate buttons
│   └── OverrideModal.jsx     # Modal for submitting an override
├── App.jsx
├── main.jsx
└── index.css
```

## Notes

- Currently wired to `GET /review` for the alert queue. Since the backend's
  `/review` endpoint only returns medium-severity alerts today, that's all
  you'll see until the backend is extended to include high/critical too.
- `POST /override/{id}` on the backend doesn't yet accept `new_severity` /
  `comment` in its body — the frontend already sends them, so once that's
  wired up on the Python side it'll just work.
- No mock/placeholder data — everything renders from live API responses,
  including empty and error states.
