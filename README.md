# Agentic SIEM Triage

An agentic security operations pipeline that ingests mock SIEM alerts, triages them with LangGraph agents, and surfaces human-in-the-loop decisions through a FastAPI dashboard.

## Structure

```
agentic-siem-triage/
├── alerts/          ← mock SIEM alerts
├── agents/          ← LangGraph nodes
├── tools/           ← API integrations
├── schemas/         ← shared data contracts
├── backend/         ← HITL dashboard backend
├── reports/         ← generated outputs
├── main.py
├── requirements.txt
└── README.md
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # add ANTHROPIC_API_KEY
python main.py
```

If you have a static Suricata `eve.json` archive from another run, set `RELATED_LOG_BACKEND=eve` or leave it unset and the app will use `eve.json` in the repo root as the local related-log source. For live backends, set `RELATED_LOG_BACKEND=elasticsearch` or `RELATED_LOG_BACKEND=loki` and configure the corresponding connection variables such as `ELASTICSEARCH_URL` / `ELASTICSEARCH_INDEX` or `LOKI_URL` / `LOKI_SELECTOR`.

## Run dashboard

```bash
uvicorn backend.app:app --reload
```

## Branches

| Branch | Focus |
|--------|-------|
| `main` | Core scaffold |
| `feature/security-layer` | Threat enrichment & validation tools |
| `feature/pipeline-ui` | HITL dashboard & pipeline visualization |
