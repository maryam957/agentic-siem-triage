# Agentic SIEM Triage

An agentic security operations pipeline that ingests mock SIEM alerts, triages them with LangGraph agents, and surfaces human-in-the-loop decisions through a FastAPI dashboard.

## Structure

```
agentic-siem-triage/
├── alerts/          ← mock SIEM alerts
├── agents/          ← LangGraph nodes
├── tools/           ← API integrations
├── schemas/         ← shared data contracts
├── ui/              ← HITL dashboard
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

## Run dashboard

```bash
uvicorn ui.app:app --reload
```

## Branches

| Branch | Focus |
|--------|-------|
| `main` | Core scaffold |
| `feature/security-layer` | Threat enrichment & validation tools |
| `feature/pipeline-ui` | HITL dashboard & pipeline visualization |
