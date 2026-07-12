"""Static assets for the HITL dashboard."""

PIPELINE_CSS = """
.pipeline { display: flex; gap: 0.5rem; margin: 1.5rem 0; flex-wrap: wrap; }
.stage { flex: 1; min-width: 120px; padding: 0.75rem; border-radius: 8px; text-align: center; font-size: 0.9rem; }
.stage.complete { background: #d4edda; color: #155724; }
.stage.active { background: #cce5ff; color: #004085; border: 2px solid #007bff; }
.stage.pending { background: #f8f9fa; color: #6c757d; }
.actions { display: flex; gap: 0.5rem; margin-top: 1rem; }
.btn { padding: 0.5rem 1rem; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
.btn-escalate { background: #dc3545; color: white; }
.btn-investigate { background: #ffc107; color: #212529; }
.btn-fp { background: #6c757d; color: white; }
"""
