import axios from 'axios'

const client = axios.create({
  // Relative baseURL: requests go to the Vite dev server (localhost:1574),
  // which proxies them to the backend (see vite.config.js) — this keeps
  // every request same-origin from the browser's point of view.
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
})

/**
 * `/review` renders an HTML table (see ui/app.py) rather than JSON, so we
 * parse it into the alert shape the rest of the UI expects. Only
 * alert_id / score / severity_label are present in that table today —
 * ttps, reasoning, timeline, and recommended_actions aren't rendered by
 * the backend yet, so those fields come back undefined here.
 */
function parseReviewHtml(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html')
  const rows = Array.from(doc.querySelectorAll('table tr')).slice(1) // skip header row

  const alerts = []
  for (const row of rows) {
    const cells = row.querySelectorAll('td')
    if (cells.length < 3) continue // "no alerts" placeholder row (single colspan cell)

    const alert_id = cells[0].textContent.trim()
    if (!alert_id) continue

    alerts.push({
      alert_id,
      score: Number(cells[1].textContent.trim()),
      severity_label: cells[2].textContent.trim(),
    })
  }
  return alerts
}

/**
 * Fetch alerts currently pending human analyst review
 * (medium, high, and critical severity).
 */
export async function getAlerts() {
  const response = await client.get('/review')
  return parseReviewHtml(response.data)
}

/**
 * Approve the AI's triage decision for a given alert.
 */
export async function approveAlert(alertId) {
  const response = await client.post(`/approve/${alertId}`)
  return response.data
}

/**
 * Override the AI's triage decision with an analyst-supplied
 * severity and comment.
 */
export async function overrideAlert(alertId, data) {
  const response = await client.post(`/override/${alertId}`, data)
  return response.data
}

/**
 * Send an alert back through the reasoning node for
 * re-investigation.
 */
export async function reinvestigateAlert(alertId) {
  const response = await client.post(`/reinvestigate/${alertId}`)
  return response.data
}

export default client
