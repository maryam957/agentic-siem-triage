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
 * Fetch alerts currently pending human analyst review.
 */
export async function getAlerts() {
  const response = await client.get('/alerts')
  return response.data
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
