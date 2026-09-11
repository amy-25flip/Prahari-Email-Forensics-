// Service worker: does the actual cross-origin call to the backend.
// Chrome exempts extension background/service-worker fetches from CORS when the
// target URL is covered by a declared host_permissions entry (see manifest.json),
// so the backend needs no CORS changes for this to work.

const DEFAULT_BACKEND = 'http://localhost:8000'

async function getBackendUrl() {
  const { backendUrl } = await chrome.storage.local.get('backendUrl')
  return (backendUrl || DEFAULT_BACKEND).replace(/\/$/, '')
}

async function analyze(rawBase64, expectedBackend) {
  const backend = await getBackendUrl()
  if (expectedBackend && backend !== expectedBackend) throw new Error('Backend changed; retry the scan.')
  const target = new URL(backend)
  const local = ['localhost', '127.0.0.1'].includes(target.hostname) && target.protocol === 'http:'
  const hosted = target.hostname.endsWith('.onrender.com') && target.protocol === 'https:'
  if ((!local && !hosted) || target.username || target.password || target.search || target.hash) throw new Error('Unsupported backend URL.')
  if (typeof rawBase64 !== 'string' || rawBase64.length > 1398104) throw new Error('Invalid or oversized email.')
  const raw = Uint8Array.from(atob(rawBase64), c => c.charCodeAt(0))
  if (!raw.length || raw.length > 1048576) throw new Error('Email must be between 1 byte and 1 MiB.')
  let response
  try {
    response = await fetch(backend + '/api/analyze?enrich=true', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'message/rfc822', 'X-Requested-With': 'Email-Threat-Detection' },
      body: raw
    })
  } catch (networkError) {
    throw new Error(`Could not reach backend at ${backend} (${networkError.message}). Check the backend URL in the extension popup and that the server is running.`)
  }
  if (!response.ok) {
    let detail = ''
    try { detail = (await response.json()).detail || '' } catch { /* non-JSON error body */ }
    throw new Error(`Backend rejected the request (HTTP ${response.status}). ${detail}`.trim())
  }
  return response.json()
}

async function recordHistory(result) {
  const { history = [] } = await chrome.storage.local.get('history')
  history.unshift({
    id: result.id, subject: result.subject, sender: result.sender, score: result.score, risk: result.risk,
    attribution: result.assessment?.attribution?.confidence_score ?? null,
    band: result.assessment?.attribution?.band ?? null,
    scannedAt: Date.now()
  })
  await chrome.storage.local.set({ history: history.slice(0, 25) })
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'scan-email') {
    analyze(message.rawBase64, message.expectedBackend)
      .then(async result => { await recordHistory(result); sendResponse({ ok: true, result }) })
      .catch(error => sendResponse({ ok: false, error: String(error && error.message || error) }))
    return true // keep the message channel open for the async sendResponse above
  }
  if (message.type === 'get-backend-url') {
    getBackendUrl().then(backendUrl => sendResponse({ backendUrl }))
    return true
  }
  return false
})
