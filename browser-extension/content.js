// Content script for mail.google.com.
//
// LIMITATION: Gmail has no official API for "give me the raw source of the email
// I'm currently looking at". This replicates Gmail's own "Show original" request
// (view=om), which is undocumented and can break if Google changes Gmail's markup.
// Every DOM lookup below is wrapped so a failure degrades to a visible status
// message instead of silently doing nothing.

const SCAN_TTL_MS = 60 * 60 * 1000 // don't rescan the same message within an hour
let ikToken = null
let statusEl = null

function ensureStatusBadge() {
  if (statusEl && document.body.contains(statusEl)) return statusEl
  statusEl = document.createElement('div')
  statusEl.className = 'etd-status'
  statusEl.textContent = 'Gmail Guard: watching for emails'
  document.body.appendChild(statusEl)
  return statusEl
}

function setStatus(text, tone = 'neutral') {
  const el = ensureStatusBadge()
  el.textContent = text
  el.className = 'etd-status etd-status-' + tone
}

function findIkToken() {
  if (ikToken) return ikToken
  try {
    for (const script of document.scripts) {
      const match = script.textContent && script.textContent.match(/"ik":"([A-Za-z0-9_-]+)"/)
      if (match) { ikToken = match[1]; return ikToken }
    }
  } catch (err) { console.warn('[Gmail Guard] could not locate ik token', err) }
  return null
}

function findOpenMessageId() {
  try {
    const nodes = document.querySelectorAll('[data-message-id]')
    if (!nodes.length) return null
    // The last rendered message-id node in the reading pane is the most recently opened message.
    const last = nodes[nodes.length - 1]
    const raw = last.getAttribute('data-message-id') || ''
    return raw.replace(/^#/, '') || null
  } catch (err) { console.warn('[Gmail Guard] could not locate an open message', err); return null }
}

async function alreadyScanned(permmsgid) {
  const { scanned = {} } = await chrome.storage.local.get('scanned')
  const at = scanned[permmsgid]
  return typeof at === 'number' && Date.now() - at < SCAN_TTL_MS
}

async function markScanned(permmsgid) {
  const { scanned = {} } = await chrome.storage.local.get('scanned')
  scanned[permmsgid] = Date.now()
  for (const key of Object.keys(scanned)) if (Date.now() - scanned[key] > SCAN_TTL_MS) delete scanned[key]
  await chrome.storage.local.set({ scanned })
}

async function fetchRawSource(permmsgid) {
  const ik = findIkToken()
  if (!ik) throw new Error('Could not locate Gmail session token (ik). Gmail may have changed; auto-scan disabled for this page.')
  const url = `https://mail.google.com/mail/u/0/?ik=${encodeURIComponent(ik)}&view=om&permmsgid=${encodeURIComponent(permmsgid)}`
  const response = await fetch(url, { credentials: 'include' })
  if (!response.ok) throw new Error(`Gmail returned HTTP ${response.status} for the original-message request.`)
  const text = await response.text()
  if (!/^[A-Za-z-]+:\s/m.test(text.slice(0, 500))) throw new Error('Unexpected response fetching the original message; Gmail’s markup may have changed.')
  return text
}

function injectBanner(container, result) {
  container.querySelectorAll(':scope > .etd-banner').forEach(el => el.remove())
  const banner = document.createElement('div')
  const tone = result.score >= 60 ? 'danger' : result.score >= 25 ? 'warn' : 'good'
  const attribution = result.assessment?.attribution
  const topFindings = (result.findings || []).slice(0, 2).map(f => f.title)
  banner.className = `etd-banner etd-banner-${tone}`
  banner.innerHTML = `
    <div class="etd-banner-head">
      <strong>Gmail Guard: ${result.risk} risk (${result.score}/100)</strong>
      ${attribution ? `<span class="etd-pill">Attribution confidence: ${attribution.confidence_score}/100 (${attribution.band})</span>` : ''}
    </div>
    ${topFindings.length ? `<ul class="etd-findings">${topFindings.map(t => `<li>${t}</li>`).join('')}</ul>` : '<div class="etd-findings-empty">No configured detection rules triggered — not proof the email is safe.</div>'}
    <div class="etd-banner-foot">Scanned automatically by Gmail Guard. Not proof of fraud or safety — verify independently before acting.</div>
  `
  container.prepend(banner)
}

function injectError(container, message) {
  container.querySelectorAll(':scope > .etd-banner').forEach(el => el.remove())
  const banner = document.createElement('div')
  banner.className = 'etd-banner etd-banner-neutral'
  banner.innerHTML = `<div class="etd-banner-head"><strong>Gmail Guard: scan unavailable</strong></div><div class="etd-banner-foot">${message}</div>`
  container.prepend(banner)
}

async function scanIfNeeded() {
  const permmsgid = findOpenMessageId()
  if (!permmsgid) { setStatus('Gmail Guard: no open email detected', 'neutral'); return }
  const container = document.querySelector(`[data-message-id="#${permmsgid}"], [data-message-id="${permmsgid}"]`)
  if (!container) return
  if (await alreadyScanned(permmsgid)) return
  setStatus('Gmail Guard: scanning opened email…', 'busy')
  try {
    const raw = await fetchRawSource(permmsgid)
    await markScanned(permmsgid)
    chrome.runtime.sendMessage({ type: 'scan-email', raw }, response => {
      if (chrome.runtime.lastError) { setStatus('Gmail Guard: extension error — reload the page', 'error'); return }
      if (!response || !response.ok) { injectError(container, response?.error || 'Unknown error.'); setStatus('Gmail Guard: last scan failed', 'error'); return }
      injectBanner(container, response.result)
      setStatus('Gmail Guard: watching for emails', 'neutral')
    })
  } catch (err) {
    injectError(container, err.message)
    setStatus('Gmail Guard: last scan failed', 'error')
  }
}

let debounce = null
const observer = new MutationObserver(() => {
  clearTimeout(debounce)
  debounce = setTimeout(scanIfNeeded, 800)
})
observer.observe(document.body, { childList: true, subtree: true })
setStatus('Gmail Guard: watching for emails', 'neutral')
