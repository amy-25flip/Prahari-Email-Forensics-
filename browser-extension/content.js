// Gmail DOM integration is undocumented; failures are visible and retry with backoff.
const scanState = new globalThis.GmailGuardScanState()
let statusEl = null
let retryTimer = null

function setStatus(text, tone = 'neutral') {
  if (!statusEl || !document.body.contains(statusEl)) {
    statusEl = document.createElement('div')
    document.body.appendChild(statusEl)
  }
  if (statusEl.textContent !== text) statusEl.textContent = text
  const name = 'etd-status etd-status-' + tone
  if (statusEl.className !== name) statusEl.className = name
}

function accountPath() {
  const match = location.pathname.match(/^\/mail\/u\/\d+\//)
  if (!match) throw Error('Unsupported Gmail account path; automatic scanning paused.')
  return match[0]
}

function findOpenMessage() {
  const root = document.querySelector('[role="main"]') || document.body
  const nodes = [...root.querySelectorAll('[data-message-id]')].filter(node => node.getClientRects().length)
  const container = nodes[nodes.length - 1]
  const id = container?.getAttribute('data-message-id')?.replace(/^#/, '')
  return id ? { id, container } : null
}

function rpc(message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Scan timed out. Please retry later.')), 120000)
    chrome.runtime.sendMessage(message, response => {
      clearTimeout(timer)
      if (chrome.runtime.lastError) reject(Error(chrome.runtime.lastError.message))
      else if (!response) reject(Error('No response from Gmail Guard service worker.'))
      else resolve(response)
    })
  })
}

// Gmail's per-session "ik" token, needed to build the original-message URL, is
// undocumented and its placement drifts between Gmail frontend versions. Try
// several isolated-world-readable sources in order; first hit wins. Must be
// re-verified against live Gmail whenever the markup changes.
function resolveIk() {
  const pats = [
    /"ik"\s*:\s*"([A-Za-z0-9_-]{6,})"/,   // JSON-object style (the classic one)
    /"ik"\s*,\s*"([A-Za-z0-9_-]{6,})"/,   // array/tuple style
    /\bGM_ID_KEY\b\s*[:=]\s*["']([A-Za-z0-9_-]{6,})["']/,
    /[?&]ik=([A-Za-z0-9_-]{6,})/          // an ik carried inside any URL literal
  ]
  for (const s of document.scripts) {
    const t = s.textContent || ''
    if (!t.includes('ik')) continue
    for (const re of pats) { const m = t.match(re); if (m) return m[1] }
  }
  const el = document.querySelector('[data-ik],[href*="ik="],[src*="ik="],[data-url*="ik="]')
  if (el) {
    const direct = el.getAttribute('data-ik')
    if (direct && /^[A-Za-z0-9_-]{6,}$/.test(direct)) return direct
    const raw = el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('data-url') || ''
    const m = raw.match(/[?&]ik=([A-Za-z0-9_-]{6,})/)
    if (m) return m[1]
  }
  return null
}

// Final fallback: Gmail's ik lives only in the page's main-world globals
// (window.GM_ID_KEY / GLOBALS[9]), unreachable from this isolated world. Ask the
// service worker to read it via chrome.scripting in the MAIN world.
async function ikFromPageWorld() {
  try {
    const res = await rpc({ type: 'get-ik' })
    return res && /^[A-Za-z0-9_-]{6,}$/.test(res.ik || '') ? res.ik : null
  } catch { return null }
}

// Gmail's view=om HTML-escapes the raw source inside a <pre>; undo the handful of
// entities it uses so the reconstructed RFC822 text is faithful for parsing.
function htmlUnescape(s) {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'").replace(/&#x27;/gi, "'").replace(/&amp;/g, '&')
}

async function fetchRawSource(id) {
  const ik = resolveIk() || await ikFromPageWorld()
  if (!ik) throw Error('Gmail session token unavailable; Gmail markup may have changed.')
  const url = new URL(accountPath(), location.origin)
  url.search = new URLSearchParams({ ik, view: 'om', permmsgid: id })
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 15000)
  try {
    const response = await fetch(url, { credentials: 'include', signal: controller.signal })
    if (!response.ok) throw Error('Gmail original-message request failed: HTTP ' + response.status)
    const body = await response.text()
    // Current Gmail returns an HTML "Original Message" viewer page with the RFC822
    // source HTML-escaped inside a <pre>, not raw text/plain. Extract and unescape
    // it; fall back to the body as-is for the old raw-bytes behavior.
    const pre = body.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i)
    const raw = pre ? htmlUnescape(pre[1]) : body
    if (!/^[A-Za-z0-9-]+:\s/.test(raw.slice(0, 500))) throw Error('Gmail did not return original email bytes.')
    const bytes = new TextEncoder().encode(raw)
    if (bytes.length > 1048576) throw Error('Email exceeds 1 MiB limit.')
    let binary = ''
    for (let i = 0; i < bytes.length; i += 16384) binary += String.fromCharCode(...bytes.subarray(i, i + 16384))
    return btoa(binary)
  } finally { clearTimeout(timer) }
}

function compact(result) {
  return { id: result.id, score: result.score, risk: result.risk, triage: result.triage,
    findings: (result.findings || []).slice(0, 4).map(f => ({ title: f.title })),
    attribution: result.assessment?.attribution ? {
      confidence_score: result.assessment.attribution.confidence_score, band: result.assessment.attribution.band
    } : null }
}

function el(tag, className, text) {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text != null) node.textContent = text
  return node
}

function render(container, key, result, error) {
  const stamp = JSON.stringify([key, result?.id, error])
  const previous = container.querySelector(':scope > .etd-banner')
  if (previous?.dataset.stamp === stamp) return
  previous?.remove()
  const priority = result?.triage?.priority
  const tone = error ? 'neutral' : priority === 'urgent' || result.score >= 60 ? 'danger' :
    priority !== 'routine' || result.score >= 25 ? 'warn' : 'good'
  const banner = el('div', 'etd-banner etd-banner-' + tone)
  banner.dataset.stamp = stamp

  const head = el('div', 'etd-head')
  head.appendChild(el('span', 'etd-brand', 'Gmail Guard'))
  if (!error) {
    const chip = el('span', 'etd-score')
    chip.appendChild(el('span', 'etd-score-num', String(result.score)))
    chip.appendChild(el('span', 'etd-score-max', '/100'))
    head.appendChild(chip)
  }
  banner.appendChild(head)

  banner.appendChild(el('div', 'etd-verdict',
    error ? 'Scan unavailable' : (result.triage?.label || (result.risk + ' risk'))))
  banner.appendChild(el('div', 'etd-action',
    error || result.triage?.action || 'No configured signals is not proof of safety.'))

  const findings = result?.findings || []
  if (findings.length) {
    const list = el('ul', 'etd-findings')
    for (const f of findings) list.appendChild(el('li', 'etd-finding', f.title))
    banner.appendChild(list)
  }

  if (result?.attribution) {
    banner.appendChild(el('div', 'etd-foot',
      'Attribution evidence ' + result.attribution.confidence_score + '/100 — infrastructure signal, not proof of identity.'))
  }

  container.prepend(banner)
}

async function scanIfNeeded() {
  const opened = findOpenMessage()
  if (!opened) { setStatus('Gmail Guard: no open email detected'); return }
  let key
  let account
  try {
    account = accountPath()
    const { backendUrl } = await rpc({ type: 'get-backend-url' })
    if (accountPath() !== account) return
    key = JSON.stringify([account, backendUrl, opened.id])
    const current = scanState.get(key)
    if (current?.result) { render(opened.container, key, current.result); setStatus('Gmail Guard: watching for emails'); return }
    if (!scanState.begin(key)) {
      if (current?.error) render(opened.container, key, null, current.error)
      return
    }
    setStatus('Gmail Guard: scanning opened email', 'busy')
    const rawBase64 = await fetchRawSource(opened.id)
    const response = await rpc({ type: 'scan-email', rawBase64, expectedBackend: backendUrl })
    if (!response.ok) throw Error(response.error || 'Analysis failed.')
    if (!response.result?.triage || typeof response.result.score !== 'number') throw Error('Invalid analysis response.')
    const result = compact(response.result)
    scanState.success(key, result)
    const visible = findOpenMessage()
    if (visible?.id === opened.id && accountPath() === account) render(visible.container, key, result)
    setStatus('Gmail Guard: watching for emails')
  } catch (error) {
    if (key) {
      const retryAt = scanState.failure(key, error.message)
      clearTimeout(retryTimer)
      retryTimer = setTimeout(scanIfNeeded, Math.max(0, retryAt - Date.now()))
    } else {
      clearTimeout(retryTimer)
      retryTimer = setTimeout(scanIfNeeded, 30000)
    }
    if (opened.container.isConnected) render(opened.container, key || opened.id, null, error.message)
    setStatus('Gmail Guard: last scan failed; retry pending', 'error')
  }
}

let debounce = null
new MutationObserver(() => {
  clearTimeout(debounce)
  debounce = setTimeout(scanIfNeeded, 800)
}).observe(document.body, { childList: true, subtree: true })
setStatus('Gmail Guard: watching for emails')
