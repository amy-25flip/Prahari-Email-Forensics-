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

async function fetchRawSource(id) {
  const script = [...document.scripts].map(s => s.textContent || '').find(s => /"ik"\s*:\s*"([A-Za-z0-9_-]+)"/.test(s))
  const ik = script?.match(/"ik"\s*:\s*"([A-Za-z0-9_-]+)"/)?.[1]
  if (!ik) throw Error('Gmail session token unavailable; Gmail markup may have changed.')
  const url = new URL(accountPath(), location.origin)
  url.search = new URLSearchParams({ ik, view: 'om', permmsgid: id })
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 15000)
  try {
    const response = await fetch(url, { credentials: 'include', signal: controller.signal })
    if (!response.ok) throw Error('Gmail original-message request failed: HTTP ' + response.status)
    const reader = response.body.getReader()
    const chunks = []
    let size = 0
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.length
      if (size > 1048576) { await reader.cancel(); throw Error('Email exceeds 1 MiB limit.') }
      chunks.push(value)
    }
    const bytes = new Uint8Array(size)
    let offset = 0
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
    const prefix = new TextDecoder().decode(bytes.slice(0, 500))
    if (!/^[A-Za-z0-9-]+:\s/.test(prefix)) throw Error('Gmail did not return original email bytes.')
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

function render(container, key, result, error) {
  const stamp = JSON.stringify([key, result?.id, error])
  const previous = container.querySelector(':scope > .etd-banner')
  if (previous?.dataset.stamp === stamp) return
  previous?.remove()
  const banner = document.createElement('div')
  banner.dataset.stamp = stamp
  const priority = result?.triage?.priority
  const tone = error ? 'neutral' : priority === 'urgent' || result.score >= 60 ? 'danger' :
    priority !== 'routine' || result.score >= 25 ? 'warn' : 'good'
  banner.className = 'etd-banner etd-banner-' + tone
  const title = document.createElement('strong')
  title.textContent = error ? 'Gmail Guard: scan unavailable' :
    'Gmail Guard: ' + (result.triage?.label || result.risk + ' risk') + ' (' + result.score + '/100)'
  banner.appendChild(title)
  const details = document.createElement('div')
  details.className = 'etd-banner-foot'
  details.textContent = error || result.triage?.action || 'No configured signals is not proof of safety.'
  banner.appendChild(details)
  for (const finding of result?.findings || []) {
    const line = document.createElement('div')
    line.textContent = finding.title
    banner.appendChild(line)
  }
  if (result?.attribution) {
    const line = document.createElement('div')
    line.textContent = 'Attribution evidence score: ' + result.attribution.confidence_score + '/100; not proof of identity.'
    banner.appendChild(line)
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
