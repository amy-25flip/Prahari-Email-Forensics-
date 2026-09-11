const backendInput = document.getElementById('backend')
const statusEl = document.getElementById('status')
const historyEl = document.getElementById('history')
const tone = score => score >= 60 ? 'danger' : score >= 25 ? 'warn' : 'good'

async function load() {
  const { backendUrl, history = [] } = await chrome.storage.local.get(['backendUrl', 'history'])
  backendInput.value = backendUrl || 'http://localhost:8010'
  historyEl.innerHTML = history.length ? history.map(h => `
    <div class="row">
      <div><strong>${escapeHtml(h.subject || '(no subject)')}</strong><br><small>${escapeHtml(h.sender || '')}</small></div>
      <span class="badge ${tone(h.score)}">${h.score}</span>
    </div>`).join('') : '<div class="empty">No emails scanned yet. Open one in Gmail.</div>'
}

function escapeHtml(value) {
  const div = document.createElement('div')
  div.textContent = value
  return div.innerHTML
}

document.getElementById('save').addEventListener('click', async () => {
  const value = backendInput.value.trim().replace(/\/$/, '')
  if (!value) return
  await chrome.storage.local.set({ backendUrl: value })
  statusEl.textContent = 'Saved. Reload Gmail for it to take effect.'
})

load()
