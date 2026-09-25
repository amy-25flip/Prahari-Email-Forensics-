const { test } = require('node:test')
const assert = require('node:assert/strict')
const vm = require('node:vm')
const fs = require('node:fs')
const path = require('node:path')
const source = name => fs.readFileSync(path.join(__dirname, name), 'utf8')

function state() {
  const context = vm.createContext({})
  vm.runInContext(source('scan-state.js'), context)
  let now = 0
  return { cache: new context.GmailGuardScanState(() => now), advance: n => { now += n } }
}

test('failed scans retry; pending scans deduplicate; successes expire', () => {
  const { cache, advance } = state()
  assert.equal(cache.begin('a'), true)
  assert.equal(cache.begin('a'), false)
  cache.failure('a', 'offline')
  assert.equal(cache.begin('a'), false)
  advance(5000)
  assert.equal(cache.begin('a'), true)
  cache.success('a', { id: 'report' })
  assert.equal(cache.get('a').result.id, 'report')
  assert.equal(cache.begin('a'), false)
  advance(3600000)
  assert.equal(cache.begin('a'), true)
})

test('cache is bounded without evicting pending requests', () => {
  const { cache } = state()
  for (let i = 0; i < 100; i++) assert.equal(cache.begin(String(i)), true)
  assert.equal(cache.begin('overflow'), false)
  cache.success('0', {})
  assert.equal(cache.begin('overflow'), true)
  assert.equal(cache.entries.size, 100)
})

test('background preserves original bytes and rejects backend configuration races', async () => {
  let sent
  const context = vm.createContext({ URL, Uint8Array, atob,
    chrome: { storage: { local: { get: async () => ({ backendUrl: 'http://localhost:8012' }) } }, runtime: { onMessage: { addListener() {} } } },
    fetch: async (url, options) => { sent = { url, options }; return { ok: true, json: async () => ({ id: 'ok' }) } }
  })
  vm.runInContext(source('background.js'), context)
  const bytes = Buffer.from([70, 114, 111, 109, 58, 32, 97, 13, 10, 13, 10, 0, 128, 255])
  await context.analyze(bytes.toString('base64'), 'http://localhost:8012')
  assert.deepEqual(Buffer.from(sent.options.body), bytes)
  assert.equal(sent.options.headers['Content-Type'], 'message/rfc822')
  await assert.rejects(context.analyze(bytes.toString('base64'), 'http://localhost:8000'), /Backend changed/)
  await assert.rejects(context.analyze('', 'http://localhost:8012'), /between 1 byte/)
})

// ---------- click-time guard ----------
function loadGuard() {
  const context = vm.createContext({ URL })
  vm.runInContext(source('click-guard.js'), context)
  return context.GmailGuardClickGuard
}

class FakeNode {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.attrs = {}; this.className = ''; this.textContent = ''; this.removed = false; this.focused = false }
  appendChild(node) { this.children.push(node); node.parent = this; return node }
  setAttribute(k, v) { this.attrs[k] = v }
  getAttribute(k) { return this.attrs[k] }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn) }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter(f => f !== fn) }
  remove() { this.removed = true; if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this) }
  focus() { this.focused = true }
  contains(node) { return node === this || this.children.some(c => c.contains?.(node)) }
  closest(selector) { return selector === 'a[href]' && this.tag === 'a' && this.attrs.href ? this : null }
  find(cls) { for (const c of this.children) { if (c.className === cls) return c; const hit = c.find?.(cls); if (hit) return hit } return null }
  fire(type, event) { for (const fn of this.listeners[type] || []) fn(event) }
}

function guardFixture(result) {
  const guard = loadGuard()
  const doc = { baseURI: 'https://mail.google.com/mail/u/0/', body: new FakeNode('body'), createElement: tag => new FakeNode(tag),
    listeners: {}, addEventListener(t, f) { (this.listeners[t] ||= []).push(f) }, removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f) } }
  const opened = []
  const win = { open: (...args) => opened.push(args) }
  const container = new FakeNode('div')
  const link = container.appendChild(new FakeNode('a')); link.attrs.href = 'https://www.google.com/url?q=https%3A%2F%2Fsecure-login.example%2Fverify&sa=D'
  const handle = guard.install(container, result, doc, win)
  const click = target => { const ev = { target, prevented: false, stopped: false, preventDefault() { this.prevented = true }, stopPropagation() { this.stopped = true } }; container.fire('click', ev); return ev }
  return { guard, doc, opened, container, link, handle, click }
}

test('click guard applies only to urgent or high-score messages', () => {
  const guard = loadGuard()
  assert.equal(guard.shouldGuard({ triage: { priority: 'urgent' }, score: 10 }), true)
  assert.equal(guard.shouldGuard({ triage: { priority: 'review' }, score: 60 }), true)
  assert.equal(guard.shouldGuard({ triage: { priority: 'review' }, score: 59 }), false)
  assert.equal(guard.shouldGuard({ triage: { priority: 'routine' }, score: 5 }), false)
  assert.equal(guard.shouldGuard(null), false)
  assert.equal(guard.shouldGuard({ triage: {}, score: 'NaN' }), false)
})

test('describeLink unwraps Google redirects, flags dangerous schemes and survives garbage', () => {
  const guard = loadGuard()
  const wrapped = guard.describeLink('https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fx&sa=D')
  assert.equal(wrapped.host, 'evil.example'); assert.equal(wrapped.internal, false); assert.equal(wrapped.dangerous, false)
  assert.equal(guard.describeLink('javascript:alert(1)').dangerous, true)
  assert.equal(guard.describeLink('data:text/html;base64,AAAA').dangerous, true)
  assert.equal(guard.describeLink('https://mail.google.com/mail/u/0/#inbox').internal, true)
  assert.equal(guard.describeLink('https://evilmail.google.com.attacker.example/').internal, false)
  assert.equal(guard.describeLink('http://[bad').ok, false)
  assert.equal(guard.describeLink(undefined).internal, true)   // a missing href resolves to the current Gmail page and is never intercepted
})

test('clicking a link in a high-risk message is stopped and shows the real destination', () => {
  const f = guardFixture({ triage: { priority: 'urgent' }, score: 82 })
  const ev = f.click(f.link)
  assert.equal(ev.prevented, true); assert.equal(ev.stopped, true)
  const overlay = f.doc.body.children[0]
  assert.equal(overlay.attrs.role, 'alertdialog'); assert.equal(overlay.attrs['aria-modal'], 'true')
  assert.match(overlay.find('etd-guard-card').find('etd-guard-dest').textContent, /^https:\/\/secure-login\.example\/verify/)
  assert.equal(overlay.find('etd-guard-card').find('etd-guard-actions').find('etd-guard-cancel').focused, true)   // safe default has focus
  assert.equal(f.opened.length, 0)                                                                                // nothing navigated
})

test('Open anyway opens once, in a new tab, with noopener; cancel opens nothing', () => {
  const f = guardFixture({ triage: { priority: 'urgent' }, score: 82 })
  f.click(f.link)
  const actions = f.doc.body.children[0].find('etd-guard-card').find('etd-guard-actions')
  actions.find('etd-guard-cancel').fire('click', { preventDefault() {} })
  assert.equal(f.opened.length, 0); assert.equal(f.doc.body.children.length, 0)
  f.click(f.link)
  f.doc.body.children[0].find('etd-guard-card').find('etd-guard-actions').find('etd-guard-open').fire('click', { preventDefault() {} })
  assert.deepEqual(f.opened, [['https://secure-login.example/verify', '_blank', 'noopener,noreferrer']])
  assert.equal(f.doc.body.children.length, 0)
})

test('dangerous-scheme links get no Open anyway button; Gmail-internal links and outside clicks pass through', () => {
  const f = guardFixture({ triage: { priority: 'urgent' }, score: 90 })
  f.link.attrs.href = 'javascript:alert(1)'
  f.click(f.link)
  const actions = f.doc.body.children[0].find('etd-guard-card').find('etd-guard-actions')
  assert.equal(actions.find('etd-guard-open'), null); assert.notEqual(actions.find('etd-guard-cancel'), null)
  actions.find('etd-guard-cancel').fire('click', { preventDefault() {} })
  const inbox = f.container.appendChild(new FakeNode('a')); inbox.attrs.href = 'https://mail.google.com/mail/u/0/#inbox'
  assert.equal(f.click(inbox).prevented, false)
  const outside = new FakeNode('a'); outside.attrs.href = 'https://elsewhere.example/'
  assert.equal(f.click(outside).prevented, false)
  assert.equal(f.click(new FakeNode('span')).prevented, false)
})

test('Escape closes the dialog and remove() detaches the guard completely', () => {
  const f = guardFixture({ triage: { priority: 'urgent' }, score: 90 })
  f.click(f.link)
  assert.equal(f.doc.body.children.length, 1)
  let prevented = false
  f.doc.listeners.keydown.forEach(fn => fn({ key: 'Escape', preventDefault() { prevented = true } }))
  assert.equal(prevented, true); assert.equal(f.doc.body.children.length, 0)
  f.click(f.link); f.handle.remove()
  assert.equal(f.doc.body.children.length, 0)
  assert.equal(f.click(f.link).prevented, false)
})
