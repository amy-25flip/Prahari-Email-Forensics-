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
