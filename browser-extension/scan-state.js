// Page-local, bounded result cache. Never retain raw messages.
globalThis.GmailGuardScanState = class {
  constructor(now = () => Date.now()) { this.now = now; this.entries = new Map() }
  get(key) {
    const item = this.entries.get(key)
    if (item?.result && item.expires <= this.now()) { this.entries.delete(key); return null }
    return item || null
  }
  begin(key) {
    const old = this.get(key)
    if (old?.pending || old?.result || (old?.retryAt || 0) > this.now()) return false
    if (this.entries.size >= 100 && !old) {
      const removable = [...this.entries].find(([, item]) => !item.pending)
      if (!removable) return false
      this.entries.delete(removable[0])
    }
    this.entries.set(key, { pending: true, attempts: old?.attempts || 0 })
    return true
  }
  success(key, result) {
    this.entries.set(key, { result, expires: this.now() + 3600000 })
  }
  failure(key, error) {
    const attempts = Math.min(10, (this.entries.get(key)?.attempts || 0) + 1)
    const retryAt = this.now() + Math.min(300000, 5000 * 2 ** (attempts - 1))
    this.entries.set(key, { error, attempts, retryAt })
    return retryAt
  }
}
