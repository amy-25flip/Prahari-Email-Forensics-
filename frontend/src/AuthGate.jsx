import { useState } from 'react'
import { KeyRound } from 'lucide-react'

export default function AuthGate({ error, onSubmit }) {
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(e) {
    e.preventDefault()
    const token = draft.trim()
    if (!token || busy) return
    setBusy(true)
    try { await onSubmit(token) } finally { setBusy(false); setDraft('') }
  }
  return <main className="auth-shell">
    <section className="intake auth-card">
      <div className="section-head"><h2>Sign in</h2><KeyRound size={20}/></div>
      <p>This server uses role-based access. Enter the personal access token issued to you (viewer, analyst or admin). It is kept only for this browser tab.</p>
      <form onSubmit={submit} className="smtp-fields">
        <label>Access token<input type="password" aria-label="Access token" value={draft} onChange={e => setDraft(e.target.value)} autoComplete="off" autoFocus/></label>
        <button className="primary" type="submit" disabled={!draft.trim() || busy}>{busy ? 'Checking...' : 'Sign in'}</button>
      </form>
      {error && <p className="map-status warn" role="alert">{error}</p>}
    </section>
  </main>
}
