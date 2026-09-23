import { useEffect, useState } from 'react'
import api from './api'
import { KeyRound, RefreshCw, Trash2 } from 'lucide-react'

const tone = score => score >= 60 ? 'danger' : score >= 25 ? 'warn' : 'good'
const TOKEN_KEY = 'efp_gmail_token'
const POLL_MS = 15000

// sessionStorage (not localStorage): the Gmail cases read token grants access to
// every push-analyzed email, so it's kept only for this tab/session and cleared
// when the tab closes -- shrinking the window an XSS or a shared/persistent
// browser profile could lift it from. (A server-side per-user auth flow would be
// stronger still, and is the right move before any real public deployment.)
function readToken() { try { return sessionStorage.getItem(TOKEN_KEY) || '' } catch { return '' } }
function writeToken(value) { try { if (value) sessionStorage.setItem(TOKEN_KEY, value); else sessionStorage.removeItem(TOKEN_KEY) } catch { /* private browsing / storage blocked */ } }

export default function GmailAlerts({ openCase }) {
  const [token, setToken] = useState(readToken)
  const [draft, setDraft] = useState('')
  const [cases, setCases] = useState(null)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)

  async function load(activeToken) {
    try {
      const response = await api.get('/gmail/cases', { headers: { Authorization: `Bearer ${activeToken}` } })
      setCases(response.data); setError('')
    } catch (e) {
      if (e.response?.status === 401) { writeToken(''); setToken(''); setCases(null); setError('Token rejected. Re-enter the Gmail cases read token.') }
      else if (e.response?.status === 503) { setCases(null); setError('Gmail push is not configured on this server.') }
      else { setError('Could not load Gmail alerts. Retrying automatically.') }
    }
    setLoaded(true)
  }
  useEffect(() => {
    if (!token) return
    let active = true
    async function poll() { if (active) await load(token) }
    poll()
    const timer = setInterval(poll, POLL_MS)
    return () => { active = false; clearInterval(timer) }
  }, [token])

  function connect(e) {
    e.preventDefault()
    const value = draft.trim()
    if (!value) return
    writeToken(value); setToken(value); setDraft('')
  }
  function disconnect() { writeToken(''); setToken(''); setCases(null); setError(''); setLoaded(false) }

  if (!token) return <section className="section">
    <div className="section-head"><h3>Connect Gmail alerts</h3><KeyRound size={18}/></div>
    <p>Emails analyzed automatically from the live Gmail push pipeline land in a separate, dedicated session, not this browser's own case history. Enter the server's Gmail cases read token (<code>GMAIL_CASES_READ_TOKEN</code>) to view them here. The token is kept only for this browser tab and cleared when you close it.</p>
    <form className="smtp-fields" onSubmit={connect}><label>Read token<input type="password" aria-label="Gmail cases read token" value={draft} onChange={e => setDraft(e.target.value)} autoComplete="off"/></label><button className="primary" type="submit" disabled={!draft.trim()}>Connect</button></form>
    {error && <p className="map-status warn">{error}</p>}
  </section>

  return <section className="section">
    <div className="section-head"><h3>Live Gmail alerts</h3><div><button className="secondary" onClick={() => load(token)} title="Refresh now" aria-label="Refresh alerts now"><RefreshCw size={15}/></button><button className="secondary" onClick={disconnect} title="Disconnect this browser's token" aria-label="Disconnect this browser's token"><Trash2 size={15}/></button></div></div>
    <p className="map-status">Emails to the watched Gmail inbox appear here automatically, refreshing every {POLL_MS / 1000}s. Each one is analyzed by the same pipeline as a manual upload.</p>
    {error && <p className="map-status warn">{error}</p>}
    {!loaded ? <p role="status">Loading...</p> : cases === null ? null : cases.length === 0 ? <p className="map-status">No Gmail-push-analyzed emails yet.</p> : <div className="case-list">{cases.map(c => <div className="case-row" key={c.id}><span className={`case-score ${tone(c.score)}`}>{c.score}</span><button className="case-open" onClick={() => openCase(c.id)}><strong>{c.subject || '(no subject)'}</strong><small>{c.sender}</small></button><Badge>{new Date(c.created * 1000).toLocaleString()}</Badge></div>)}</div>}
  </section>
}

function Badge({ children }) { return <span className="badge neutral">{children}</span> }
