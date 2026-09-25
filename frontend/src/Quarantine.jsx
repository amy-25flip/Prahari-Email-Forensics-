import { useCallback, useEffect, useState } from 'react'
import { ShieldAlert, Inbox, RefreshCw, LoaderCircle } from 'lucide-react'
import api from './api'

const tone = triage => triage === 'urgent' ? 'danger' : triage === 'review' ? 'warn' : 'neutral'

export default function Quarantine() {
  const [data, setData] = useState(null)
  const [inbox, setInbox] = useState([])
  const [detail, setDetail] = useState({})
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [q, i] = await Promise.all([api.get('/quarantine'), api.get('/gateway/inbox')])
      setData(q.data); setInbox(i.data.messages || []); setError('')
    } catch (e) {
      setError(e.response?.status === 403 ? 'Your role cannot view the quarantine (analyst or admin required).' : 'Could not load the quarantine.')
    }
  }, [])
  useEffect(() => {
    const first = setTimeout(load, 0)
    const timer = setInterval(load, 8000)
    return () => { clearTimeout(first); clearInterval(timer) }
  }, [load])

  async function act(id, action) {
    const verb = action === 'release' ? 'Release this message to the inbox' : 'Permanently discard this held message'
    if (!window.confirm(`${verb}? This decision is logged in the case's audit chain.`)) return
    setBusy(id + action)
    try { await api.post(`/quarantine/${id}/${action}`); await load() }
    catch (e) { setError(typeof e.response?.data?.detail === 'string' ? e.response.data.detail : 'Action failed.') }
    finally { setBusy('') }
  }
  async function toggle(id) {
    if (detail[id]) { setDetail(d => ({ ...d, [id]: null })); return }
    try { const res = await api.get(`/quarantine/${id}`); setDetail(d => ({ ...d, [id]: res.data })) } catch { setError('Could not load message details.') }
  }

  const gw = data?.gateway
  return <section className="section quarantine">
    <div className="section-head"><h3><ShieldAlert size={16}/> Held before delivery</h3><button className="secondary" onClick={load} aria-label="Refresh quarantine" title="Refresh"><RefreshCw size={15}/></button></div>
    {error && <p className="map-status warn" role="alert">{error}</p>}
    {!data ? <p role="status"><LoaderCircle size={14} className="spin"/> Loading...</p> : <>
      <p className="map-status">
        {gw?.listening ? <>Gateway listening on SMTP port <strong>{gw.port}</strong>. Messages scoring {gw.hold_score}+ or rated urgent are held; a message whose analysis fails is also held for manual review.</>
          : <>Gateway is not running. Start the server with <code>GATEWAY_SMTP_PORT=2525</code> and point an SMTP client or MTA relay at it to see mail analysed before delivery.</>}
        {' '}{data.inbox_count} message(s) delivered.
      </p>
      {data.held.length === 0 ? <div className="empty"><Inbox size={26}/><p>Nothing is being held.</p></div> : <div className="case-list">
        {data.held.map(m => <div className="quarantine-item" key={m.id}>
          <div className="case-row">
            <span className={`case-score ${tone(m.triage)}`}>{m.score}</span>
            <button className="case-open" onClick={() => toggle(m.id)} aria-expanded={!!detail[m.id]}><strong>{m.subject || '(no subject)'}</strong><small>{m.mail_from} to {(m.rcpt_tos || []).join(', ')} - held {new Date(m.held_at * 1000).toLocaleString()}</small></button>
            <button className="primary" disabled={busy === m.id + 'release'} onClick={() => act(m.id, 'release')}>Release</button>
            <button className="secondary" disabled={busy === m.id + 'discard'} onClick={() => act(m.id, 'discard')}>Discard</button>
          </div>
          <ul className="landing-findings">{(m.reasons || []).map((r, i) => <li key={i}><small>{r}</small></li>)}</ul>
          {detail[m.id] && <div className="landing-result">
            <p className="caveat">Findings: {(detail[m.id].meta.findings || []).join(', ') || 'none recorded'}</p>
            {detail[m.id].case && <p className="caveat">Triage: {detail[m.id].case.triage?.label}. {detail[m.id].case.triage?.action}</p>}
            {(detail[m.id].case?.urls || []).slice(0, 5).map((u, i) => <p key={i} className="mono landing-final">{u.url} (score {u.score})</p>)}
          </div>}
        </div>)}
      </div>}
      {inbox.length > 0 && <details><summary>Delivered messages ({inbox.length})</summary>
        <ul className="landing-findings">{inbox.slice(0, 10).map(m => <li key={m.id}><small>{m.subject || '(no subject)'} - {m.from} - triage {m.triage} {m.score && `(${m.score})`} {m.released_by && `- released by ${m.released_by}`}</small></li>)}</ul>
      </details>}
      <p className="caveat">{data.note}</p>
    </>}
  </section>
}
