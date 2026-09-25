import { useState } from 'react'
import { Globe2, LoaderCircle } from 'lucide-react'
import api from './api'

export default function LandingInspect({ caseId, url }) {
  const [open, setOpen] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  async function run() {
    if (!confirmed || busy) return
    setBusy(true); setError(''); setResult(null)
    try {
      setResult((await api.post(`/cases/${caseId}/urls/inspect`, { url, confirm: true })).data)
    } catch (e) {
      setError(typeof e.response?.data?.detail === 'string' ? e.response.data.detail : 'Inspection could not be run.')
    } finally { setBusy(false) }
  }

  if (!open) return <button className="secondary landing-open" onClick={() => setOpen(true)}><Globe2 size={14}/> Inspect landing page (static)</button>
  return <div className="landing-panel">
    <p className="caveat">This fetches the page once, without JavaScript or cookies, and describes it. <strong>The destination will see this server&apos;s IP address.</strong> Only public web hosts are contacted.</p>
    <label className="landing-confirm"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/> I understand and want to contact this destination</label>
    <button className="primary" onClick={run} disabled={!confirmed || busy}>{busy ? <><LoaderCircle size={14} className="spin"/> Inspecting...</> : 'Run inspection'}</button>
    {error && <p className="map-status warn" role="alert">{error}</p>}
    {result && <div className="landing-result" role="region" aria-label="Landing page inspection result">
      <p><span className={`badge ${result.status === 'ok' ? 'good' : 'warn'}`}>{result.status}</span> {result.reason || ''}</p>
      {result.status === 'ok' && <>
        <p><strong>{result.title || '(no title)'}</strong></p>
        <p className="mono landing-final">{result.final_url}</p>
        {result.redirects?.length > 0 && <p className="caveat">{result.redirects.length} redirect(s) followed.</p>}
        {result.findings?.length ? <ul className="landing-findings">{result.findings.map((f, i) => <li key={i}><span className="badge warn">{f.title}</span> <small>{f.detail}</small></li>)}</ul> : <p className="caveat">No structural flags on the fetched page.</p>}
        {result.signals && <p className="caveat">{result.signals.forms} form(s), {result.signals.password_fields} password field(s), {result.signals.scripts_external} external script(s), {result.signals.iframes} frame(s). DOM hash {String(result.dom_hash || '').slice(0, 12)}</p>}
      </>}
      <details><summary>Fetch transcript</summary><pre>{(result.transcript || []).join('\n')}</pre></details>
      <p className="caveat">{result.scope}</p>
    </div>}
  </div>
}
