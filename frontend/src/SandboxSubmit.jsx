import { useState } from 'react'
import axios from 'axios'

export default function SandboxSubmit({ caseId, sha256 }) {
  const [state, setState] = useState(null)
  const [busy, setBusy] = useState(false)
  async function submit() {
    setBusy(true)
    try {
      const response = await axios.post(`/api/cases/${caseId}/attachments/${sha256}/sandbox`, {}, { headers: { 'X-Requested-With': 'Email-Threat-Detection' } })
      setState(response.data)
    } catch (e) { setState({ status: 'error', detail: e.response?.data?.detail || 'Submission failed.' }) }
    finally { setBusy(false) }
  }
  async function check() {
    if (!state?.analysis_id) return
    setBusy(true)
    try {
      const response = await axios.get(`/api/attachments/sandbox/${state.analysis_id}`)
      setState({ ...response.data, analysis_id: state.analysis_id })
    } catch { setState({ ...state, detail: 'Could not check status.' }) }
    finally { setBusy(false) }
  }
  return <div className="sandbox-submit">
    {!state && <button disabled={busy} onClick={submit} title="Uploads the actual attachment content to VirusTotal for fresh multi-engine sandbox analysis — unlike hash lookup, this shares file content externally.">Submit for sandbox analysis</button>}
    {state && <div className="map-status">
      <strong>{state.status}</strong>: {state.detail}
      {state.status === 'submitted' || state.status === 'pending' ? <button disabled={busy} onClick={check} style={{ marginLeft: 8 }}>Check status</button> : null}
    </div>}
  </div>
}
