import { useEffect, useState } from 'react'
import api from './api'
import { Send, LoaderCircle } from 'lucide-react'

export default function SiemDelivery({ caseId }) {
  const [config, setConfig] = useState(null)
  const [receipt, setReceipt] = useState(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let active = true
    api.get('/siem').then(r => { if (active) setConfig(r.data) }).catch(() => { if (active) setConfig({enabled:false, mode:'unavailable'}) })
    return () => { active = false }
  }, [])
  async function send() {
    if (busy) return
    setBusy(true)
    try {
      const response = await api.post(`/cases/${caseId}/siem`, null, {timeout:20000})
      setReceipt(response.data)
    } catch { setReceipt({status:'unknown', detail:'Delivery could not be confirmed. Check the collector before retrying.'}) }
    finally { setBusy(false) }
  }
  return <section className="section"><div className="section-head"><h3>SOC delivery</h3><span className="badge">{config?.mode || 'Checking configuration'}</span></div>
    <p>{config?.detail || 'Delivery is unavailable until an administrator configures a collector.'}</p>
    <button className="secondary" onClick={send} disabled={!config?.enabled || busy || ['accepted','written'].includes(receipt?.status)}>{busy ? <LoaderCircle className="spin" size={16}/> : <Send size={16}/>} Send case metadata</button>
    {receipt && <p role="status"><strong>{receipt.status}: </strong>{receipt.detail}</p>}
  </section>
}
