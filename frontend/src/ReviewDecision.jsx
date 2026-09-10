import {useEffect,useState} from 'react'
import axios from 'axios'
import {Check,Pause} from 'lucide-react'

export default function ReviewDecision({caseId}) {
  const [state,setState]=useState('Loading')
  const [note,setNote]=useState('')
  const [ack,setAck]=useState(false)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  useEffect(()=>{let active=true;axios.get(`/api/cases/${caseId}/review`).then(r=>{if(active)setState(r.data.decision)}).catch(()=>{if(active)setError('Review status unavailable')});return()=>{active=false}},[caseId])
  async function submit(decision) {
    setBusy(true);setError('')
    try {const r=await axios.post(`/api/cases/${caseId}/review`,{decision,note,acknowledged:ack},{headers:{'X-Requested-With':'Email-Threat-Detection'}});setState(r.data.decision)}
    catch(e){setError(e.response?.data?.detail||'Review could not be recorded')}
    finally {setBusy(false)}
  }
  return <section className="ps-section"><h2>Analyst review: {state}</h2><p>Recorded decision only. No email is released or blocked.</p>
    <label>Verification note<textarea value={note} onChange={e=>setNote(e.target.value)} maxLength={1000} style={{width:'100%',minHeight:80}}/></label>
    <label><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/> I reviewed the findings and verification limitations</label>
    <div className="exports"><button disabled={busy||note.trim().length<20} onClick={()=>submit('hold')}><Pause size={14}/>Hold</button><button disabled={busy||!ack||note.trim().length<20} onClick={()=>submit('approved')}><Check size={14}/>Record approval</button></div>
    {error&&<p role="alert">{error}</p>}
  </section>
}
