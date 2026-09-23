import { useRef, useState } from 'react'
import api from './api'
import { Download, Upload, Link2 } from 'lucide-react'

export default function CheckpointTools() {
  const input=useRef()
  const proofInput=useRef()
  const [message,setMessage]=useState('')
  const [proofStatus,setProofStatus]=useState(null)
  const [busy,setBusy]=useState(false)
  async function save() {
    setBusy(true)
    try {
      const response=await api.get('/checkpoint')
      const url=URL.createObjectURL(new Blob([JSON.stringify(response.data,null,2)],{type:'application/json'}))
      const link=document.createElement('a');link.href=url;link.download='email-evidence-checkpoint.json';link.click()
      setTimeout(()=>URL.revokeObjectURL(url),1000)
    } catch {setMessage('Could not create a checkpoint. Check stored evidence integrity.')}
    finally {setBusy(false)}
  }
  async function verify(file) {
    if(!file)return
    setBusy(true)
    try {
      if(file.size>4096)throw Error('Checkpoint exceeds size limit')
      const value=JSON.parse(await file.text())
      const response=await api.post('/checkpoint/verify',value)
      setMessage(`${response.data.valid?'Match':'Not verified'}: ${response.data.detail}`)
    } catch {setMessage('Checkpoint could not be verified. Supply the original checkpoint JSON from this session.')}
    finally {setBusy(false);input.current.value=''}
  }
  async function blockchainStamp() {
    setBusy(true)
    try {
      const response=await api.post('/checkpoint/blockchain-stamp',{})
      const data=response.data
      setProofStatus(`${data.status}: ${data.detail}`)
      if(data.proof){
        const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}))
        const link=document.createElement('a');link.href=url;link.download='blockchain-timestamp-proof.json';link.click()
        setTimeout(()=>URL.revokeObjectURL(url),1000)
      }
    } catch (e) {setProofStatus(e.response?.data?.detail||'Blockchain timestamp submission failed.')}
    finally {setBusy(false)}
  }
  async function checkProof(file) {
    if(!file)return
    setBusy(true)
    try {
      if(file.size>16384)throw Error('Proof exceeds size limit')
      const value=JSON.parse(await file.text())
      const response=await api.post('/checkpoint/blockchain-verify',{sha256:value.sha256,proof:value.proof})
      setProofStatus(`${response.data.status}: ${response.data.detail}`)
    } catch {setProofStatus('Could not check this proof. Supply the downloaded blockchain-timestamp-proof.json file.')}
    finally {setBusy(false);proofInput.current.value=''}
  }
  return <div><div className="exports"><button disabled={busy} onClick={save}><Download size={14}/>Checkpoint</button><button disabled={busy} onClick={()=>input.current.click()}><Upload size={14}/>Verify checkpoint</button></div>
    <input type="file" hidden ref={input} accept=".json" onChange={e=>verify(e.target.files[0])}/>
    <p>Session checkpoint; independent custody required. Not a third-party signature.</p>
    {message&&<p role="status">{message}</p>}
    <div className="exports" style={{marginTop:10}}><button disabled={busy} onClick={blockchainStamp}><Link2 size={14}/>Blockchain timestamp</button><button disabled={busy} onClick={()=>proofInput.current.click()}><Upload size={14}/>Check timestamp</button></div>
    <input type="file" hidden ref={proofInput} accept=".json" onChange={e=>checkProof(e.target.files[0])}/>
    <p>Anchors the checkpoint hash to the Bitcoin blockchain via OpenTimestamps (independent of this server). Confirmation takes hours, not seconds; download the proof and check back later.</p>
    {proofStatus&&<p role="status">{proofStatus}</p>}
  </div>
}
