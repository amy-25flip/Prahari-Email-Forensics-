import { useRef, useState } from 'react'
import axios from 'axios'
import { Download, Upload } from 'lucide-react'

export default function CheckpointTools() {
  const input=useRef()
  const [message,setMessage]=useState('')
  const [busy,setBusy]=useState(false)
  async function save() {
    setBusy(true)
    try {
      const response=await axios.get('/api/checkpoint')
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
      const response=await axios.post('/api/checkpoint/verify',value,{headers:{'X-Requested-With':'Email-Threat-Detection'}})
      setMessage(`${response.data.valid?'Match':'Not verified'}: ${response.data.detail}`)
    } catch {setMessage('Checkpoint could not be verified. Supply the original checkpoint JSON from this session.')}
    finally {setBusy(false);input.current.value=''}
  }
  return <div><div className="exports"><button disabled={busy} onClick={save}><Download size={14}/>Checkpoint</button><button disabled={busy} onClick={()=>input.current.click()}><Upload size={14}/>Verify checkpoint</button></div>
    <input type="file" hidden ref={input} accept=".json" onChange={e=>verify(e.target.files[0])}/>
    <p>Session checkpoint; independent custody required. Not a third-party signature.</p>
    {message&&<p role="status">{message}</p>}
  </div>
}
