import { useEffect, useState } from 'react'
import api from './api'
import { UserCheck, MessageSquare, Send, LoaderCircle, AlertCircle } from 'lucide-react'

export default function CaseActivity({ caseId }) {
  const [owner, setOwner] = useState(null)
  const [ownerDraft, setOwnerDraft] = useState('')
  const [notes, setNotes] = useState([])
  const [noteDraft, setNoteDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [assignBusy, setAssignBusy] = useState(false)
  const [error, setError] = useState('')
  const [assignError, setAssignError] = useState('')
  const [editingOwner, setEditingOwner] = useState(false)

  useEffect(() => {
    let active = true
    async function load() {
      try {
        const [assignRes, notesRes] = await Promise.all([
          api.get(`/cases/${caseId}/assign`),
          api.get(`/cases/${caseId}/notes`)
        ])
        if (!active) return
        setOwner(assignRes.data.owner || null)
        setOwnerDraft(assignRes.data.owner || '')
        setNotes(notesRes.data || [])
      } catch {
        if (active) setError('Could not load case activity')
      }
    }
    load()
    return () => { active = false }
  }, [caseId])

  async function handleAssign(e) {
    e.preventDefault()
    const target = ownerDraft.trim()
    if (!target) return
    setAssignBusy(true)
    setAssignError('')
    try {
      const res = await api.post(`/cases/${caseId}/assign`, { owner: target })
      setOwner(res.data.owner)
      setEditingOwner(false)
    } catch (err) {
      setAssignError(err.response?.data?.detail || 'Could not assign case')
    } finally {
      setAssignBusy(false)
    }
  }

  async function handleAddNote(e) {
    e.preventDefault()
    const text = noteDraft.trim()
    if (!text) return
    setBusy(true)
    setError('')
    try {
      const res = await api.post(`/cases/${caseId}/notes`, { text })
      setNotes(prev => [...prev, res.data])
      setNoteDraft('')
    } catch (err) {
      if (err.response?.status === 503) {
        setError('Case note capacity reached: maximum of 50 notes per case.')
      } else {
        setError(err.response?.data?.detail || 'Could not add note to case.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="section" aria-label="Analyst Notes and Assignment">
      <div className="section-head">
        <h3>Case Activity & Notes</h3>
        <span className="badge">{notes.length} note{notes.length === 1 ? '' : 's'}</span>
      </div>

      <div style={{ marginBottom: 20, padding: '14px 18px', border: '1px solid #282d38', borderRadius: 8, background: '#0e1119' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <UserCheck size={16} style={{ color: '#a3e635' }} />
            <span style={{ fontSize: 12, color: '#9ca3b0' }}>Assigned Investigator:</span>
            <strong style={{ fontSize: 13, color: owner ? '#e6e8ef' : '#7c8797' }}>
              {owner ? owner : 'Unassigned'}
            </strong>
          </div>
          {!editingOwner ? (
            <button
              className="secondary"
              style={{ padding: '4px 10px', fontSize: 11 }}
              onClick={() => setEditingOwner(true)}
            >
              {owner ? 'Reassign' : 'Assign case'}
            </button>
          ) : (
            <form onSubmit={handleAssign} style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input
                type="text"
                value={ownerDraft}
                onChange={e => setOwnerDraft(e.target.value)}
                placeholder="Analyst name / handle"
                maxLength={200}
                style={{ background: '#11141c', color: '#e6e8ef', border: '1px solid #343947', borderRadius: 4, padding: '4px 8px', fontSize: 11 }}
              />
              <button className="primary" type="submit" disabled={assignBusy || !ownerDraft.trim()} style={{ padding: '4px 10px', fontSize: 11 }}>
                {assignBusy ? <LoaderCircle className="spin" size={12}/> : 'Save'}
              </button>
              <button className="secondary" type="button" onClick={() => { setEditingOwner(false); setOwnerDraft(owner || '') }} style={{ padding: '4px 8px', fontSize: 11 }}>
                Cancel
              </button>
            </form>
          )}
        </div>
        {assignError && <p role="alert" style={{ color: '#f68181', fontSize: 11, margin: '6px 0 0' }}>{assignError}</p>}
      </div>

      <div style={{ marginBottom: 18 }}>
        {notes.length ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 300, overflowY: 'auto' }}>
            {notes.map((n, i) => (
              <div key={i} style={{ padding: '10px 14px', background: '#10131b', border: '1px solid #262c37', borderRadius: 6 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                  <span style={{ fontSize: 10, color: '#a3e635', fontFamily: 'Consolas, monospace' }}>Note #{i + 1}</span>
                  <span style={{ fontSize: 10, color: '#9ca3b0' }}>{new Date(n.at * 1000).toLocaleString()}</span>
                </div>
                <p style={{ margin: 0, fontSize: 12, color: '#d5dbe5', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{n.text}</p>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty" style={{ padding: '24px 12px' }}>
            <MessageSquare size={22} />
            <p>No analyst notes recorded for this case yet.</p>
          </div>
        )}
      </div>

      <form onSubmit={handleAddNote} style={{ borderTop: '1px solid #252a35', paddingTop: 14 }}>
        <label style={{ display: 'block', fontSize: 12, color: '#9ca3b0', marginBottom: 6 }}>
          Add investigation note
          <textarea
            aria-label="Add case note"
            value={noteDraft}
            onChange={e => setNoteDraft(e.target.value)}
            placeholder="Record observations, forensic leads, or verification context..."
            maxLength={2000}
            style={{ width: '100%', height: 75, resize: 'vertical', marginTop: 6 }}
          />
        </label>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 6 }}>
          <small style={{ color: '#9ca3b0' }}>{noteDraft.trim().length} / 2000 characters (max 50 notes)</small>
          <button className="primary" type="submit" disabled={busy || !noteDraft.trim()} style={{ padding: '7px 14px', fontSize: 11 }}>
            {busy ? <LoaderCircle className="spin" size={14}/> : <Send size={14}/>} Record note
          </button>
        </div>
        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8, color: '#f68181', fontSize: 11 }}>
            <AlertCircle size={14}/> <span>{error}</span>
          </div>
        )}
      </form>
    </section>
  )
}
