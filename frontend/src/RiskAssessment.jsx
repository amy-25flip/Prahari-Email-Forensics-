import { AlertTriangle, ClipboardCheck } from 'lucide-react'

export default function RiskAssessment({ result }) {
  const value = result.triage
  if (!value) return null
  const Icon = value.priority === 'routine' ? ClipboardCheck : AlertTriangle
  return <section className="section" aria-label="Analyst review priority">
    <div className="section-head"><h3><Icon size={18}/> {value.label}</h3><span className={`badge ${value.priority === 'urgent' ? 'danger' : value.priority === 'routine' ? 'neutral' : 'warn'}`}>Review priority</span></div>
    {value.reasons.map(reason => <p key={reason}>{reason}</p>)}
    <p><strong>{value.action}</strong></p>
    <details><summary>Score and review decision</summary><p>{value.score_explanation}</p>
      <p>{value.policy}</p>
      {Object.entries(result.groups).map(([group, points]) => <div className="header-row" key={group}><strong>{group}</strong><span>{points} points after group cap</span></div>)}
    </details>
  </section>
}
