import { AlertTriangle } from 'lucide-react'

export default function Conflicts({ result }) {
  const items = result.conflicts
  if (!items?.length) return null
  function describe(ref) {
    const [kind, index] = ref.split('/')
    if (kind === 'findings') return result.findings[Number(index)]?.detail
    if (kind === 'authentication') return `${index.toUpperCase()}: ${result.authentication[index]?.status}`
    if (kind === 'ml') return `NLP: ${result.ml.label} (${result.ml.confidence ?? 'unknown'}% model probability)`
    if (kind === 'urls') {
      const url = result.urls[Number(index)]
      return `Displayed: ${url?.displayed || 'Not captured'} | Destination: ${url?.url}`
    }
    return ref
  }
  return <section className="section" aria-label="Evidence conflicts">
    <div className="section-head"><h3>Evidence conflicts</h3><span className="badge warn">{items.length} for review</span></div>
    {items.map(item => <div className="finding" key={item.id}><AlertTriangle size={17}/><div>
      <strong>{item.title}</strong><p>{item.explanation}</p>
      {item.evidence_refs.map(ref => <p className="mono" key={ref}>{describe(ref)}</p>)}
      <div className="verification warn"><strong>Next verification</strong><p>{item.action}</p></div>
      <small>{item.assessment}</small>
    </div></div>)}
  </section>
}
