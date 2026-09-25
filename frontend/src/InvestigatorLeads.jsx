import { Users } from 'lucide-react'

export default function InvestigatorLeads({ value }) {
  if (!value || value.status === 'disabled') return null
  return <section className="ps-section" aria-label="Investigator leads">
    <h2><Users size={16} aria-hidden="true"/> Investigator leads</h2>
    {value.items.length ? value.items.map(item => <div className="header-row" key={`${item.kind}-${item.subject}`}>
      <strong>{item.kind === 'registrar' ? `Registrar for ${item.subject}` : `Network owner of ${item.subject}`}</strong>
      <span>{[item.registrar || item.network, item.abuse_contact && `abuse: ${item.abuse_contact}`, item.registered_at && `registered ${item.registered_at.slice(0, 10)}`, item.range, item.country].filter(Boolean).join(' · ')}</span>
    </div>) : <p>No registry contacts could be retrieved (lookups are best effort).</p>}
    <p className="caveat">{value.caveat}</p>
  </section>
}
