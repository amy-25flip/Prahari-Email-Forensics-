export default function DomainIntelligence({ value }) {
  if (!value) return null
  return <section className="section"><div className="section-head"><h3>Sender domain intelligence</h3><span className="badge">{value.status}</span></div>
    <p className="mono">{value.domain || 'No sender domain'}</p>
    {value.status==='disabled' && <p>External DNS and registry enrichment was not enabled.</p>}
    {value.detail && <p>{value.detail}</p>}
    {Object.entries(value.dns || {}).map(([type,record]) => <div className="header-row" key={type}><strong>{type}</strong><span className="mono">{record.values.length ? record.values.join(' / ') : record.status}</span></div>)}
    {value.registration && <><p>Registered domain: {value.registered_domain}</p><p>Registrar: {value.registration.registrar || 'Not available'}</p><p>Registration date: {value.registration.registered_at || 'Not available'}</p><p>{value.registration.detail}</p><small>{value.registration.source || 'Registry lookup unavailable'}</small></>}
    <small className="lookup-date">Observed {new Date(value.observed_at*1000).toLocaleString()}{value.cached ? ' (cached)' : ''}</small>
  </section>
}
