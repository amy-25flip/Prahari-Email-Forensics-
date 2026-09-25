import { History, Globe2, FileCode, Link, Hash, Mail, Info } from 'lucide-react'

const ICONS = {
  sender_domain: Globe2,
  sender_address: Mail,
  reported_ip: Globe2,
  url: Link,
  attachment_hash: Hash,
  reply_address: Mail
}

const TYPE_LABELS = {
  sender_domain: 'Sender Domain',
  sender_address: 'Sender Address',
  reported_ip: 'Reported Relay IP',
  url: 'URL Destination',
  attachment_hash: 'Attachment SHA-256',
  reply_address: 'Reply Address'
}

export default function NetworkHistory({ value, openCase }) {
  if (!value) return null

  const recurring = value.recurring || []
  const hasRecurring = recurring.length > 0
  const cross = value.cross_session || []

  return (
    <section className="section" aria-label="Indicator Network History">
      <div className="section-head">
        <h3>Session Indicator History</h3>
        <span className={`badge ${hasRecurring || cross.length ? 'warn' : 'good'}`}>
          {hasRecurring ? `${recurring.length} recurring indicator${recurring.length === 1 ? '' : 's'}` : cross.length ? `${cross.length} seen in earlier analyses` : 'First observation'}
        </span>
      </div>

      {hasRecurring ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 12 }}>
          {recurring.map((item, i) => {
            const Icon = ICONS[item.type] || FileCode
            return (
              <div key={i} style={{ padding: '12px 14px', background: '#0e1118', border: '1px solid #282d38', borderRadius: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <Icon size={15} style={{ color: '#e2a564' }} />
                    <span style={{ fontSize: 11, fontWeight: 600, color: '#e6e8ef' }}>
                      {TYPE_LABELS[item.type] || item.type}
                    </span>
                  </div>
                  <span className="badge warn" style={{ fontSize: 10 }}>
                    Seen in {item.occurrence_count} prior case{item.occurrence_count === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="mono" style={{ fontSize: 11, color: '#a3e635', wordBreak: 'break-all', marginBottom: 8 }}>
                  {item.value}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, fontSize: 10, color: '#9ca3b0' }}>
                  <span>
                    First: {item.first_seen ? (typeof item.first_seen === 'number' ? new Date(item.first_seen * 1000).toLocaleString() : item.first_seen) : 'Unknown'}
                  </span>
                  {item.case_ids?.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                      <span>Prior cases:</span>
                      {item.case_ids.map(cid => (
                        <button
                          key={cid}
                          className="secondary"
                          style={{ padding: '2px 6px', fontSize: 9 }}
                          onClick={() => openCase && openCase(cid)}
                          title={`Open prior case ${cid}`}
                        >
                          {cid}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="empty" style={{ padding: '18px 12px' }}>
          <History size={24} style={{ color: '#a3e635' }} />
          <p>No prior occurrences of these sender domains, IPs, URLs, or hashes in this session's case history.</p>
        </div>
      )}

      {cross.length > 0 && (
        <div className="cross-session" role="region" aria-label="Seen across the deployment">
          <h4>Seen across the deployment</h4>
          {cross.map((c, i) => (
            <div key={i} className="cross-item">
              <span className="badge warn">{TYPE_LABELS[c.type] || c.type}</span>
              <span className="mono" style={{ wordBreak: 'break-all' }}>{c.value}</span>
              <small>{c.seen_count} earlier analys{c.seen_count === 1 ? 'is' : 'es'} - {c.other_sessions} other session{c.other_sessions === 1 ? '' : 's'} - last {new Date(c.last_seen * 1000).toLocaleDateString()}</small>
            </div>
          ))}
        </div>
      )}

      {value.scope && (
        <p className="caveat" style={{ fontSize: 11, color: '#9ca3b0', marginTop: 8 }}>
          <Info size={13} style={{ display: 'inline', verticalAlign: 'text-bottom', marginRight: 4 }} />
          {value.scope}
        </p>
      )}
    </section>
  )
}
