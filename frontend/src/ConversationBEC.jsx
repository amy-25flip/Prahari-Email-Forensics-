import { MessageCircle, AlertTriangle, ShieldCheck, Info } from 'lucide-react'

export default function ConversationBEC({ value }) {
  if (!value) return null

  const checks = value.checks || []
  const hasAnomalies = checks.length > 0
  const matchMethod = value.thread_matched_on === 'header'
    ? 'RFC In-Reply-To / References header chain'
    : value.thread_matched_on === 'fallback'
    ? 'Sender address + normalized subject fallback'
    : 'No prior thread messages identified'

  return (
    <section className="section" aria-label="Conversation-aware BEC Analysis">
      <div className="section-head">
        <h3>Conversation & Thread History</h3>
        <span className={`badge ${hasAnomalies ? 'danger' : 'good'}`}>
          {hasAnomalies ? `${checks.length} thread anomal${checks.length === 1 ? 'y' : 'ies'}` : 'Clean thread history'}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 14, padding: '10px 14px', background: '#0e1118', border: '1px solid #232834', borderRadius: 8 }}>
        <MessageCircle size={18} style={{ color: '#a3e635', flexShrink: 0 }} />
        <div style={{ fontSize: 11, color: '#c5cbd4' }}>
          <div><strong>Thread Matching Method:</strong> <span className="mono">{matchMethod}</span></div>
          <div style={{ color: '#9ca3b0', marginTop: 3 }}>
            {value.prior_messages_considered} prior message{value.prior_messages_considered === 1 ? '' : 's'} evaluated in session history
          </div>
        </div>
      </div>

      {hasAnomalies ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
          {checks.map((c, i) => (
            <div className="finding" key={i}>
              <AlertTriangle size={17} style={{ color: '#ef4444' }} />
              <div>
                <strong style={{ color: '#fca5a5' }}>{c.title}</strong>
                <p>{c.detail}</p>
                <small>Conversation BEC Anomaly · {c.kind}</small>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty" style={{ padding: '18px 12px' }}>
          <ShieldCheck size={24} style={{ color: '#a3e635' }} />
          <p>No mid-thread payment instruction changes, bank account swaps, or reply-to anomalies detected.</p>
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
