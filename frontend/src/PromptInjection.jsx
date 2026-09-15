import { Bot, ShieldCheck, Info } from 'lucide-react'

const LABELS = {
  instruction_pattern: 'Instruction pattern',
  hidden_instruction: 'Hidden instruction',
  hidden_comment_raw_html_only: 'Hidden HTML comment (raw HTML only)',
  hidden_content_present: 'Hidden content (informational)',
  zero_width_characters: 'Zero-width characters',
}

export default function PromptInjection({ value }) {
  if (!value) return null
  const indicators = value.indicators || []
  // hidden_content_present alone (CSS-hidden preheader text etc., common
  // and benign in ordinary marketing/ESP email) must not read as an alarm
  // the way an actual instruction pattern does -- see prompt_injection.py.
  const suspicious = indicators.filter(i => i.type !== 'hidden_content_present')
  const badge = suspicious.length ? 'danger' : indicators.length ? 'warn' : 'good'
  const badgeText = suspicious.length ? `${suspicious.length} detected` : indicators.length ? 'Hidden content only' : 'None detected'
  return <section className="section" aria-label="AI manipulation signals">
    <div className="section-head"><h3>AI manipulation signals</h3><span className={`badge ${badge}`}>{badgeText}</span></div>
    {indicators.length ? <>
      {indicators.map((item, i) => <div className="finding" key={i}>{item.type === 'hidden_content_present' ? <Info size={17}/> : <Bot size={17}/>}<div>
        <strong>{item.description}</strong>
        {item.excerpt && <p className="mono" style={{ overflowWrap: 'anywhere' }}>&ldquo;{item.excerpt}&rdquo;</p>}
        <small>{LABELS[item.type] || item.type}</small>
      </div></div>)}
    </> : <div className="empty"><ShieldCheck size={28}/><p>No content addressed to an AI system or classifier was found. This is not proof the email is safe.</p></div>}
    <p className="caveat">{value.detail}</p>
  </section>
}
