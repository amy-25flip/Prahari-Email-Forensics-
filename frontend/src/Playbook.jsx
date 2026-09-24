const LABELS = { now: 'Do now', next: 'Next', record: 'Record & report' }

export default function Playbook({ value }) {
  if (!value?.steps?.length) return null
  return <section className="ps-section playbook-section"><h2>Suggested next steps</h2>
    <ol className="playbook-steps">
      {value.steps.map((step, i) => <li key={i} className={`playbook-step ${step.priority}`}>
        <span className="playbook-tag">{LABELS[step.priority] || step.priority}</span>
        <strong>{step.action}</strong>
        <small>{step.why}</small>
      </li>)}
    </ol>
    <p className="caveat">{value.note}</p>
  </section>
}
