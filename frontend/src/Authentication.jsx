const alignment = value => value === true ? 'yes' : value === false ? 'no' : 'not established'

export default function Authentication({ values }) {
  return <section className="section"><div className="section-head"><h3>Sender authentication</h3></div>{Object.entries(values).map(([name, value]) => <div className="auth-row" key={name}>
    <div><strong>{name.toUpperCase()}</strong><span className={`badge ${value.status==='pass'?'good':value.status==='fail'?'danger':'warn'}`}>{value.status}</span></div><p>{value.detail}</p>
    {value.inputs && <p className="mono">IP: {value.inputs.client_ip}<br/>MAIL FROM: {value.inputs.mail_from}<br/>HELO: {value.inputs.helo}</p>}
    {value.context_source && <p>Context: {value.context_source}</p>}
    {value.signatures?.map((s,i)=><p key={i}>Signature {i+1}: {s.status} · {s.domain} / {s.selector}<br/>{s.detail}</p>)}
    {value.record && <details><summary>Policy and alignment</summary><p className="mono">{value.policy_domain}: {value.record}</p><p>SPF aligned: {alignment(value.spf_aligned)} · DKIM aligned: {alignment(value.dkim_aligned)}</p><p>{value.standard}</p></details>}
    {value.observed_at && <small className="lookup-date">Checked {new Date(value.observed_at*1000).toLocaleString()}</small>}
  </div>)}</section>
}
