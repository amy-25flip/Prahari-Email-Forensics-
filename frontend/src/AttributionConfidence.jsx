export default function AttributionConfidence({value}) {
  if(!value)return null
  const color=value.band==='high'?'good':value.band==='moderate'?'warn':'danger'
  const applied=value.factors.filter(f=>f.applied)
  return <section className="ps-section attribution-section"><h2>Attribution confidence</h2>
    <div className={`attribution-score ${color}`}><strong>{value.confidence_score}<small>/100</small></strong><span>{value.band.toUpperCase()} CONFIDENCE</span></div>
    <p>{value.policy}</p>
    <details open><summary>Factor breakdown ({applied.length} of {value.factors.length} applied)</summary>
      <table className="attribution-factors"><tbody>{value.factors.map((f,i)=><tr key={i} className={f.applied?(f.direction==='+'?'applied-positive':'applied-negative'):'not-applied'}><td className="mono">{f.direction}{f.weight}</td><td><strong>{f.factor.replace(/_/g,' ')}</strong><p>{f.detail}</p></td></tr>)}</tbody></table>
    </details>
    {value.caveats.map((c,i)=><p key={i} className="caveat">{c}</p>)}
  </section>
}
