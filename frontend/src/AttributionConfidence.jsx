export default function AttributionConfidence({value}) {
  if(!value)return null
  const color=value.band==='high'?'good':value.band==='moderate'?'warn':'danger'
  const applied=value.factors.filter(f=>f.applied)
  return <section className="ps-section attribution-section"><h2>Attribution confidence</h2>
    <div className={`attribution-score ${color}`}><strong>{value.confidence_score}<small>/100</small></strong><span>{value.band.toUpperCase()} CONFIDENCE</span></div>
    <p className="caveat">{value.policy}</p>
    <details><summary>Factor breakdown ({applied.length} of {value.factors.length} applied)</summary>
      <table className="attribution-factors">
        <caption className="sr-only" style={{position:'absolute',width:1,height:1,padding:0,margin:-1,overflow:'hidden',clip:'rect(0,0,0,0)',border:0}}>Attribution Confidence Factors</caption>
        <thead><tr><th style={{textAlign:'center',width:44,padding:'7px 10px',borderBottom:'1px solid #22252e'}}>Weight</th><th style={{textAlign:'left',padding:'7px 10px',borderBottom:'1px solid #22252e'}}>Factor & Evidence</th></tr></thead>
        <tbody>{value.factors.map((f,i)=><tr key={i} className={f.applied?(f.direction==='+'?'applied-positive':'applied-negative'):'not-applied'}><td className="mono">{f.direction}{f.weight}</td><td><strong>{f.factor.replace(/_/g,' ')}</strong> <span>{f.detail}</span></td></tr>)}</tbody>
      </table>
    </details>
    {value.caveats.map((c,i)=><p key={i} className="caveat">{c}</p>)}
  </section>
}
