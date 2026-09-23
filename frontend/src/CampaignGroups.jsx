import { useEffect, useState } from 'react'
import api from './api'

export default function CampaignGroups({openCase}) {
  const [data,setData]=useState(null)
  const [query,setQuery]=useState('')
  const [error,setError]=useState('')
  useEffect(()=>{let active=true;api.get('/campaigns').then(r=>{if(active)setData(r.data)}).catch(()=>{if(active)setError('Campaign evidence unavailable')});return()=>{active=false}},[])
  if(error)return <p role="alert">{error}</p>
  if(!data)return <p role="status">Loading campaign evidence...</p>
  const groups=data.campaigns.filter(g=>`${g.id} ${g.case_ids.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase()))
  return <section className="ps-section"><h2>Candidate campaigns</h2><input aria-label="Search campaigns" placeholder="Campaign or case ID" value={query} onChange={e=>setQuery(e.target.value)}/>
    <p>{data.campaigns.length} candidate groups · {data.edges.filter(e=>e.strength==='context_only').length} infrastructure-only relationships</p>
    {groups.map(g=><div key={g.id}><h3>{g.id} · {g.count} emails {g.sample?'· Demonstration':''}</h3><p>{g.assessment}</p>{g.case_ids.map(id=><button key={id} onClick={()=>openCase(id)}>{id}</button>)}</div>)}
    <details><summary>Infrastructure and thread evidence</summary>{data.edges.map((e,i)=><div key={i}><strong>{e.source} / {e.target} · {e.strength}</strong>{e.evidence.map((v,j)=><p key={j} style={{overflowWrap:'anywhere'}}>{v.type}: {v.value}</p>)}</div>)}</details>
  </section>
}
