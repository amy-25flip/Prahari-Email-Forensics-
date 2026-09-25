import { useEffect, useMemo, useRef, useState } from 'react'
import api, { roleToken } from './api'
import { ShieldCheck, ShieldAlert, ScanLine, Network, Files, Upload, ArrowUpRight, ArrowLeft, Download, Search, Trash2, X, LoaderCircle, Fingerprint, Mail, Globe2, Link2, AlertTriangle, ChevronRight, FileText } from 'lucide-react'
import AuthGate from './AuthGate'
import InvestigatorLeads from './InvestigatorLeads.jsx'
import LanguageNotice from './LanguageNotice'
import LandingInspect from './LandingInspect'
import Quarantine from './Quarantine'
import RelayMap from './RelayMap'
import Authentication from './Authentication'
import './index.css'
import './authentication.css'
import { FeedStatus, UrlReputation } from './Reputation'
import Conflicts from './Conflicts'
import RiskAssessment from './RiskAssessment'
import SiemDelivery from './SiemDelivery'
import DomainIntelligence from './DomainIntelligence'
import CheckpointTools from './CheckpointTools'
import CampaignGroups from './CampaignGroups'
import GmailAlerts from './GmailAlerts'
import PSAssessment from './PSAssessment'
import AttributionConfidence from './AttributionConfidence'
import SandboxSubmit from './SandboxSubmit'
import ReviewDecision from './ReviewDecision'
import PromptInjection from './PromptInjection'
import CaseActivity from './CaseActivity'
import Playbook from './Playbook'
import ConversationBEC from './ConversationBEC'
import NetworkHistory from './NetworkHistory'
import EvidenceGraph from './EvidenceGraph'
import './ps-features.css'

const tone = score => score >= 60 ? 'danger' : score >= 25 ? 'warn' : 'good'
const short = text => text.length > 40 ? text.slice(0, 37) + '...' : text

function Badge({ children, color = 'neutral' }) { return <span className={`badge ${color}`}>{children}</span> }
function Empty({ icon: Icon = Files, children }) { return <div className="empty"><Icon size={28}/><p>{children}</p></div> }
function Section({ title, meta, children }) { return <section className="section"><div className="section-head"><h3>{title}</h3>{meta}</div>{children}</section> }

function Workspace({ who, onSignOut }) {
  const [view, setView] = useState('analyze')
  const [redacted, setRedacted] = useState(false)
  const [maskEmails, setMaskEmails] = useState(false)
  const [tab, setTab] = useState('evidence')
  const [email, setEmail] = useState('')
  const [file, setFile] = useState(null)
  const [receipt, setReceipt] = useState('')
  const [enrich, setEnrich] = useState(false)
  const [smtpEnabled, setSmtpEnabled] = useState(false)
  const [smtp, setSmtp] = useState({ client_ip: '', mail_from: '', helo: '' })
  const [result, setResult] = useState(null)
  const [cases, setCases] = useState([])
  const [samples, setSamples] = useState([])
  const [health, setHealth] = useState(null)
  const [graph, setGraph] = useState({ nodes: [], edges: [] })
  // Defensive: the graph view does `graph.nodes.find(n => n.id === e.source).subject`
  // (and similarly for e.target) without a null guard -- if an edge ever
  // references a node id not present in graph.nodes (backend/store.py's
  // connections() currently builds both from one atomic snapshot so this
  // shouldn't happen today, but a future change to either side easily could),
  // that throws and crashes the graph view instead of just skipping the one
  // stale edge. Filtered once here so every render path below stays safe.
  const graphEdges = useMemo(() => {
    const nodeIds = new Set(graph.nodes.map(n => n.id))
    return graph.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))
  }, [graph])
  const [edge, setEdge] = useState(null)
  const [graphTab, setGraphTab] = useState('entities')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [query, setQuery] = useState('')
  const [verification, setVerification] = useState(null)
  const input = useRef()

  const fail = e => setError(typeof e.response?.data?.detail === 'string' ? e.response.data.detail : 'Could not complete the request. Check the backend and retry.')
  async function refresh() {
    const response = await api.get('/cases')
    setCases(response.data)
    const relations = await api.get('/connections')
    setGraph(relations.data)
    setEdge(null)
  }

  useEffect(() => {
    if (view !== 'cases') return
    const timer = setTimeout(async () => {
      try {
        const url = query.trim() ? `/cases?q=${encodeURIComponent(query.trim())}` : '/cases'
        const response = await api.get(url)
        setCases(response.data)
      } catch {
        /* keep current cases */
      }
    }, 200)
    return () => clearTimeout(timer)
  }, [query, view])
  useEffect(() => {
    let active = true
    async function init() {
      try {
        const h = await api.get('/health')
        if (!active) return
        setHealth(h.data)
        const s = await api.get('/samples')
        if (!active) return
        setSamples(s.data)
        await refresh()
      } catch (e) { if (active) fail(e) }
    }
    init()
    const timer = setInterval(() => api.get('/health').then(r => active && setHealth(r.data)).catch(() => active && setHealth(null)), 10000)
    return () => { active = false; clearInterval(timer) }
  }, [])

  async function analyze(sample) {
    if (busy) return
    setBusy(true); setError(''); setNotice(''); setVerification(null)
    try {
      const headers = enrich && smtpEnabled ? { 'X-SMTP-Context': JSON.stringify(smtp) } : {}
      if (file && receipt) headers['X-Receiver-Evidence'] = receipt
      let response
      if (sample) response = await api.post(`/samples/${sample}`)
      else if (file) response = await api.post(`/analyze?enrich=${enrich}`, await file.arrayBuffer(), { headers: { ...headers, 'Content-Type': 'message/rfc822' } })
      else response = await api.post(`/analyze?enrich=${enrich}`, { email }, { headers })
      setResult(response.data); setView('analyze'); setTab('evidence')
      await refresh()
    } catch (e) { fail(e) }
    finally { setBusy(false) }
  }
  async function openCase(id) {
    if (busy) return
    setBusy(true)
    try { setResult((await api.get(`/cases/${id}`)).data); setView('analyze'); setTab('evidence'); setVerification(null) }
    catch (e) { fail(e) }
    finally { setBusy(false) }
  }
  async function openGmailCase(id) {
    if (busy) return
    const token = (() => { try { return sessionStorage.getItem('efp_gmail_token') } catch { return '' } })()
    if (!token) return
    setBusy(true)
    try { setResult((await api.get(`/gmail/cases/${id}`, { headers: { Authorization: `Bearer ${token}` } })).data); setView('analyze'); setTab('evidence'); setVerification(null) }
    catch (e) { fail(e) }
    finally { setBusy(false) }
  }
  async function remove(id) {
    try { await api.delete(`/cases/${id}`); if (result?.id === id) setResult(null); setVerification(null); await refresh() }
    catch (e) { fail(e) }
  }
  async function verify() {
    try { setVerification((await api.get('/verify')).data) } catch (e) { fail(e) }
  }
  async function download(fmt) {
    try {
      const response = await api.get(`/cases/${result.id}/export/${fmt}?privacy=${redacted ? 'redacted' : 'full'}&mask_emails=${maskEmails ? 1 : 0}`, { responseType: 'blob' })
      const url = URL.createObjectURL(response.data)
      const a = document.createElement('a'); a.href = url; a.download = `case-${result.id}.${{ stix: 'stix.json', evidence: 'evidence.md' }[fmt] || fmt}`; a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (e) { fail(e) }
  }
  function selectFile(f) {
    if (!f) return
    if (f.size > 1048576) { setError('Email exceeds 1 MiB.'); return }
    if (!f.name.toLowerCase().endsWith('.eml')) { setError('Choose an .eml email file.'); return }
    setFile(f); setReceipt(''); setError('')
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={e => { e.preventDefault(); setView('analyze') }}><span className="brand-icon"><ShieldCheck size={23}/></span><span>AI-Powered Email<br/>Threat Detection</span></a>
      <div className="workspace-label">WORKSPACE <span>01</span></div>
      <nav>{[['analyze', ScanLine, 'Investigate'], ['cases', Files, 'Case history'], ['gmail', Mail, 'Gmail alerts'], ['quarantine', ShieldAlert, 'Quarantine'], ['graph', Network, 'Connections']].map(([key, Icon, title]) => <button key={key} className={view === key ? 'nav-item active' : 'nav-item'} onClick={() => setView(key)}><Icon size={18}/><span>{title}</span>{key === 'cases' && <small>{cases.length}</small>}</button>)}</nav>
      <div className="sidebar-bottom"><span className="session-dot"/> {who ? `${who.actor} (${who.role})` : 'Private session'}{who && <button className="secondary" onClick={onSignOut} style={{ marginLeft: 8, padding: '2px 8px', fontSize: 10 }}>Sign out</button>}<small>{health?.retention_hours ?? 24}-hour retention · {cases.length}/30 cases</small></div>
    </aside>
    <main>
      <header className="topbar"><div className="breadcrumb">Workspace <ChevronRight size={14}/><strong>{view === 'analyze' ? 'Investigate' : view === 'cases' ? 'Case history' : view === 'gmail' ? 'Gmail alerts' : view === 'quarantine' ? 'Quarantine' : 'Connections'}</strong></div><span className="model-state"><i className={health?.model === 'ready' ? 'online' : ''}/>{health?.model === 'ready' ? 'BERT ready' : health?.model === 'loading' ? 'BERT loading' : health ? 'AI unavailable' : 'API disconnected'}</span></header>
      <div className="content">
        <div className="page-heading"><div><div className="eyebrow">FORENSIC WORKSPACE</div><h1>{view === 'analyze' ? 'Email investigation' : view === 'cases' ? 'Case history' : view === 'gmail' ? 'Gmail alerts' : view === 'quarantine' ? 'Quarantine' : 'Campaign connections'}</h1></div></div>
        {error && <div className="message error" role="alert"><AlertTriangle size={18}/><span>{error}</span><button title="Dismiss error" aria-label="Dismiss error" onClick={() => setError('')}><X size={16}/></button></div>}
        {notice && <div className="message">{notice}</div>}
        {view === 'analyze' && !result && <div className="hero"><p>Traces the relay chain, scores authentication and attribution, and flags what the evidence actually supports.</p></div>}
        <div className="feed-strip"><ShieldCheck size={15}/><FeedStatus feed={result && view === 'analyze' ? result.reputation_feed : health?.reputation}/></div>
        {view === 'analyze' && <>
          {!result ? <div className="intake-layout"><section className="intake"><div className="section-head"><h2>New investigation</h2><Fingerprint size={20}/></div><div className="input-tabs"><span>Raw email</span><button onClick={() => input.current.click()}><Upload size={15}/>Upload .eml</button><input ref={input} type="file" accept=".eml" hidden onChange={e => selectFile(e.target.files[0])}/></div>
            {file ? <div className="selected-file"><FileText size={32}/><strong>{file.name}</strong><small>{(file.size / 1024).toFixed(1)} KiB · original bytes preserved</small><button title="Remove file" aria-label="Remove file" onClick={() => { setFile(null); setReceipt(''); input.current.value = '' }}><X size={18}/></button></div> : <textarea aria-label="Raw email source" value={email} onChange={e => setEmail(e.target.value)} placeholder={'From: sender@example.com\nTo: analyst@college.edu\nSubject: ...\nReceived: ...\n\nEmail body'} spellCheck={false}/>}
            <details className="smtp-context"><summary>Receiver-signed evidence (when available)</summary><input type="file" aria-label="Receiver evidence JSON" accept=".json" disabled={!file} onChange={async e=>{const chosen=e.target.files[0];if(!chosen){setReceipt('');return}if(chosen.size>8192){setError('Receiver evidence exceeds 8 KiB');setReceipt('');return}try{setReceipt(JSON.stringify(JSON.parse(await chosen.text())));setError('')}catch{setReceipt('');setError('Invalid receiver evidence JSON')}}}/><small>{receipt?'Receipt selected; server verification required':'Original .eml and a configured trusted receiver required'}</small></details>
            <label className="enrichment"><input type="checkbox" checked={enrich} onChange={e => setEnrich(e.target.checked)}/><span>External enrichment<small>Queries DNS, sends public relay IPs to ipwho.is, and looks up the sender domain with its registry. Email bodies stay on this server.</small></span></label>
            {enrich && <div className="smtp-context"><label className="enrichment"><input type="checkbox" checked={smtpEnabled} onChange={e => setSmtpEnabled(e.target.checked)}/><span>Receiver SMTP context<small>Analyst-supplied values from receiver logs; email headers alone are not trusted.</small></span></label>{smtpEnabled && <div className="smtp-fields">{[['client_ip', 'Connecting IP'], ['mail_from', 'Envelope MAIL FROM'], ['helo', 'HELO domain']].map(([key, label]) => <label key={key}>{label}<input value={smtp[key]} onChange={e => setSmtp({ ...smtp, [key]: e.target.value })}/></label>)}</div>}</div>}
            <div className="input-footer"><span><ShieldCheck size={14}/> Session-isolated storage</span><button className="primary" disabled={busy || (!file && !email.trim()) || (enrich && smtpEnabled && Object.values(smtp).some(v => !v.trim()))} onClick={() => analyze()}>{busy ? <LoaderCircle className="spin" size={17}/> : <ScanLine size={17}/>} {busy ? 'Analyzing' : 'Analyze email'}</button></div></section>
            <aside className="sample-list"><div className="section-head"><h3>Sample investigations</h3></div><Badge>Controlled fixtures</Badge>{samples.map((s, i) => <button disabled={busy} className="sample" key={s.id} onClick={() => analyze(s.id)}><span className="sample-number">0{i + 1}</span><span><strong>{s.title}</strong><small>{s.kind}</small></span><ArrowUpRight size={17}/></button>)}<div className="sample-note">Reserved domains and documentation IPs. Samples are analyzed by the same pipeline; no real-world attribution is implied.</div></aside></div> : <>
            <div className="case-toolbar"><button onClick={() => { setResult(null); setVerification(null); setFile(null); setEmail(''); setReceipt(''); setSmtp({ client_ip: '', mail_from: '', helo: '' }); setSmtpEnabled(false); setEnrich(false); if (input.current) input.current.value = '' }}><ArrowLeft size={16}/> New investigation</button><span className="mono">CASE {result.id}</span><div className="exports"><label><input type="checkbox" checked={redacted} onChange={e=>setRedacted(e.target.checked)}/> Redact exports</label><label title="Partially masks email addresses (j***@domain). Off by default: addresses are forensic evidence."><input type="checkbox" checked={maskEmails} onChange={e=>setMaskEmails(e.target.checked)}/> Mask emails</label>{['pdf', 'json', 'csv', 'cef', 'stix', 'evidence'].map(fmt => <button key={fmt} onClick={() => download(fmt)} title={{ stix: 'Download STIX 2.1 bundle of adverse indicators (TLP:AMBER)', evidence: 'Download electronic-evidence support pack (draft, for a human signer)' }[fmt] || `Download ${fmt.toUpperCase()} report`}><Download size={14}/>{{ evidence: 'EVIDENCE PACK' }[fmt] || fmt.toUpperCase()}</button>)}</div></div>
            <div className="subject-line"><Mail size={22}/><div><h2>{result.subject}</h2><p>{result.sender}</p></div>{result.sample && <Badge>Fixture</Badge>}</div>
            <div className="metrics"><div className={`risk-metric ${tone(result.score)}`}><div className="gauge" style={{ '--progress': `${result.score}%` }}><strong>{result.score}<small>/100</small></strong></div><div><span className="metric-label">EVIDENCE SCORE</span><h2>{result.risk}</h2><small>Grouped heuristic score</small></div></div><div><span className="metric-label">NLP CLASSIFICATION</span><h2 className={result.ml.verdict ? ({phishing:'danger',caution:'warn',uncertain:'warn',legitimate:'good'}[result.ml.verdict.band] || 'warn-text') : 'warn-text'} title={result.ml.verdict?.note || ''}>{result.ml.verdict?.summary || result.ml.label}</h2><small>{result.ml.phishing_probability != null ? `${result.ml.phishing_probability}% phishing probability · uncalibrated${result.ml.verdict?.authenticated_sender ? ' · sender authenticated' : ''}` : (result.ml.confidence != null ? `${result.ml.confidence}% model probability · uncalibrated` : 'No model prediction available')}</small></div><div><span className="metric-label">ATTRIBUTION CONFIDENCE</span><h2 className={result.assessment?.attribution ? (result.assessment.attribution.band === 'high' ? 'good' : result.assessment.attribution.band === 'moderate' ? 'warn' : 'danger') : 'warn-text'}>{result.assessment?.attribution ? `${result.assessment.attribution.confidence_score}/100` : 'Pending'}</h2><small>{result.assessment?.attribution ? `${result.assessment.attribution.band} · ${result.hops.length} relay hop${result.hops.length === 1 ? '' : 's'}` : 'Assessment unavailable'}</small></div><div><span className="metric-label">REVIEW PRIORITY</span><h2 className={{ urgent: 'danger', review: 'warn', incomplete: 'warn-text', routine: 'good' }[result.triage?.priority] || 'warn-text'}>{result.triage?.label || 'Unavailable'}</h2><small>{`Analyzed in ${(result.elapsed_ms / 1000).toFixed(2)} s - ${result.live_dns ? 'external enrichment on' : 'local checks only'}`}</small></div></div>
            <RiskAssessment result={result}/>
            <SiemDelivery key={result.id} caseId={result.id}/>
            <div className="view-tabs">{[['evidence', 'Evidence'], ['relay', 'Relay path'], ['urls', `URLs (${result.urls.length})`], ['source', 'Source & attachments']].map(([key, name]) => <button className={tab === key ? 'selected' : ''} key={key} onClick={() => setTab(key)}>{name}</button>)}</div>
            {tab === 'evidence' && <Conflicts result={result}/>}
            {tab === 'evidence' && <PromptInjection value={result.prompt_injection}/>}
            {tab === 'evidence' && <ConversationBEC value={result.assessment?.conversation}/>}
            {tab === 'evidence' && <NetworkHistory value={result.assessment?.network_history} openCase={openCase}/>}
            {tab === 'evidence' && <><LanguageNotice value={result.language}/><Playbook value={result.assessment?.playbook}/><AttributionConfidence value={result.assessment?.attribution}/><InvestigatorLeads value={result.assessment?.leads}/><PSAssessment value={result.assessment}/><CaseActivity key={`activity-${result.id}`} caseId={result.id}/><ReviewDecision key={result.id} caseId={result.id}/></>}
            {tab === 'evidence' && <div className="evidence-layout"><Section title="Detection evidence" meta={<Badge>{result.findings.length} findings</Badge>}>{result.findings.length ? result.findings.map((f, i) => <div className="finding" key={i}><AlertTriangle size={17}/><div><strong>{f.title}</strong><p>{f.detail}</p><small>{f.group}</small></div><span className="points">+{f.points}</span></div>) : <Empty icon={ShieldCheck}>No configured detection rules triggered. This is not proof that the email is safe.</Empty>}<div className="group-caps">Group totals after caps: {Object.entries(result.groups).map(([key, value]) => `${key} ${value}`).join(' · ')}</div></Section><div><Authentication values={result.authentication}/><DomainIntelligence value={result.domain_intelligence}/><Section title="Evidence integrity"><CheckpointTools/><div className="hash mono">{result.sha256}</div><button className="secondary" onClick={verify}><Fingerprint size={16}/> Verify stored evidence</button>{verification && <div className={`verification ${verification.valid ? 'good' : 'danger'}`}><strong>{verification.valid ? 'Integrity checks passed' : 'Integrity check failed'}</strong><p>{verification.detail}</p></div>}</Section></div></div>}
            {tab === 'relay' && <><RelayMap result={result}/><Section title="Header-reported relay sequence">{result.hops.length ? result.hops.map(h => <div className="hop" key={h.index}><span>{String(h.index).padStart(2, '0')}</span><div><strong className="mono">{h.ips.join(' / ') || 'No IP in this header'}</strong><p className="mono">{h.raw}</p><Badge color="warn">{h.trust}</Badge></div></div>) : <Empty icon={Globe2}>No Received headers supplied.</Empty>}</Section></>}
            {tab === 'urls' && <Section title="Extracted links" meta={<Badge>Local reputation matching</Badge>}>{result.urls.length ? result.urls.map((u, i) => <div className="url-row" key={i}><Link2 size={18}/><div><strong className="mono">{u.url}</strong><p>{u.domain} · {u.protocol} · {u.length} characters</p><div className="tags">{u.reasons.length ? u.reasons.map(r => <Badge key={r} color="warn">{r}</Badge>) : <Badge>No structural flags</Badge>}</div><UrlReputation value={u.reputation}/><LandingInspect key={`${result.id}-${i}`} caseId={result.id} url={u.url}/></div><span className={`url-score ${tone(u.score)}`} title="URL structural score">{u.score}</span></div>) : <Empty icon={Link2}>No HTTP or HTTPS links found.</Empty>}</Section>}
            {tab === 'source' && <><Section title="Attachment inventory">{result.attachments.length ? result.attachments.map((a, i) => <div className="attachment" key={i}><FileText size={20}/><div><strong>{a.name}</strong><p>{a.type} · {a.size} bytes</p><small className="mono">{a.sha256}</small>{a.size > 0 && <SandboxSubmit key={`${result.id}-${a.sha256}`} caseId={result.id} sha256={a.sha256}/>}</div><Badge color={a.warning ? 'warn' : 'neutral'}>{a.warning ? 'Review extension' : 'Not malware-scanned'}</Badge></div>) : <Empty icon={FileText}>No attachments found.</Empty>}</Section><Section title="Decoded message"><pre>{result.body || 'No text body found.'}</pre></Section>{result.ocr && <Section title="Text read from images (OCR)" meta={<Badge>{result.ocr.engine?.available ? 'English/Latin script only' : 'OCR unavailable'}</Badge>}>{result.ocr.text ? <pre>{result.ocr.text}</pre> : <Empty icon={FileText}>{result.ocr.engine?.available ? 'No readable text was found in the images.' : result.ocr.engine?.detail}</Empty>}<p className="caveat">OCR is an aid, not proof: it can miss or misread text, and it does not read Indic scripts.</p></Section>}<Section title="Email headers">{result.headers.map((h, i) => <div className="header-row" key={i}><strong>{h.name}</strong><span className="mono">{h.value}</span></div>)}</Section></>}
            <details className="limitations"><summary>Scope & limitations</summary><ul>{result.limitations.map(l => <li key={l}>{l}</li>)}<li>{result.ml.detail}</li></ul></details>
          </>}
        </>}
        {view === 'cases' && <><div className="list-tools"><label className="search"><Search size={17}/><input aria-label="Search cases full text" placeholder="Search full text (subject, sender, IOCs, findings...)" value={query} onChange={e => setQuery(e.target.value)}/></label><Badge>{cases.length} investigation{cases.length === 1 ? '' : 's'}</Badge></div><div className="case-list">{cases.length ? cases.map(c => <div className="case-row" key={c.id}><span className={`case-score ${tone(c.score)}`}>{c.score}</span><button className="case-open" onClick={() => openCase(c.id)}><strong>{c.subject || '(no subject)'}</strong><small>{c.sender}</small></button><Badge>{c.sample ? 'Fixture' : 'Uploaded'}</Badge><button title="Delete case and original email" aria-label="Delete case and original email" onClick={() => remove(c.id)}><Trash2 size={17}/></button></div>) : <Empty>No matching investigations found.</Empty>}</div></>}
        {view === 'gmail' && <GmailAlerts openCase={openGmailCase}/>}
        {view === 'quarantine' && <Quarantine/>}
        {view === 'graph' && <>
          <div className="view-tabs" style={{ marginBottom: 20 }}>
            {[['entities', 'Cross-Case Entity Graph'], ['clusters', 'Campaign Clusters'], ['connections', 'Direct Case Links']].map(([key, name]) => (
              <button key={key} className={graphTab === key ? 'selected' : ''} onClick={() => setGraphTab(key)}>{name}</button>
            ))}
          </div>
          {graphTab === 'entities' && <EvidenceGraph openCase={openCase}/>}
          {graphTab === 'clusters' && <CampaignGroups openCase={openCase}/>}
          {graphTab === 'connections' && <>
            <div className="graph-stats"><Badge>{graph.nodes.length} emails</Badge><Badge color="good">{graphEdges.length} relationships</Badge><span>Direct case-to-case connections · analyst review required</span></div>
            {graph.nodes.length ? <><div className="graph"><svg viewBox="0 0 850 420" role="img" aria-label="Email relationship graph">{graphEdges.map((e, i) => { const pos = id => { const index = graph.nodes.findIndex(n => n.id === id); const angle = index * Math.PI * 2 / graph.nodes.length - Math.PI / 2; return [425 + Math.cos(angle) * 260, 210 + Math.sin(angle) * 135] }; const a = pos(e.source), b = pos(e.target); return <g key={i} onClick={() => setEdge(e)}><line x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} stroke={edge === e ? '#a3e635' : '#657b49'} strokeWidth="2"/><line x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} stroke="transparent" strokeWidth="18" className="clickable"/><title>{e.evidence.map(x => x.value).join(', ')}</title></g>})}{graph.nodes.map((n, i) => { const angle = i * Math.PI * 2 / graph.nodes.length - Math.PI / 2; const x = 425 + Math.cos(angle) * 260, y = 210 + Math.sin(angle) * 135; return <g key={n.id} className="clickable" tabIndex={0} role="button" aria-label={`Open case ${n.subject}`} onClick={() => openCase(n.id)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') openCase(n.id) }}><circle cx={x} cy={y} r="24" fill="#141a20" stroke={n.score >= 60 ? '#ef4444' : '#a3e635'} strokeWidth="2"/><text x={x} y={y + 5} textAnchor="middle" fill="#f1f5f9" fontSize="13">{n.score}</text><text x={x} y={y + 43} textAnchor="middle" fill="#c1c8d1" fontSize="11">{short(n.subject).slice(0, 30)}</text><title>{n.subject}</title></g> })}</svg></div><Section title="Relationship evidence">{graphEdges.length ? graphEdges.map((e, i) => <button className={`edge-row ${edge === e ? 'chosen' : ''}`} key={i} onClick={() => setEdge(e)}><Network size={18}/><span><strong>{short(graph.nodes.find(n => n.id === e.source)?.subject || 'Unknown')} ↔ {short(graph.nodes.find(n => n.id === e.target)?.subject || 'Unknown')}</strong>{e.evidence.map((v, j) => <small className="mono" key={j}>{v.type}: {v.value}</small>)}</span><ChevronRight size={18}/></button>) : <Empty icon={Network}>No shared distinctive indicators found.</Empty>}{edge && <div className="verification"><strong>{edge.assessment}</strong><p>A shared indicator supports investigation, not a confirmed campaign attribution.</p></div>}</Section></> : <Empty icon={Network}>Analyze emails to build their relationship graph.</Empty>}
          </>}
        </>}
        <footer><span><ShieldCheck size={14}/> AI-Powered Email Threat Detection</span><span>Evidence first. Attribution with uncertainty.</span></footer>
      </div>
    </main>
  </div>
}


export default function App() {
  const [state, setState] = useState({ status: 'loading', who: null, error: '' })
  const attempted = useRef(false)
  async function check() {
    try {
      const health = (await api.get('/health')).data
      if (!health.auth_required) { setState({ status: 'open', who: null, error: '' }); return }
      setState({ status: 'ready', who: (await api.get('/whoami')).data, error: '' })
    } catch (e) {
      if (e.response?.status === 401) setState({ status: 'login', who: null, error: attempted.current ? 'That token was not accepted.' : '' })
      else setState({ status: 'open', who: null, error: '' })
    }
  }
  useEffect(() => {
    const first = setTimeout(check, 0)
    // A 401 while signed in means the token stopped working (rotated or revoked). During sign-in, check() reports the failure itself.
    const onAuth = () => { roleToken.set(''); setState(prev => prev.status === 'ready' ? { status: 'login', who: null, error: 'Your session ended. Sign in again.' } : prev) }
    window.addEventListener('efp-auth-required', onAuth)
    return () => { clearTimeout(first); window.removeEventListener('efp-auth-required', onAuth) }
  }, [])
  if (state.status === 'loading') return <main className="auth-shell"><LoaderCircle className="spin" size={22} aria-label="Loading"/></main>
  if (state.status === 'login') return <AuthGate error={state.error} onSubmit={async token => { attempted.current = true; roleToken.set(token); setState({ status: 'loading', who: null, error: '' }); await check() }}/>
  return <Workspace key={state.who?.actor || 'open'} who={state.who} onSignOut={() => { attempted.current = false; roleToken.set(''); setState({ status: 'login', who: null, error: '' }) }}/>
}
