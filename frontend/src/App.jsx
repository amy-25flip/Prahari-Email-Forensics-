import { useState } from "react"
import axios from "axios"

const API = "http://localhost:8000"

export default function App() {
  const [email, setEmail] = useState("")
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState("ready")

  async function analyze() {
    if (!email.trim()) return
    setLoading(true)
    setResult(null)
    setStatus("analyzing...")
    try {
      const res = await axios.post(`${API}/analyze`, { email })
      setResult(res.data)
      setStatus("complete")
    } catch (e) {
      setStatus("error — check backend is running")
    }
    setLoading(false)
  }

  const score = result?.fraud_score || 0
  const riskColor = score >= 60 ? "#FF3B3B" : score >= 30 ? "#F59E0B" : "#10B981"
  const riskLabel = score >= 60 ? "High Risk" : score >= 30 ? "Medium Risk" : "Low Risk"
  const riskDesc = score >= 60
    ? "Multiple fraud indicators detected. Quarantine before any user interaction."
    : score >= 30
    ? "Anomalies present. Manual review recommended."
    : "No significant threat indicators found."

  return (
    <div style={s.root}>
      <div style={s.page}>
        <div style={s.header}>
          <div style={s.logo}>
            <span style={s.logoMain}>EFP</span>
            <span style={s.logoDivider}> / </span>
            <span style={s.logoSub}>Email Forensic Platform</span>
          </div>
          <span style={s.statusBadge}>{status}</span>
        </div>

        <div style={s.inputSection}>
          <div style={s.fieldLabel}>Raw Email Source</div>
          <textarea
            style={s.textarea}
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="Paste complete raw email with headers..."
            spellCheck={false}
          />
          <button
            style={{ ...s.btn, opacity: loading ? 0.5 : 1 }}
            onClick={analyze}
            disabled={loading}
          >
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </div>

        {result && <div style={s.divider} />}

        {result && (
          <div>
            <div style={s.scoreBlock}>
              <div style={{ ...s.scoreNum, color: riskColor }}>{score}</div>
              <div style={s.scoreMeta}>
                <div style={{ ...s.scoreVerdict, color: riskColor }}>{riskLabel}</div>
                <div style={s.scoreDesc}>{riskDesc}</div>
              </div>
            </div>

            <div style={s.divider} />

            <Section title="ML Classification">
              <Row k="Method" v={result.ml_classification?.method || "—"} />
              <Row k="Result" v={
                <Pill
                  text={result.ml_classification?.is_phishing ? "Phishing" : "Legitimate"}
                  color={result.ml_classification?.is_phishing ? "#FF3B3B" : "#10B981"}
                />
              } />
              <Row k="Confidence" v={(result.ml_classification?.confidence ?? "—") + (result.ml_classification?.confidence ? "%" : "")} />
            </Section>

            <Section title="Spoofing Signals">
              {(result.spoof_signals || []).length === 0
                ? <Muted>No spoofing signals detected</Muted>
                : (result.spoof_signals || []).map((sig, i) => (
                  <div key={i} style={sigStyle}>
                    <div style={sigBar} />{sig}
                  </div>
                ))
              }
            </Section>

            <Section title="Email Headers">
              <Row k="From" v={result.headers?.from} mono />
              <Row k="Return-Path" v={result.headers?.return_path} mono />
              <Row k="Reply-To" v={result.headers?.reply_to || "Not set"} mono />
              <Row k="Subject" v={result.headers?.subject} />
              <Row k="Relay Hops" v={(result.headers?.received_chain?.length || 0) + " hops detected"} />
            </Section>

            <Section title="Authentication">
              <Row k="Domain" v={result.authentication?.domain || "—"} />
              <Row k="SPF" v={<Pill text={result.authentication?.spf_valid ? "pass" : "fail"} color={result.authentication?.spf_valid ? "#10B981" : "#FF3B3B"} />} />
              <Row k="DMARC" v={<Pill text={result.authentication?.dmarc_valid ? "pass" : "fail"} color={result.authentication?.dmarc_valid ? "#10B981" : "#FF3B3B"} />} />
              <Row k="SPF Record" v={result.authentication?.spf_record || "None found"} mono />
              <Row k="DMARC Policy" v={result.authentication?.dmarc_policy || "None found"} />
            </Section>

            <Section title="DKIM">
              <Row k="Signature" v={
                <Pill
                  text={result.dkim?.verification?.status || "unknown"}
                  color={result.dkim?.verification?.status === "pass" ? "#10B981" : result.dkim?.verification?.status === "fail" ? "#FF3B3B" : "#F59E0B"}
                />
              } />
              <Row k="Detail" v={result.dkim?.verification?.detail || "—"} />
              <Row k="Domain" v={result.dkim?.header_info?.found ? result.dkim.header_info.domain : "Not found"} mono />
              <Row k="Algorithm" v={result.dkim?.header_info?.found ? result.dkim.header_info.algorithm : "—"} />
            </Section>

            <Section title="Relay Path">
              {(result.ips || []).length === 0
                ? <Muted>No public IPs found</Muted>
                : (result.ips || []).map((g, i) => (
                  <div key={i} style={s.hop}>
                    <div style={s.hopIdx}>{String(i+1).padStart(2,"0")}</div>
                    <div style={{flex:1}}>
                      <div style={s.hopIP}>{g.ip}</div>
                      <div style={s.hopGeo}>{[g.city,g.country].filter(Boolean).join(", ")||"Unknown"}</div>
                      <div style={s.hopTags}>
                        {g.isp && <Tag text={g.isp} />}
                        {g.proxy && <Tag text="Proxy" danger />}
                        {g.hosting && <Tag text="Hosting" warn />}
                      </div>
                    </div>
                  </div>
                ))
              }
            </Section>

            <Section title="URL Analysis">
              {(result.url_analysis?.urls || []).length === 0
                ? <Muted>No URLs found</Muted>
                : <>
                  <div style={s.urlSummary}>
                    {result.url_analysis.count} URL{result.url_analysis.count !== 1 ? "s" : ""} found — <span style={{color: result.url_analysis.suspicious_count > 0 ? "#FF3B3B" : "#10B981"}}>{result.url_analysis.suspicious_count} suspicious</span>
                  </div>
                  {(result.url_analysis.urls||[]).map((u,i) => (
                    <div key={i} style={s.urlItem}>
                      <div style={s.urlText}>{u.url}</div>
                      <div style={s.hopTags}>
                        {u.is_suspicious && u.flags?.length > 0
                          ? u.flags.map((f,j) => <Tag key={j} text={f} danger />)
                          : <span style={{fontSize:11,color:"#444"}}>no flags</span>
                        }
                      </div>
                    </div>
                  ))}
                </>
              }
            </Section>
          </div>
        )}

        <div style={s.footer}>EFP — Email Forensic Platform · SIH 2026</div>
      </div>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div style={s.section}>
      <div style={s.sectionTitle}>{title}</div>
      {children}
    </div>
  )
}

function Row({ k, v, mono }) {
  return (
    <div style={s.row}>
      <span style={s.rowKey}>{k}</span>
      <span style={mono ? s.rowValMono : s.rowVal}>{v || "—"}</span>
    </div>
  )
}

function Pill({ text, color }) {
  return (
    <span style={{
      display:"inline-flex", alignItems:"center",
      fontSize:10, fontWeight:700, letterSpacing:"0.06em",
      textTransform:"uppercase", padding:"3px 10px",
      borderRadius:3, background:color+"18", color,
      border:`1px solid ${color}33`,
    }}>{text}</span>
  )
}

function Tag({ text, danger, warn }) {
  const color = danger ? "#FF3B3B" : warn ? "#F59E0B" : "#555"
  const bg = danger ? "#FF3B3B15" : warn ? "#F59E0B15" : "#1a1a1a"
  return (
    <span style={{
      fontSize:10, fontWeight:500, padding:"2px 8px",
      borderRadius:3, background:bg, color,
      border:`1px solid ${color}33`,
    }}>{text}</span>
  )
}

function Muted({ children }) {
  return <div style={{fontSize:12.5, color:"#444", padding:"8px 0"}}>{children}</div>
}

const sigStyle = {
  display:"flex", alignItems:"center", gap:12,
  padding:"11px 0", borderBottom:"1px solid #1c1c1c",
  fontSize:12.5, color:"#FF3B3B",
}
const sigBar = { width:2, height:14, background:"#FF3B3B", borderRadius:1, flexShrink:0 }

const s = {
  root:{ background:"#080808", minHeight:"100vh", width:"100%" },
  page:{ maxWidth:740, margin:"0 auto", padding:"52px 32px 80px", fontFamily:"'Inter',sans-serif", color:"#E8E8E8" },
  header:{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:52, paddingBottom:20, borderBottom:"1px solid #1c1c1c" },
  logo:{ display:"flex", alignItems:"center" },
  logoMain:{ fontSize:13, fontWeight:700, letterSpacing:"0.1em", color:"#E8E8E8", textTransform:"uppercase" },
  logoDivider:{ fontSize:13, color:"#333", margin:"0 8px" },
  logoSub:{ fontSize:13, fontWeight:400, letterSpacing:"0.06em", color:"#444", textTransform:"uppercase" },
  statusBadge:{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:"#333", letterSpacing:"0.04em" },
  inputSection:{ marginBottom:36 },
  fieldLabel:{ fontSize:10, fontWeight:600, color:"#444", letterSpacing:"0.1em", textTransform:"uppercase", marginBottom:10 },
  textarea:{ width:"100%", height:168, fontFamily:"'JetBrains Mono',monospace", fontSize:11.5, lineHeight:1.8, color:"#C8C8C8", background:"#0e0e0e", border:"1px solid #1e1e1e", borderRadius:5, padding:"14px 16px", resize:"vertical", outline:"none" },
  btn:{ marginTop:12, background:"#E8E8E8", color:"#080808", border:"none", padding:"10px 28px", fontFamily:"'Inter',sans-serif", fontSize:12, fontWeight:700, letterSpacing:"0.05em", textTransform:"uppercase", borderRadius:4, cursor:"pointer" },
  divider:{ height:1, background:"#1a1a1a", margin:"36px 0" },
  scoreBlock:{ display:"flex", alignItems:"flex-end", gap:28, padding:"8px 0 32px" },
  scoreNum:{ fontSize:100, fontWeight:200, lineHeight:1, letterSpacing:"-0.06em", fontFamily:"'Inter',sans-serif", minWidth:140 },
  scoreMeta:{ paddingBottom:8 },
  scoreVerdict:{ fontSize:14, fontWeight:700, letterSpacing:"0.08em", textTransform:"uppercase", marginBottom:8 },
  scoreDesc:{ fontSize:12.5, color:"#555", lineHeight:1.6, maxWidth:360 },
  section:{ marginBottom:36 },
  sectionTitle:{ fontSize:10, fontWeight:600, letterSpacing:"0.1em", textTransform:"uppercase", color:"#444", marginBottom:14, paddingBottom:10, borderBottom:"1px solid #1a1a1a" },
  row:{ display:"flex", gap:20, padding:"10px 0", borderBottom:"1px solid #141414", alignItems:"flex-start" },
  rowKey:{ width:140, flexShrink:0, fontSize:11, color:"#444", paddingTop:1 },
  rowVal:{ fontSize:13, color:"#C8C8C8", lineHeight:1.5, flex:1 },
  rowValMono:{ fontFamily:"'JetBrains Mono',monospace", fontSize:11.5, color:"#C8C8C8", lineHeight:1.6, flex:1, wordBreak:"break-all" },
  hop:{ display:"flex", gap:18, padding:"14px 0", borderBottom:"1px solid #141414" },
  hopIdx:{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:"#333", width:22, flexShrink:0, paddingTop:3 },
  hopIP:{ fontFamily:"'JetBrains Mono',monospace", fontSize:13, color:"#C8C8C8", marginBottom:4, fontWeight:500 },
  hopGeo:{ fontSize:11.5, color:"#555", marginBottom:8 },
  hopTags:{ display:"flex", gap:6, flexWrap:"wrap" },
  urlSummary:{ fontSize:12, color:"#555", marginBottom:14, paddingBottom:10, borderBottom:"1px solid #141414" },
  urlItem:{ padding:"12px 0", borderBottom:"1px solid #141414" },
  urlText:{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:"#444", wordBreak:"break-all", marginBottom:8, lineHeight:1.6 },
  footer:{ marginTop:60, paddingTop:20, borderTop:"1px solid #141414", fontSize:11, color:"#2a2a2a", letterSpacing:"0.04em" },
}