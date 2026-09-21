# SIH26106 - Judge-Readable PPT Copy Pack

**Team:** Cache-Me-Maybe
**Product name:** **PRAHARI**
**Tagline:** **Detect. Attribute. Prove.**
**PS:** AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform
**Theme:** Blockchain & Cybersecurity | **Category:** Software

Use this file as **slide-ready copy**, not a research dump. Keep lines short, build diagrams around the phrases, and move caveats into speaker notes where the slide is crowded.

---

## Slide 1 - Title

**AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform**

**PRAHARI**
*The sentinel for every inbox.*

**Team:** Cache-Me-Maybe
**PS ID:** SIH26106
**Theme:** Blockchain & Cybersecurity
**Category:** Software
**Team ID:** [fill after SIH portal assignment]

Visual: clean title slide, product name visible, no extra clutter.

---

## Slide 2 - Proposed Solution

### Hook
**One compromised employee inbox can become a national-scale breach.**

Bank of Baroda, July 2026: public reports described a nearly **1 TB** data leak claim after an employee email-account compromise; the bank said core banking was unaffected.

CERT-In handled **29,44,248 cyber incidents in 2025**.

### Solution
**PRAHARI turns a suspicious email into a forensic case in seconds.**

It detects phishing, authenticates the sender, traces relay infrastructure, scores attribution confidence, and preserves tamper-evident evidence.

### What It Does
- **AI phishing detection:** team-trained BERT, **99.32% held-out accuracy**
- **Sender authentication:** SPF, DKIM, DMARC, ARC
- **Relay geo-map:** hop-by-hop infrastructure tracing
- **URL + attachment intelligence:** PhishTank, VirusTotal, AbuseIPDB, Tor signals
- **Spoofing + BEC signals:** mismatches, deceptive domains, suspicious language
- **Campaign correlation:** links related emails by shared indicators
- **Court-supporting evidence:** SHA-256 chain + Bitcoin timestamp anchor
- **SOC-ready output:** PDF, JSON, CSV, CEF, Splunk
- **DPDP-conscious exports:** masks Aadhaar, PAN, UPI and mobile numbers

### Uniqueness Box
**Most tools block email. PRAHARI investigates it.**

**Most AI models read the email. PRAHARI also defends the AI.**

Novelty:
- **AI-manipulation detection:** hidden prompt-injection and tokenizer-evasion checks
- **Authentication-aware AI:** verified senders are not punished by content alone
- **Honest attribution:** infrastructure + confidence, not fake attacker identity
- **Tamper-evident proof:** every case is hash-chained and timestampable

Speaker note: Say "employee email-account compromise," not "confirmed phishing cause." Do not claim human attacker geolocation.

---

## Slide 3 - Technical Approach

### Hero Pipeline
**Email in -> Evidence out**

`Upload / Paste / Gmail`
-> `Parse headers + body + attachments`
-> `SPF / DKIM / DMARC / ARC`
-> `BERT + AI-manipulation scan`
-> `URL + attachment reputation`
-> `Relay map + IP intelligence`
-> `Attribution Confidence Engine`
-> `Campaign correlation`
-> `Hash-chained evidence store`
-> `Report + SIEM export`

### Real-Time Ingestion
- **Gmail Pub/Sub:** automatic inbox analysis
- **Gmail Guard extension:** live risk banner inside Gmail
- **Same backend pipeline:** upload, paste, Gmail and extension all converge

### Tech Stack Strip
**Python + FastAPI** | **React + Vite** | **BERT / PyTorch** | **SPF/DKIM/DMARC/ARC**
**OpenTimestamps + SHA-256** | **Splunk HEC** | **PhishTank / VirusTotal / AbuseIPDB**

### Proof It Runs
- **419 backend tests passing**
- Frontend build/lint clean
- Team-trained phishing model
- Gmail Guard live-verified
- Splunk HEC verified

Visual: make the pipeline the main graphic. Keep technology as a thin logo strip.

---

## Slide 4 - Feasibility & Viability

### Feasibility
**Working prototype today, not a concept.**

- Runs locally end-to-end
- 419 backend tests green
- Open-source, proven stack
- External APIs are optional
- Graceful fallback when enrichment is unavailable
- Modular pipeline: each detector can be swapped or upgraded

### Challenges -> Mitigation

| Challenge | Our Strategy |
|---|---|
| VPN/Tor/proxy hides source | Report infrastructure honestly; never invent a person |
| ML false positives | Fuse model output with email authentication |
| API latency/outage | Timeouts, cache, safe `unavailable` states |
| Evidence tampering | SHA-256 chain + Bitcoin timestamp anchor |
| Real-world model drift | Analyst review + retraining-ready dataset pipeline |

### Viability
**Built for real SOC workflows.**

- Works for banks, PSUs, cybercrime cells and enterprise SOCs
- Uses existing tools: Gmail, Splunk, PDF/JSON/CSV exports
- Low-cost core detection; paid APIs only improve enrichment
- Scales from one mailbox to a shared SOC service

Phrase to use: **"Truthful forensics beats fake certainty."**

---

## Slide 5 - Impact & Benefits

### Impact Numbers
**Seconds, not guesswork.**

- **~50 ms local median analysis**
- **~0.6 s with live enrichment**
- **8+ evidence layers in one workflow**
- **99.32% held-out ML accuracy**
- **0.49% held-out false-positive rate**

### Who Benefits
- **SOC analysts:** faster triage, fewer tools
- **Cybercrime units:** structured forensic package
- **Banks and PSUs:** early phishing/BEC detection
- **Email admins:** authentication and spoofing visibility
- **Compliance teams:** safer, masked evidence exports

### Benefits
- **Operational:** one email becomes a complete case
- **Economic:** reduces BEC and credential-theft exposure
- **Legal:** preserves evidence with tamper detection
- **National:** affordable email forensics for Indian institutions
- **Trust:** explains uncertainty instead of hiding it

Closing line:

**PRAHARI: from inbox alert to defensible evidence.**

Speaker note: 99.32% is a held-out test-split result, not a real-world guarantee.

---

## Slide 6 - Research & References

Use compact references with QR/link row.

1. **FBI IC3 2024 Internet Crime Report** - cybercrime and BEC loss impact
   https://www.ic3.gov
2. **FBI IC3 BEC PSA** - US $55.5B exposed BEC losses, Oct 2013-Dec 2023
   https://www.ic3.gov
3. **CERT-In / PIB 2025 cyber-incident data** - 29,44,248 incidents handled
   https://www.pib.gov.in
4. **Bank of Baroda July 2026 incident reports** - employee email-account compromise and public data-leak claims
   Sources: Indian Express / Economic Times / bank disclosure
5. **Email authentication standards** - SPF, DKIM, DMARC, ARC
   RFC 7208, RFC 6376, RFC 9989, RFC 8617
6. **BERT** - Devlin et al., 2019
   https://aclanthology.org/N19-1423.pdf
7. **OpenTimestamps** - Bitcoin-anchored trusted timestamping
   https://opentimestamps.org
8. **BSA 2023, Section 63** - Indian electronic-evidence certificate support

Link row:

**Prototype | Demo Video | GitHub**

Only add **Live Web App** if actually deployed.

---

## Must-Say Guardrails

Keep these in speaker notes or Q&A answers.

- We locate **email relay infrastructure**, not a human attacker.
- The ML score is **held-out test performance**, not a universal guarantee.
- Blockchain anchoring **supports** a BSA Section 63 certificate; it does not issue one.
- Gmail Guard is live-verified but depends on Gmail's private frontend markup.
- DPDP masking is best-effort protection, not certified DLP.
- VirusTotal/AbuseIPDB are optional enrichments; the core pipeline still works without them.

---

## Visuals To Build

1. **Hero pipeline:** Email in -> forensic case out
2. **Seven evidence layers:** auth, ML, URL, attachment, relay, reputation, evidence
3. **Risk vs solution:** compromised inbox vs PRAHARI case file
4. **Hash-chain proof:** one edited block breaks the chain
5. **Live product screenshot:** Gmail Guard + dashboard

Best slide energy:

**Don't show a tool. Show an investigation.**
