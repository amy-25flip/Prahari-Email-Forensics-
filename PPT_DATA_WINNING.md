# SIH26106 - Judge-Readable PPT Copy Pack

**Team:** Cache-Me-Maybe
**Product name:** **PRAHARI**
**Tagline:** **Detect. Attribute. Prove.**
**PS:** AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform
**Theme:** Blockchain & Cybersecurity | **Category:** Software

Use Slides 1-6 below as **slide-ready copy**, not a research dump. Keep lines short, build diagrams around the phrases, and move caveats into speaker notes where the slide is crowded. The **Complete Feature Status Checklist** further down is a reference list for the team (what's built vs. planned) - not meant to go on a slide verbatim.

**Two production tips (free, apply everywhere):**
- Put a tiny **`Built` / `Roadmap`** legend on any slide that mixes both, so nothing reads as vague to a judge.
- Where possible, narrate the whole deck around **one suspicious email's journey** (arrives -> analyzed -> infrastructure mapped -> evidence sealed -> redacted report exported) instead of listing modules - it's more memorable and doubles as a natural demo script.

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

**AI that detects attacks on AI.** Most phishing tools protect humans from emails; PRAHARI also protects its own automated analyst from hidden instructions and tokenizer tricks designed to fool it.

Novelty:
- **AI-manipulation detection:** hidden prompt-injection and tokenizer-evasion checks
- **Verified-sender mercy:** a scary-looking but DKIM/DMARC-aligned legitimate email is not punished by content alone - careful, not alarmist
- **Truthful attribution as innovation:** infrastructure + confidence, never a fake attacker identity - more forensic than flashy
- **Tamper-evident proof:** every case is hash-chained and timestampable

Speaker note: Say "employee email-account compromise," not "confirmed phishing cause." Do not claim human attacker geolocation. Demo order that lands best: open with the Gmail Guard banner (where the user already works), then the dashboard case, then the export - not backend internals first.

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
- **419 backend tests passing** - covering Gmail race conditions, dead-letter retries, prompt injection, PII masking, OpenTimestamps, and every fallback state, not just the happy path
- Frontend build/lint clean
- Team-trained phishing model
- Gmail Guard live-verified
- Splunk HEC verified

**Engineering depth, not just feature count:** Gmail Pub/Sub ingestion handles real production weirdness - OIDC-authenticated push, Gmail's own indexing-lag races, a dead-letter retry queue with bounded attempts. That's proof the team handled production conditions, not just toy uploads.

**Complexity with brakes:** the system is complex enough to fuse 7 signal groups, but disciplined enough to cap scores and label uncertainty rather than force a confident-sounding wrong answer.

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
| Setup burden (Gmail Pub/Sub, Splunk HEC) | Neither is zero-config - said honestly, not hidden; core detection needs neither to work |

### Viability
**Built for real SOC workflows.**

- **No new inbox habit required:** upload `.eml`, paste raw source, Gmail Pub/Sub, or the Gmail Guard banner - analysts keep working where they already work
- Uses existing tools: Gmail, Splunk, PDF/JSON/CSV exports
- Low-cost core detection; paid APIs only improve enrichment
- Scales from one mailbox to a shared SOC service

### Sustainability
- **"Pay for enrichment, not for survival."** The core pipeline runs with zero paid APIs; VirusTotal/AbuseIPDB only deepen enrichment - useful for institutions with limited budgets.
- **Trust without a private notary.** OpenTimestamps' Bitcoin anchoring gives independent verification without the team having to build or fund its own evidence authority.
- Core local inference avoids sending email bodies to a model API; optional enrichment sends only selected indicators/hashes, never full content.
- Social: brings enterprise-grade email forensics to teams and institutions without big security budgets.

### Planned Enhancements (Next Phase - Research-Informed)
*Say "planned" or "roadmap" - never "built" or "live." Grounded in 5 papers reviewed Sept 2026 (SAHF-PD, PhishTrace, PhishLumos, PAM 2025, BEC Systematic Review - full citations on Slide 6).*

- QR-code / image / PDF-embedded phishing detection (OCR + QR decode)
- Conversation-aware BEC detection (payment-detail changes, reply-to swaps, thread anomalies)
- Selective landing-page inspection for unresolved links (isolated worker, no credentials used)
- Calibrated probability scores (Brier score, reliability diagrams) + formal evidence graph
- Learned multimodal fusion model, replacing today's rule-based score caps

Phrase to use: **"Truthful forensics beats fake certainty."**

---

## Slide 5 - Impact & Benefits

### Impact Numbers
**Seconds, not guesswork.**

- **~50 ms local median analysis**
- **~0.6 s with live enrichment**
- **7 scored evidence groups**, plus enrichment/attribution/campaign layers, converging into one verdict
- **99.32% held-out ML accuracy**
- **0.49% held-out false-positive rate**

### Reframe: not a phishing filter - a national email evidence layer
The real impact isn't blocking one email; it's turning suspicious emails across banks, PSUs, colleges and cybercrime cells into **comparable, exportable forensic cases.** DPDP-conscious masking with Aadhaar Verhoeff validation is a rare, India-specific detail that signals this was built for Indian institutions, not adapted from a generic SOC tool.

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

**Roadmap research (reviewed Sept 2026, informs Slide 4's Planned Enhancements):**

9. **SAHF-PD** - Yuan et al., "LLM-Based Multimodal Feature Extraction and Hierarchical Fusion for Phishing Detection," Electronics 2026, 15(2):368. https://doi.org/10.3390/electronics15020368
10. **PhishTrace review** - Laleb, Le & Nguyen, "Digital Forensics and Phishing Defense: A Literature Review and Gap Analysis," J. Cybersecur. Priv. 2026, 6:116.
11. **PhishLumos** - Chiba, Nakano & Koide, "PhishLumos: From a Single URL to Campaign-Level Phishing Mitigation," IEEE ICC 2026 / IEEE Access 2026. https://doi.org/10.1109/ACCESS.2026.3696597
12. **PAM 2025 Enterprise Phishing Networks** - Luo et al., "Characterizing the Networks Sending Enterprise Phishing Emails" (over one-third of observed phishing originated from reputable networks including Amazon and Microsoft).
13. **BEC Systematic Review** - Almutairi, Kang & Alhashimy, "Business Email Compromise: A Systematic Review," Computers & Security, 2025 (30 peer-reviewed studies, 2007-2024).

Link row:

**Prototype | Demo Video | GitHub**

Only add **Live Web App** if actually deployed.

---

## Complete Feature Status Checklist (Master Reference)

**This is a reference list, not slide copy.** Pull only 4-6 items per slide (see Slide 2/3/4 above). Two tiers, never mix them on a slide or in a demo:
- **✅ Built & verified today** - real, working, tested code. Safe to say "built," "works," "live."
- **🔜 Planned (research-informed roadmap)** - not yet built. Say "planned" or "next phase." If a judge asks to see it, say so honestly - that honesty is this project's credibility.

### ✅ Built & Verified Today

**Detection**
- ✅ Team-trained BERT phishing classifier - 99.32% accuracy, 0.49% false-positive rate, 33,527 held-out test emails
- ✅ AI-manipulation / prompt-injection detection (hidden CSS, zero-width Unicode) - 51 tests
- ✅ Adversarial NLP-evasion detector (homoglyph + zero-width raw-vs-normalized probability delta)
- ✅ Authentication-aware ML fusion - a content-only signal from a cryptographically verified sender no longer inflates the score
- ✅ Social-engineering language rules (credential pressure, payment diversion, verification avoidance)

**Authentication & Origin**
- ✅ Full SPF, DKIM, DMARC (RFC 9989), ARC (RFC 8617) verification
- ✅ Trust-boundary separation: receiver-attested "earliest reliable node" kept distinct from the header-reported chain
- ✅ Every relay hop explicitly labeled "receiver trust not established" unless attested

**Infrastructure & Reputation**
- ✅ Relay geolocation (IP/ISP/ASN, source + timestamp recorded per lookup)
- ✅ Tor-exit-node matching
- ✅ AbuseIPDB hosting/proxy/VPN classification
- ✅ Domain/DNS/RDAP intelligence
- ✅ URL structural analysis + PhishTank matching
- ✅ VirusTotal attachment-hash reputation + opt-in sandbox upload (parallelized lookups)
- ✅ Static attachment inspection - executable signatures, PDF action markers, Office macros, encryption markers

**Attribution & Evidence**
- ✅ Attribution Confidence Engine - transparent 0-100 weighted score, hard-capped low when origin is undetermined
- ✅ Campaign correlation - shared indicators + character-shingle Jaccard fuzzy body-similarity
- ✅ Distinct triage priority states (urgent / review / incomplete / routine) - separate from the uncalibrated evidence score
- ✅ SHA-256 hash-chained tamper-evident event log with an independent chain-integrity verify check
- ✅ Bitcoin-blockchain anchoring via OpenTimestamps
- ✅ Optional Fernet at-rest field encryption

**Compliance & Privacy**
- ✅ DPDP-conscious export masking - Aadhaar (Verhoeff-checksum validated), PAN, UPI, mobile numbers, auto-masked in every export
- ✅ Redacted export mode - content/identity withheld, case ID and hash retained

**Real-Time Ingestion**
- ✅ Gmail Pub/Sub server-side push ingestion - live-verified on a real account
- ✅ "Gmail Guard" browser extension - live-verified end-to-end against real Gmail, in-page risk banner

**Reporting & SOC Integration**
- ✅ PDF / JSON / CSV / CEF exports
- ✅ Live-verified Splunk HEC delivery
- ✅ Case list, single-case view, campaign/connection view, review-and-acknowledge workflow

**Engineering Quality**
- ✅ 419 automated backend tests, frontend build/lint clean
- ✅ Multi-round independent AI code review on every change

### 🔜 Planned - Research-Informed Roadmap (Not Yet Built)

*Grounded in 5 papers reviewed Sept 2026: SAHF-PD (Electronics 2026), PhishTrace review (J. Cybersecur. Priv. 2026), PhishLumos (IEEE Access 2026), PAM 2025 Enterprise Phishing Networks, BEC Systematic Review (Computers & Security 2025). Full citations on Slide 6.*

**Highest-priority next additions**
- 🔜 QR-code / image / PDF-embedded phishing detection (OCR + QR decode) - closes today's text-only blind spot
- 🔜 Conversation-aware BEC detection - payment-detail changes, reply-to swaps, thread-history anomalies
- 🔜 Selective landing-page inspection for unresolved links - isolated worker, screenshot + credential-form detection, no credentials used
- 🔜 Formal evidence graph across campaigns - typed nodes/edges (email/domain/URL/IP/certificate/hash) with per-link confidence
- 🔜 Learned multimodal fusion model - replacing today's fixed rule-based score caps

**Foundation hardening**
- 🔜 Independent, near-duplicate-safe evaluation suite - our own training script already flags that exact-dedup alone doesn't catch template-level near-duplicates; next step is campaign/source-held-out benchmarks
- 🔜 Calibrated probability scores (Brier score, reliability diagrams) - today's states are distinct, but the score itself stays uncalibrated
- 🔜 Evidence-linked explanations - stable finding IDs that reference exact source location
- 🔜 Network-behavior-over-time tracking - our own first/last-seen history, not just a single external lookup

**Additional roadmap items**
- 🔜 India-specific curated brand/UPI reference set for impersonation detection (the similarity-check mechanism already exists; the curated list doesn't ship by default)
- 🔜 Multilingual / code-mixed detection (Hindi + regional languages)
- 🔜 Broader adversarial-robustness testing (paraphrase, padding, truncation attacks - beyond today's homoglyph/zero-width coverage)
- 🔜 Full-text case search, analyst notes, ownership/assignment
- 🔜 Async job pipeline for slow enrichment (OCR, page-fetch) with retries and resilience
- 🔜 Role-based access control for multi-analyst teams
- 🔜 Analyst feedback capture + drift monitoring + controlled retraining

**Longer-horizon (only if justified by real constraints)**
- 🔜 Federated learning across institutions - if multiple orgs have data they can't pool
- 🔜 Graph neural networks over the campaign graph - once a large, accurately labeled graph exists
- 🔜 Evidence-grounded investigation chat assistant

---

## Must-Say Guardrails

Keep these in speaker notes or Q&A answers.

- We locate **email relay infrastructure**, not a human attacker.
- The ML score is **held-out test performance**, not a universal guarantee.
- Blockchain anchoring **supports** a BSA Section 63 certificate; it does not issue one. Bitcoin confirmation takes **hours, not seconds** - say so if asked.
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

**Favorite idea if there's time to build it: an "Evasion Lab" demo panel.** Show the raw phishing probability next to the homoglyph/zero-width-normalized probability side by side for one crafted email, with a plain verdict: "model resisted" or "model fooled." The line that lands: *"Even when the AI isn't fooled, the attempt itself becomes evidence."* Novel, honest, visual, and hard to forget - `result['adversarial']` already computes this data, so it's a UI panel, not new backend logic.

Best slide energy:

**Don't show a tool. Show an investigation.**
