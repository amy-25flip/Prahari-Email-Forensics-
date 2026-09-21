# SIH26106 — Prototype-Exact PPT Data Pack (build-the-winning-deck)

**Team:** Cache-Me-Maybe · **PS ID:** SIH26106 · **Theme:** Blockchain & Cybersecurity · **Category:** Software
**PS Title:** AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform

> Every number below is verified against the actual code/tests on 2026-09-20. Items marked **[VERIFY]** are external facts (news events, national statistics) you must confirm before presenting — judges can fact-check, and this project's whole edge is that it never overclaims.

---

## 0. Product name + tagline (winners name the product, not just the team)

Both 2025 winners named their product with a one-line value prop (VYOM-SAHAYAK "Helper in Space"; "Lanezy — Revolutionizing India's Roads"). Pick one:

- **PRAHARI** — *"The sentinel for every inbox."* (प्रहरी = sentinel/guardian; culturally resonant, judges respond to it)
- **MailTrace** — *"From inbox to origin — evidence you can defend."*
- **PhishForge Forensics** — *"Detect. Attribute. Prove."*

Recommended: **PRAHARI** (memorable, on-theme for a security guardian, Indian identity). Everything below is name-agnostic — drop your chosen name into the tagline slots.

---

## SLIDE 1 — TITLE (fill the official template fields, do not restyle)

- Problem Statement ID: **SIH26106**
- Title: **AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform**
- Theme: **Blockchain & Cybersecurity** · PS Category: **Software**
- Team ID: **[fill once assigned on sih.gov.in]** · Team Name: **Cache-Me-Maybe**
- **[VISUAL QA]** Open in real PowerPoint and confirm the title text box doesn't overrun the footer bar (pre-existing template geometry — never visually confirmed).

---

## SLIDE 2 — PROPOSED SOLUTION (the make-or-break slide)

Structure it like the winners: **Hook → Named Solution + tagline → What it does (bullets) → Uniqueness block.**

### The hook (one line + one number, top of slide) — VERIFIED 2026-09-21, cite sources on Slide 6
- **Bank of Baroda, July 2026 (real, citable):** the bank confirmed unauthorized access involving a compromised employee email account on **27 July 2026**; public reports described a dark-web listing claiming **nearly 1 TB** of customer/internal data, while the bank said core banking systems were not affected. **This is exactly the email-security gap our platform investigates early: suspicious inbox activity, forensic evidence, and defensible infrastructure tracing before a breach escalates.**
- **National scale (real, citable):** CERT-In handled **29,44,248 cyber-security incidents in 2025** (official PIB / CERT-In). Globally, the FBI's IC3 reports **nearly US $2.8 billion in BEC losses in 2024** and **US $55.5 billion** exposed BEC loss from Oct 2013–Dec 2023.

### One-line solution statement
> **PRAHARI** — an AI-powered platform that **detects** email threats, **authenticates** the sender, **traces** the relay path and infrastructure, **attributes** with a calibrated confidence score, and **preserves tamper-evident evidence that supports a BSA §63 legal certificate** — in one analyst workflow, in seconds.

### What it does (9 crisp capability bullets — one icon each)
1. **AI phishing detection** — team-trained BERT classifier, **99.32% accuracy** on 33,527 held-out emails.
2. **AI-manipulation + adversarial-evasion detection (novel)** — catches hidden instructions crafted to fool the *classifier/LLM analyst*, and re-scores a normalized copy when homoglyph/zero-width characters are present, catching tokenizer-evasion attacks (our fine-tuned model held ~100% under adversarial testing).
3. **Full email authentication** — SPF, DKIM, DMARC (RFC 9989) and ARC (RFC 8617).
4. **Relay & geo-intelligence** — reconstructs the `Received` hop chain and geolocates public IPs (reports *infrastructure*, never a human attacker).
5. **Attribution Confidence Engine** — transparent 0–100 score of how far the origin evidence can be trusted.
6. **URL + attachment reputation** — structural URL analysis, PhishTank, opt-in VirusTotal, AbuseIPDB IP reputation, Tor-exit detection.
7. **Campaign correlation** — links related emails via shared indicators + fuzzy body-similarity clustering.
8. **Tamper-evident evidence** — SHA-256 hash-chain + optional Fernet at-rest encryption, **anchored to the Bitcoin blockchain via OpenTimestamps** (Blockchain theme).
9. **DPDP-conscious export masking** — every exported report auto-masks **Aadhaar (Verhoeff-validated), PAN, UPI and mobile numbers** to reduce exposure under India's DPDP Act 2023; the original stays intact in the tamper-evident store. (Best-effort masking, not certified DLP.)

### Innovation & Uniqueness (the block judges score highest — give it its own box, 6 points)
1. **We defend the AI itself.** A dedicated detector for prompt-injection / AI-manipulation content (invisible CSS, zero-width Unicode), **plus an adversarial-evasion layer** that re-scores a normalized copy when homoglyph/zero-width characters are present and flags a large successful evasion (normalized phishing probability jumping past a configurable threshold, default 40 points) — most email tools only look at what the *human* sees. (Measured, not marketing: in adversarial testing our fine-tuned model held its verdict.)
2. **Authentication-aware AI.** The classifier's opinion is fused with cryptographic authentication, so a content-only phishing signal from a cryptographically verified sender no longer inflates the verdict — concrete bad links or failed auth still escalate. Sophistication that cuts false positives on legitimate mail.
3. **Evidence you can defend in court.** Blockchain-anchored, tamper-evident chain supporting a **BSA 2023 Section 63** electronic-evidence certificate.
4. **Honest attribution.** We report relay *infrastructure* and a *confidence* score, never a fabricated "this person did it" — exactly what a real investigator needs.
5. **Detection + investigation in one tool** — no stitching together five products.
6. **Built for Indian data protection.** Exports auto-mask Aadhaar/PAN/UPI/mobile to reduce exposure under **DPDP Act 2023**, and indicators ship to a Splunk SOC — bridging detection to India's regulatory workflow.

---

## SLIDE 3 — TECHNICAL APPROACH (make this DIAGRAM-FIRST — see Diagram #1 and #2)

Winners put almost no prose here. Use two visuals + a tech-stack strip. The *content* the diagrams must convey:

### Technologies (tech-stack strip with logos)
- **Backend:** Python, FastAPI · **Frontend:** React + Vite · **ML:** BERT (`bert-base-uncased`, fine-tuned), PyTorch/Transformers
- **Auth/forensics:** SPF/DKIM/DMARC/ARC, publicsuffixlist, dnspython · **Evidence:** SHA-256 hash-chain, Fernet at-rest encryption, OpenTimestamps (Bitcoin)
- **AI security:** prompt-injection DOM walker, homoglyph/zero-width adversarial-delta scorer · **Compliance:** DPDP Aadhaar/PAN/UPI masking (Verhoeff-validated)
- **Integrations:** Google Pub/Sub (Gmail), Splunk HEC (SIEM), PhishTank, VirusTotal, AbuseIPDB, ipwho.is/RDAP

### End-to-end pipeline (Diagram #1 — the hero visual)
`Email in (upload / paste / live Gmail)` → `Parse + authenticate (SPF/DKIM/DMARC/ARC)` → `BERT classify + AI-manipulation scan` → `URL + attachment reputation` → `Relay reconstruction + geolocation + Tor/VPN/abuse check` → `Attribution Confidence Engine` → `Campaign correlation` → `Tamper-evident hash-chained store (+ Bitcoin anchor)` → `Report / SIEM export (Splunk/CEF)`

### Real-time ingestion (call-out box)
- **Server-side:** Google Pub/Sub push → auto-analyze new inbox mail (live-tested on a real Gmail account).
- **Client-side "Gmail Guard" browser extension:** scans the open email in Gmail's UI and injects a risk banner — **live-verified end-to-end against real Gmail (2026-09-20).**

### Proof it's real (link row — winners always show these)
- **Working prototype (runs locally) · Demo video · GitHub** links here. *(Only add a "Live web app" URL if you actually deploy it — otherwise a demo video is the honest substitute, and it's what the 2025 winners showed.)*
- Backing claim: **419 automated backend tests passing**, multi-round independent AI code review.

---

## SLIDE 4 — FEASIBILITY & VIABILITY (3 columns: Feasibility · Challenges · Mitigation — Diagram #4)

### Feasibility
- **Working prototype today**, not a concept — full pipeline runs locally; 419 tests green; frontend builds clean.
- **Proven, open-source stack** (Python, FastAPI, React, BERT) — no exotic dependencies.
- **Low-cost:** core detection runs locally; all external enrichment is optional and free-tier, with graceful degradation.
- **Modular:** every enrichment module is independent and hot-swappable (documented `enabled/live` contract).

### Challenges & Risks → Strategies to overcome (pair them)
| Challenge | Strategy |
|---|---|
| Anonymization (VPN / proxy / Tor hides true source) | Flag anonymizing **infrastructure** honestly instead of guessing a person; Tor-exit + AbuseIPDB VPN/hosting detection |
| ML false positives on legit-but-phishy mail | **Authentication-aware fusion** — cryptographically verified senders aren't flagged on content alone |
| External API latency / outages | Explicit timeouts, in-memory TTL caching, byte-capped streaming, fallback to `unavailable` — never crashes |
| Evidence tampering / legal admissibility | **SHA-256 hash-chain + Bitcoin anchoring** — any edit breaks the chain, detectable instantly |
| Real-world generalization gap of the model | Honest "uncalibrated" labelling + analyst-review triage; deduped random split (exact normalized duplicates removed) |

### Viability / scalability (business angle — judges reward this)
- Deployable per-analyst, per-SOC, or as a shared service; scales from one intersection-equivalent (a single mailbox) to enterprise.
- Reuses existing infrastructure (Gmail, Splunk) — minimal new hardware.
- Target buyers: banks, PSUs, CERT-In-aligned SOCs, law-enforcement cybercrime units.

---

## SLIDE 5 — IMPACT & BENEFITS (big stat callouts + categorized benefits — Diagram #5)

### Headline stat callouts (3 big numbers, winner-style)
- **Sub-second analysis (measured):** a full multi-signal assessment runs in **~50 ms locally** and **~0.6 s with live enrichment** (measured median on this machine). Replaces the manual header-reading, auth-checking, and infrastructure cross-referencing an analyst otherwise does by hand — many minutes of work, folded into one automated pass. *(Say "sub-second, measured"; don't cite a specific manual-minutes figure you haven't benchmarked.)*
- **8+ signal classes** correlated in one workflow (auth, ML, AI-manipulation, URL, attachment, relay/geo, reputation, campaign).
- **99.32% model accuracy · 0.49% false-positive rate** on 33,527 held-out emails.

### Target beneficiaries
- **SOC analysts** (banks, enterprises, government) — faster, evidence-backed triage.
- **Cybercrime units / law enforcement** — structured, tamper-evident forensic packages.
- **Email admins & fraud/BEC teams** — early detection of impersonation and BEC.

### Benefits by category (icon grid)
- **Economic:** prevents credential theft and BEC losses; eliminates paid-API cost for core detection.
- **Social / national:** brings enterprise-grade email forensics to teams without big security budgets; supports CERT-In-aligned response.
- **Operational:** shrinks the window between phishing delivery and compromise; standardizes evidence for court.
- **Trust:** transparent, honest attribution — no overclaiming, defensible under scrutiny.

### Closing slogan (winners end on one)
> **PRAHARI — "Detect. Attribute. Prove."**

---

## SLIDE 6 — RESEARCH & REFERENCES (keep the real ones, add authority)

- **[1] FBI IC3 Internet Crime Report** — phishing/BEC/cyber-fraud impact. https://www.ic3.gov/AnnualReport/Reports/2023_IC3Report.pdf
- **[2] Email authentication (SPF/DKIM/DMARC)** — NIST / RFC 7208, RFC 6376, **RFC 9989 (DMARC)**, **RFC 8617 (ARC)**.
- **[3] BERT** — Devlin et al., 2019. https://aclanthology.org/N19-1423.pdf
- **[4] OpenTimestamps** — Bitcoin-anchored trusted timestamping. https://opentimestamps.org
- **[5] BSA 2023, Section 63** — India's electronic-evidence provision (in force since July 2024). *Frame precisely: our chain supports a Section 63 certificate; a human signatory issues it.*
- **[6] Bank of Baroda breach (July 2026)** — bank confirmed an employee email-account compromise; public reports described a nearly 1 TB dark-web data claim; bank said core banking systems were not affected. Sources: Indian Express / Economic Times / bank disclosure.
- **[7] FBI IC3 2024 Annual Report + IC3 BEC PSA** — BEC nearly US $2.8B in 2024; exposed BEC losses US $55.5B from Oct 2013-Dec 2023. https://www.ic3.gov
- **[8] CERT-In / PIB (2025)** — ~29.4 lakh (2.94M) cyber incidents handled in 2025, +44% YoY. https://www.pib.gov.in
- Link row: Prototype · Demo video · GitHub. *(Add a live URL only if deployed.)*

---

## Honesty guardrails (say these exactly — they are the project's credibility)
- Geo/relay locates **infrastructure, not a human attacker.**
- 99.32% is a **held-out test-split** figure, not a real-world guarantee.
- Blockchain anchoring **supports** a BSA Section 63 certificate; it does not **issue** one.
- Gmail Guard is **live-verified** but depends on Gmail's private markup (can break on Gmail changes).
- The adversarial-evasion detector flags *successful* evasions; in our testing the fine-tuned model resisted homoglyph and zero-width attacks (delta stayed ~0), so present it as **measured robustness + a defense-in-depth check**, not "we constantly catch live attacks."
- DPDP masking is best-effort regex + Aadhaar Verhoeff validation; it reduces exposure, it is not a certified DLP guarantee.

---

## FIVE DIAGRAMS / VISUALS TO BUILD (ranked by impact)

1. **End-to-end pipeline flow (HERO, Slide 3).** Left-to-right: ingest → authenticate → AI classify + manipulation scan → URL/attachment reputation → relay+geo+Tor → Attribution Confidence → campaign correlation → tamper-evident store (+Bitcoin) → SIEM/report. This one visual proves completeness.
2. **"One email, seven layers of evidence" fan/radar diagram (Slide 2 or 5).** A single email in the center, spokes to the 7–8 signal classes each with a mini verdict — shows multi-signal depth at a glance (Winner 1 used a radar-style visual).
3. **Risk-vs-Solution before/after (Slide 2).** Left: a phishing email slipping through (breach, ₹ loss). Right: PRAHARI catching + attributing + preserving evidence. Mirror Lanezy's "Risk vs Solution" split.
4. **Tamper-evident evidence chain (Slide 3 or 4).** Blocks linked by SHA-256 hashes, one block edited turns red and breaks the chain, final block anchored to a Bitcoin block — directly sells the Blockchain theme and legal-admissibility angle.
5. **Live in Gmail — annotated product screenshot (Slide 3 or 5).** Real screenshot of the Gmail Guard risk banner on an opened email + the web-app dashboard (evidence score, attribution, findings). Nothing beats "it actually runs" — winners showed working-prototype visuals.

Bonus if space: a small **confusion-matrix / accuracy infographic** (99.32% acc, 0.49% FP on 33,527 emails) to make the model claim concrete.
