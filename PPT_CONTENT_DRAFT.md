# Cache-Me-Maybe — SIH26106 Final Submission Deck Content
**Draft for teammate to build in PowerPoint. Every claim below is backed by something actually built and tested this project cycle, and has been fact-checked against the actual codebase — nothing here is aspirational, and every figure is stated with its real, honest caveat.**

---

## Pattern analysis (why this structure)

Confirmed against the **actual official SIH2026-IDEA-Presentation-Format.pptx** (downloaded from sih.gov.in, linked from Terna/Intellecta's committee guidelines, not just inferred from reference decks): the template has exactly **6 content slides** — Title → Idea/Proposed Solution → Technical Approach → Feasibility & Viability → Impact & Benefits → Research & References — plus a 7th "Important Instructions" slide the template itself says to delete before submitting. The committee guidelines are explicit and blunt: **"Strict 6-slide limit. Exceeding this or modifying the template risks outright disqualification, regardless of idea quality."** No 7th content slide, no reordering, no altered fonts/colors/layout.

What made the strongest reference deck (your own) work: a **concrete, named, recent real-world incident** as the opening hook, not a generic "phishing is a growing threat" statement. What this deck now has that a purely-theoretical one doesn't: **proof of validation against real-world data**, not just described capability — folded into the existing 6 slides below (Slide 2's Innovation/Uniqueness section and Slide 4's Strategies section) rather than given its own slide.

**Central positioning line** *(Codex's suggested framing for why this is more than a student ML demo — usable as a verbal opener or worked into Slide 2's intro if space allows)*:

> SIH26106 is not only a phishing classifier; it is an end-to-end email forensics workflow that detects suspicious mail — including mail crafted to manipulate the AI systems now screening it — explains the evidence, enriches infrastructure context, keeps a tamper-evident evidence trail, and exports cases into SOC tools.

**Questions judges are likely to ask — be ready, and the deck now preempts each explicitly:**
1. *"Can you really identify the attacker's location?"* — No, and the deck says so directly (Slide 2, "How It Addresses The Problem" — reframed as "geo-infrastructure intelligence"). We locate infrastructure and relay evidence, not the human attacker. Saying this yourselves, before being asked, reads as rigor, not weakness.
2. *"Does the deployed/demo version use the trained model?"* — The local demo does (configured via `MODEL_ID`); a fresh clone or the cloud deployment falls back to the public pretrained checkpoint unless that's explicitly configured. Know this cold if asked.
3. *"Is the 99.32% number real-world accuracy?"* — No, it's a deduplicated held-out test-split figure; real-world validation (the Gmail email) was a separate, single-sample demonstration, not a statistical claim. Say this before being asked.
4. *"Is blockchain actually used, or just the word?"* — Real: evidence hashes are submitted to OpenTimestamps for independent Bitcoin anchoring. Don't imply instant confirmation — anchoring completes on Bitcoin's own timescale (hours), and that's stated as a feature (tamper-evidence you don't have to trust us for), not a limitation to downplay.
5. *"Does real-time Gmail scanning actually work?"* — Say "when configured" once, not repeatedly across multiple bullets — stacking the same caveat reads as the feature being fragile rather than simply opt-in. The server-side Pub/Sub path has been live-tested against a real account (know the case ID if pressed: `e55fd74a10e47226`). The Gmail Guard browser extension (banner on Gmail's own page) is a separate, second implementation — built and unit-tested, but not yet run end-to-end against live Gmail. If asked to see it live, say so plainly rather than implying it's proven.
6. *"Isn't this just a phishing classifier with extra steps?"* — No — lead with the AI-manipulation detector here. It's the one piece that specifically targets attacks on automated screening itself (including this project's own model), not just the human reader, which is a materially different and newer threat class than standard phishing detection.
7. *"Is this legally admissible evidence / BSA Section 63 compliant?"* — Be precise: BSA 2023 Section 63 is India's current electronic-evidence provision (in force since July 2024), succeeding IEA Section 65B — don't call them the same thing if asked. The hash-chain + blockchain anchoring is the tamper-evidence backbone that *supports* a Section 63 certificate — the platform doesn't itself issue a signed legal certificate, since that requires a human in a responsible official position to attest to it. Overclaiming this to a judge who knows the law is a fast way to lose credibility on an otherwise strong point.

---

## SLIDE 1 — Title Page

*(Matches the official template's placeholders exactly — Team ID is a new required field per the actual template, not in the earlier draft: it's assigned once your team is registered on sih.gov.in, per the committee guidelines Section 3.A. Fill it in once you have it, don't leave the placeholder text in the submitted PDF.)*

> SMART INDIA HACKATHON 2026
> Problem Statement ID – SIH26106
> Problem Statement Title – AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
> Theme – Blockchain & Cybersecurity
> PS Category – Software
> Team ID – **[fill in once assigned on sih.gov.in]**
> Team Name (Registered on portal) – Cache-Me-Maybe

---

## SLIDE 2 — Idea / Proposed Solution

**Opening hook** *(Codex fact-check via web search found the "phishing email" cause is not actually confirmed by public reporting — sources describe "employee email-account compromise" with the method undisclosed/under investigation, and the bank stated core banking systems remained secure. Reworded to only claim what's actually reported.)*:

> Bank of Baroda, July 2026: public reports linked an employee email-account compromise to an alleged nearly 1 TB data exposure, while the bank said core banking systems remained secure. SIH26106 targets exactly this gap: detecting suspicious email activity early, preserving forensic evidence, and helping analysts investigate before an incident escalates.

**PROPOSED SOLUTION** *(Codex flagged the original as overloaded — 9+3+8 bullets across three sections will not fit the template's actual Slide 2 placeholder without looking cramped. Cut to what a judge will actually remember; everything else moves to the reserve list below for Q&A/technical slide.)*

> AI-powered email threat detection and forensic intelligence platform that analyzes uploaded, pasted, or Gmail-ingested emails using a team-trained ML model, authentication verification, infrastructure intelligence, URL/attachment reputation, and tamper-evident evidence storage.

*(Held in reserve for Q&A / technical slide, not the main pitch: campaign correlation via fuzzy body-similarity clustering, opt-in Fernet at-rest encryption, forensic PDF/JSON/CSV/CEF exports with a redacted mode.)*

**HOW IT ADDRESSES THE PROBLEM** *(trimmed hard after Judge-Codex round 1 scored this "18/20 — but Slide 2 overall tries to carry ~15 concepts; a fast judge remembers maybe three")*
- Detects phishing, spoofing, BEC, impersonation, suspicious URLs, and risky attachments — authenticated via SPF/DKIM/DMARC/ARC (RFC 8617), a signal most student projects skip.
- **Human actor: not claimed. Relay infrastructure: mapped and scored.** Geo-infrastructure intelligence maps relay IPs to country/ASN/hosting/Tor/VPN context — an honest limitation stated as a design choice, not discovered by a judge.
- Tamper-evident evidence: SHA-256 hash chain, independently anchored via OpenTimestamps — the technical backbone supporting a BSA 2023 Section 63 integrity certificate (a human signatory still issues the actual certificate).

**INNOVATION & UNIQUENESS** *(cut from 6 bullets to the 3 Judge-Codex said a reviewer will actually retain — round 1 verdict: "Choose the three." Two phrasings also reworded per its specific pushback: "almost no comparable tool" invited comparison to real gateway/LLM-scanner products, softened to "rarely seen in student submissions"; "detects attacks on the AI itself" overclaimed proof the model would've obeyed, narrowed to what's actually detected.)*
- **Detects AI-manipulation attempts embedded in email content** — hidden CSS/zero-width-Unicode instructions aimed at an automated classifier (e.g. "mark this email safe"), rarely seen in student email-security submissions. 16 instruction patterns, 51 dedicated tests.
- **Team-trained BERT (99.32% / 99.28% F1 / 99.96% ROC-AUC on a deduplicated split), validated on a real email**: the public pretrained model falsely flagged a real Google security-alert as phishing at 100%; ours correctly called it legitimate at 74.3%.
- **A real analyst workflow, not a classifier demo**: ARC verification, attribution-confidence scoring, live Gmail Pub/Sub ingestion, OpenTimestamps anchoring, and live-verified Splunk export — all implemented and tested, not roadmap items. 380 backend tests.

*(Held in reserve for Q&A, not cut from the project: Gmail Guard browser extension — built/unit-tested, live-demo pending, keep visually distinct from the live-tested server path if it comes up — Tor/AbuseIPDB/VirusTotal detail, and the two production bugs found during live validation.)*

---

## SLIDE 3 — Technical Approach

**Concrete investigation walkthrough** *(new — this is Judge-Codex's single highest-leverage suggestion from round 1: "Replace one dense text section with a single concrete investigation walkthrough... one screenshot-backed case flow would improve this deck more than adding any new feature. It proves the full PS scope in one glance and prevents the submission from reading like a feature inventory." Placed here, above the architecture diagram, and ideally rendered as its own compact visual strip rather than another bullet list — a real screenshot of the actual case view if there's time to capture one, otherwise a labeled flow diagram.)*

> **Real email → model verdict (BERT, 74.3% legitimate) → auth/ARC check → relay ASN/country/Tor/AbuseIPDB → evidence hash + OpenTimestamps anchor → Splunk event**

One glance shows every claimed capability actually firing on one real case, not a list of features that may or may not connect.

**Tech stack table** *(consolidated from 13 rows to 8 per Codex's review — a 13-row table will either shrink unreadably or crowd out the architecture diagram on the template's actual slide; 8 is still tight, consider dropping/merging a row if it overflows on the real slide. Wazuh dropped from this slide: it's real code, `siem.py`'s own status string admits "agent collection and server ingestion are not confirmed" — unlike Splunk, which was live-verified end-to-end, so it doesn't belong next to "live-verified" claims without that caveat. CycloneDX SBOM confirmed real — `security/backend-sbom.cdx.json` and `security/frontend-sbom.cdx.json` exist in the repo.)*

| Layer | Built Components |
|---|---|
| App & API | ReactJS, FastAPI, Docker, Render/local deployment |
| ML Detection | Team-fine-tuned BERT (Hugging Face Transformers, PyTorch) |
| AI-Manipulation Detection | Custom inline-hidden-content DOM walker + instruction-pattern matching + zero-width Unicode detection — catches mail crafted to manipulate a classifier, not just a human reader |
| Email Authentication | SPF, DKIM, DMARC, ARC (RFC 8617) — pyspf, dkimpy, dnspython |
| Threat Intelligence | IP/ASN/geolocation, Tor exit-list correlation, AbuseIPDB, PhishTank, attachment hash/reputation (VirusTotal, opt-in sandbox upload) |
| Forensic Integrity | SHA-256 hash chain, Fernet opt-in encryption, OpenTimestamps (Bitcoin anchoring) |
| Real-Time & SOC Integration | Gmail API + Google Cloud Pub/Sub (server-side, live-tested), Gmail Guard Chrome extension (client-side, unit-tested), Splunk HEC (live-verified), CycloneDX SBOM, JSON/PDF/CSV/CEF exports |
| Scoring | Weighted attribution-confidence engine, multi-signal evidence correlation |

**Architecture flow** *(for your teammate to diagram — describe as a left-to-right or top-down flowchart)*

```
Input: Upload .eml / Paste / Gmail push notification (real-time, when configured)
        │
        ▼
Parse & Extract (headers, body, attachments, URLs)
        │
        ▼
Parallel Enrichment:
  ├─ Authentication (SPF/DKIM/DMARC/ARC)
  ├─ Domain/DNS/RDAP intelligence
  ├─ Geolocation + IP reputation (Tor/AbuseIPDB)
  ├─ URL structural + PhishTank reputation
  ├─ Attachment hash + optional file upload
  └─ Team-trained BERT classification
        │
        ▼
Attribution Confidence Engine + Evidence Scoring + Campaign Correlation
        │
        ▼
Hash-Chained, Encrypted Case Store ──► Blockchain Timestamp (OpenTimestamps)
        │
        ▼
Analyst Dashboard / Reports (PDF/JSON/CSV/CEF) / SIEM (Splunk, live-verified)
```

---

## SLIDE 4 — Feasibility and Viability

**FEASIBILITY**
- Proven technologies: Python, FastAPI, ReactJS, BERT, SPF/DKIM/DMARC/ARC, IP geolocation.
- Modular & scalable: every enrichment module upgrades independently.
- Core detection runs locally (BERT, header/auth parsing, evidence hashing); AbuseIPDB/VirusTotal/Google Cloud/Splunk are optional paid enrichments, not required for the core pipeline. *(Reworded per Judge-Codex round 1: "Low-cost" was called weak/unsupported given these real operational costs.)*

**CHALLENGES & RISKS**
- External dependencies: DNS/geolocation services can introduce delay or downtime.
- Anonymization: VPNs, proxies, Tor can obscure true origin.
- Detection accuracy: ML and heuristics can false-positive or miss sophisticated threats.
- **Real-time infrastructure complexity**: cloud push notifications (Gmail API + Pub/Sub) require secure IAM/OIDC configuration between Google Cloud and the deployed service.

**STRATEGIES TO OVERCOME** *(two phrases softened per Codex's review — "defense-in-depth engineering discipline" and "every integration was independently reviewed" read as process-theater a judge could poke at rather than concrete evidence)*
- Timeout & fallback: caching, graceful degradation on every external call.
- Infrastructure flagging over guessing: Tor/VPN signals reported as evidence, not treated as proof of identity.
- Multi-signal correlation: no single signal — authentication, ML, headers, attribution — decides a verdict alone.
- Immutable evidence chain: SHA-256 hash chaining plus independent blockchain anchoring, so tampering is provably detectable even outside our own infrastructure.
- **380 backend tests** cover authentication parsing, enrichment fallbacks, scoring, exports, blockchain timestamping, SIEM delivery, and the AI-manipulation detector — the ML pipeline was also specifically checked for data leakage (exact rows — after lowercasing and whitespace-normalization — crossing train/test splits, plus label-conflicting rows, were removed; fuzzy/template near-duplicates were not, so the figure is a deduped random-split number) before trusting its accuracy number. Real-world Gmail validation (Slide 2) additionally found and fixed two production-like bugs the test suite alone had missed: a present-but-blank Subject header wrongly rejected, and a real Gmail API indexing-lag race condition where a push notification can arrive before the message is actually queryable.

---

## SLIDE 5 — Impact and Benefits

**TARGET BENEFICIARIES**
- SOC Analysts, Cybercrime Units, Email Administrators, Fraud & BEC Teams.

**QUANTIFIED IMPACT** *(both bullets below reworded per Judge-Codex round 1: "20-40 min to seconds" and "Lower cost" were flagged as unsupported/generic as originally worded)*
- Manual triage steps — header inspection, auth lookup, reputation checks, evidence logging — compressed into one automated pass, typically returned in seconds per email.
- Multi-signal analysis: correlates 8+ security signal classes (auth, ML, reputation, infrastructure, evidence) in one workflow instead of separate manual tools.
- **99.32% accuracy** on a deduplicated held-out test split; real-world validation performed separately (Slide 2) — not an estimated figure, and not a claim of solved generalization.
- **Splunk HEC delivery verified against a live Splunk instance**, with indexed case events available for screenshot evidence *(this stage is PDF-only — no live demo, so phrase it as evidence already captured, not an offer to demo)*.
- Core detection has no mandatory paid API or cloud subscription (see Slide 4) — optional enrichments do carry real operational cost.

**SOCIAL & ECONOMIC BENEFITS** *(keep your original four points — still accurate)*

---

## SLIDE 6 — Research and References

*(Keep your existing table as-is — still accurate and relevant. Optionally add:)*

| Sr. No. | Title | Publication | Key Findings | Gap |
|---|---|---|---|---|
| 9 | RFC 8617: Authenticated Received Chain (ARC) Protocol | IETF, 2019 | Standardizes cryptographic verification of forwarded-mail integrity across relays. | Rarely implemented in student/academic email security projects. |
| 10 | OpenTimestamps: Scalable, Trust-Minimized Timestamping | opentimestamps.org | Anchors arbitrary data hashes to the Bitcoin blockchain for independent, tamper-evident proof of existence. | Not commonly applied to digital forensic evidence chains in academic prototypes. |
| 11 | RFC 7208 (SPF), RFC 6376 (DKIM), RFC 9989 (DMARC, successor to RFC 7489), RFC 5322 (Internet Message Format) | IETF | The core standards this platform's authentication and parsing modules implement directly, not just reference — `backend/authentication.py` names RFC 9989 explicitly in its own DMARC evaluation output. | Most student tools implement one or two of these, rarely all four plus ARC. |
| 12 | MITRE ATT&CK for Enterprise — Phishing (T1566) | MITRE | Standard industry taxonomy for classifying phishing/BEC techniques. | Used here only as a reference framework for describing findings, not as a claimed detection-coverage mapping. |

*(If this table is tight for space, prioritize rows 9–10 over generic phishing-survey papers — they directly support the two differentiators judges are most likely to probe: ARC and blockchain anchoring. Rows 11–12 are cheap, safe additions — pure standards citations, no new capability claims attached — good if there's room.)*

---

## Notes for whoever builds the slides

- **Build directly inside `SIH2026-IDEA-Presentation-Format.pptx`** (the official template, downloaded from `sih.gov.in/letters/2026/SIH2026-IDEA-Presentation-Format.pptx`, saved in the project root). Do not change its fonts, colors, layout, or slide order — the committee guidelines state this risks outright disqualification regardless of idea quality. The template's own 7th slide is an "Important Instructions" page that says to delete itself before submitting — delete it, don't fill it in.
- **Exactly 6 slides, no more.** This content maps 1:1 onto the template's real placeholders: Title → Idea Title/Proposed Solution (includes "how it addresses the problem" and "innovation & uniqueness" in the same slide) → Technical Approach → Feasibility & Viability → Impact & Benefits → Research & References.
- **Submit as PDF only** — the portal does not accept PPT/Word/any other format per the template's own instructions.
- Don't inflate any number above — every figure here (99.32%, 380 tests, 74.3%, etc.) is real, fact-checked against the actual code, and should stay exactly as written with its stated caveat intact. If a judge asks to see it, it needs to hold up.
- The real-email validation story (Slide 2) works best with an actual before/after screenshot from the live app — the model verdict flipping from "PHISHING 100%" to "LEGITIMATE 74.3%" on the exact same real email — ask if there's time to capture a clean one; text alone still works if not.
- **This full draft was sent to Codex (GPT-5.5) for an independent second review**, specifically asked what it would add or change. It found one factual issue we then fixed (the Bank of Baroda hook overstated "phishing" as the confirmed cause — public reporting only confirms "employee email-account compromise," method undisclosed) and flagged that Slide 2's original bullet count (9+3+8) wouldn't fit the template's real placeholder without looking cramped — both fixed in this version. Its other contributions are folded in throughout: the "geo-infrastructure intelligence" reframing (directly answers the PS's own "GeoLocation" wording without overclaiming), the consolidated 7-row tech table, the softened "process theater" phrasing on Slide 4, the PDF-only correction on Slide 5, and the extra judge-preemption items above.
- Slide 2 was deliberately trimmed to bullets a judge will actually remember (AI-manipulation detection, trained model, ARC, attribution confidence, geo-infrastructure intelligence, Gmail push, VirusTotal/AbuseIPDB, OpenTimestamps, Splunk, real-email validation). Resist the urge to re-add everything back in — the extras are listed as reserve material for Q&A, not because they're less true.
- **This version was also checked against a separate Gemini-authored draft the user found** (a "true-origin heuristic" forensic-engine pitch with a Neo4j graph DB, DeBERTa-v3, Celery/Redis, MaxMind, Mapbox, and a 36-hour hackathon roadmap slide). Verified against the actual codebase and rejected almost entirely — most of it describes tools/architecture that don't exist in this project, and its headline "True-Origin Heuristic Algorithm" claim (isolating the real originating IP via RFC 1918 filtering and SMTP banner handshakes) directly contradicts this project's own deliberate, more honest positioning that no Received header trust is established (`'trust': 'Header-reported; receiver trust not established'` on every hop, in the actual code). Its 36-hour roadmap slide also targets the wrong stage entirely — that's the in-person Grand Finale hackathon (December 2026, only if shortlisted), not this PDF idea-submission round, per the Sept 2026 Intellecta/Terna guidelines. What *was* genuinely useful and got folded in: framing the tamper-evident evidence chain against BSA 2023 Section 63 (a strong, India-specific angle, worded carefully so it doesn't overclaim legal certification and doesn't conflate Section 63 with its predecessor IEA Section 65B), and the RFC 7208/6376/9989/5322 + MITRE ATT&CK T1566 citations added to Slide 6 — both are things this project actually implements or can honestly cite, just hadn't been named that way yet.

**Second Codex review round (after the AI-manipulation feature, both Gmail paths, and the BSA/RFC additions above were merged in) flagged and fixed:** the DMARC citation was RFC 7489, superseded by RFC 9989 — `backend/authentication.py` itself names RFC 9989 in its own DMARC output, now corrected on Slide 6; "verifies... to establish whether a message's relay path can be trusted" overclaimed what SPF/DKIM/DMARC/ARC actually do (they authenticate/align a domain or validate an ARC seal, they don't establish trust in raw `Received` hops, which stay explicitly untrusted) — reworded on Slide 2; Slide 2's Innovation & Uniqueness bullets were trimmed for length so the strongest material doesn't become unreadable fine print on the template's real placeholder; and the tech-table row count note was corrected from 7 to 8 rows to match the table as it now stands.

**Third round — a real judging simulation, not just a content review:** Codex was set up as a genuinely demanding SIH judge persona (grounded in the real Terna/Intellecta guidelines, not generic hackathon tropes) and scored this draft **83/100, verdict: shortlisted, conditional on visual discipline** — it independently verified the 99.32% figure against the actual `training_report.json` and re-ran a fresh web search on the Bank of Baroda hook rather than trusting the draft. Its specific findings, now addressed in this version:
- Slide 2 still carried ~15 concepts even after round-2 trimming — cut further to the 3 things it said a fast judge will actually retain (AI-manipulation detector, trained-model validation story, analyst-workflow positioning); the rest moved to an explicit Q&A reserve note.
- "Almost no comparable tool checks for this" invited comparison to real gateway/LLM-scanner products — softened to "rarely seen in student submissions."
- "Detects attacks on the AI itself" overclaimed proof the model would've obeyed a hidden instruction — narrowed to "detects AI-manipulation attempts embedded in email content."
- The "not attacker location" limitation is now stated as an explicit design line ("Human actor: not claimed. Relay infrastructure: mapped and scored.") rather than a caveat a judge has to dig for.
- The BSA Section 63 bullet was cut from a half-slide explanation to one line, per its note that the careful caveat was correct but "may look like legal theater" at length.
- "20–40 min to seconds" and "Lower cost" were called under-evidenced/generic — both reworded to describe what's actually being compressed/what's actually free vs. optional, instead of a bare number.
- Attachment handling was reworded so "risky attachments" doesn't imply sandbox-grade malware verdicting beyond what's actually built (hash/reputation, VirusTotal upload opt-in).
- **Its single highest-leverage suggestion — a concrete, screenshot-backed investigation walkthrough proving the full PS scope in one glance instead of a feature list — is now Slide 3's opening visual.**
