# SIH26106 - Judge-Readable PPT Copy Pack

**Team:** Cache-Me-Maybe
**Product name:** **PRAHARI**
**Tagline:** **Detect. Attribute. Prove.**
**PS:** AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform
**Theme:** Blockchain & Cybersecurity | **Category:** Software

Use Slides 1-6 below as **slide-ready copy**, not a research dump. Keep lines short, build diagrams around the phrases, and move caveats into speaker notes where the slide is crowded. Everything after Slide 6 (**Feature Checklist**, **Judging-Criteria Alignment**, **Q&A Cheat Sheet**, **Guardrails**, **Visuals**) is reference material for the team - not meant to go on a slide verbatim.

**Three production rules, apply everywhere:**
- Put a tiny **`Built` / `Roadmap`** legend on any slide that mixes both, so nothing reads as vague to a judge.
- Narrate the whole deck around **one suspicious email's journey** (arrives -> analyzed -> infrastructure mapped -> evidence sealed -> redacted report exported) instead of listing modules - more memorable, and it doubles as your live demo script.
- Never let a number on a slide be one you can't defend in Q&A. Every stat in this pack was checked against a live run of the actual app or test suite as of this pass - not estimated from memory. If a judge asks "how do you know," you have a real answer in the Q&A Cheat Sheet. Re-verify anything you change after this point before it goes on stage.

---

## 30-Second Pitch (memorize this cold)

> "One compromised inbox took down public trust in a major Indian bank this year. Most tools just block a suspicious email - we built PRAHARI to investigate it. It reads the email the way a forensic analyst would: verify who really sent it, trace the infrastructure behind it, catch the AI-evasion tricks other scanners miss, link it to other attacks in the same campaign, and seal the whole case with a tamper-evident, blockchain-anchored proof - in well under a second locally, about a second with live enrichment. It's not a filter. It's an evidence layer for every SOC and cybercrime cell in the country that can't afford an enterprise forensics suite."

Say this, then go straight to the live demo. Don't explain architecture before a judge has seen the product work.

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

CERT-In handled **29,44,248 cyber incidents in 2025.**

### Solution
**PRAHARI turns a suspicious email into a forensic case in seconds.**

It detects phishing, authenticates the sender, traces relay infrastructure, scores attribution confidence, and preserves tamper-evident evidence - the same discipline a digital forensics lab applies, compressed into one pipeline.

### What It Does

**Detect & Verify**
- **AI phishing detection:** team-trained BERT, **99.32% held-out accuracy**, hardened against truncation-shift evasion via sliding-window inference (0% -> 95% detection on our own attack re-run - see Slide 3)
- **Sender authentication:** SPF, DKIM, DMARC (incl. subdomain policy), ARC - all four, not the usual one or two
- **AI-manipulation detection that resists disguise:** catches hidden prompt-injection and tokenizer-evasion attacks even when hidden behind homoglyphs or zero-width characters
- **Quishing + image-only phishing + BEC defense:** QR codes and readable text hidden inside image and PDF attachments (OCR, English/Latin script), plus mid-thread payment/UPI changes and reply-to swaps a single-email scan would miss
- **Language-aware verdicts:** detects Hindi, Hinglish, code-mixed and regional-script text, tells the analyst when the English-trained model is outside its validated coverage, and applies transparent localized phishing rules

**Investigate & Prove**
- **Relay geo-map + reputation fusion:** hop-by-hop infrastructure tracing against PhishTank, VirusTotal, AbuseIPDB and Tor exit lists
- **Cross-case evidence graph:** typed nodes (sender, domain, relay IP, URL, attachment hash, thread) linked with per-link confidence, not a flat case list
- **Campaign correlation:** links related emails by shared indicators and a hybrid of character-shingle, TF-IDF and SimHash body-similarity
- **Alerts before delivery:** a pre-delivery SMTP gateway analyses mail before any mailbox sees it, holds high-risk messages for analyst release or discard, and stamps clean ones with risk headers (a locally testable gateway model, not a Gmail integration)
- **Analyst controls:** per-person role tokens (viewer / analyst / admin), every audit-chain event stamped with who did it, and a four-eyes rule so the analyst who ran a case cannot approve it
- **Landing-page inspection:** analyst-triggered, static, SSRF-hardened fetch that describes what a link's page is (credential forms, cross-domain posts, brand cues) without running any script
- **Cross-session memory:** a hashed indicator ledger shows when a sender, link or reply address has appeared in earlier analyses across sessions, without storing any case content
- **Court-supporting evidence:** SHA-256 hash chain + Bitcoin timestamp anchor - tamper-evident, independently verifiable - plus a one-click electronic-evidence support pack (manifest, hashes, custody trail, draft declaration for a human signer)
- **SOC-ready, DPDP-conscious output:** PDF (correct Hindi/Devanagari rendering), JSON, CSV, CEF, STIX 2.1 (MISP-importable), Splunk - Aadhaar, PAN, UPI and mobile numbers auto-masked, optional email masking, and a per-export masking summary

### Uniqueness Box
**Most tools block email. PRAHARI investigates it.**

**AI that detects attacks on AI.** Most phishing tools protect humans from emails; PRAHARI also protects its own automated analyst from hidden instructions and tokenizer tricks designed to fool it.

Novelty:
- **AI-manipulation detection that resists disguise:** hidden prompt-injection and tokenizer-evasion checks that still fire even when the attack text is hidden behind homoglyphs or padded past a naive model's attention window
- **Three separate outputs, never one blended number:** evidence score (how bad is the content), attribution confidence (how much to trust the infrastructure trace) and review priority (what an analyst should do first) - each with its own caveat, so uncertainty in one never inflates another
- **Verified-sender mercy:** a scary-looking but DKIM/DMARC-aligned legitimate email is not punished by content alone - careful, not alarmist
- **Truthful attribution as innovation:** infrastructure + confidence, never a fake attacker identity - more forensic than flashy
- **Tamper-evident proof:** every case is hash-chained and timestampable

Speaker note: Say "employee email-account compromise," not "confirmed phishing cause." Do not claim human attacker geolocation. Demo order that lands best: open with the Gmail Guard banner (where the user already works), then the dashboard case, then the evidence graph, then the export - not backend internals first.

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
- **Same backend pipeline:** upload, paste, Gmail and extension all converge - one engine, four entry points

### Tech Stack Strip
**Python + FastAPI** | **React + Vite** | **BERT / PyTorch** | **SPF/DKIM/DMARC/ARC**
**OpenTimestamps + SHA-256** | **Splunk HEC** | **PhishTank / VirusTotal / AbuseIPDB**

### Proof It Runs
- **769 backend tests passing** - covering Gmail race conditions, dead-letter retries, prompt injection, PII masking, OpenTimestamps, SSRF and access-control boundaries, a real SMTP gateway, real OCR, and every fallback state, not just the happy path
- Frontend build/lint clean (0 oxlint warnings); browser extension 9/9 tests passing (including the click-time warning)
- **Adversarial-evasion hardened, not just claimed:** truncation-shift attack detection measured at 0/100 before the fix, **95/100 after**, on the team's own held-out attack re-run
- CSP and Permissions-Policy always on; Strict-Transport-Security enabled whenever deployed with HTTPS asserted (`COOKIE_SECURE=1`) - verified live in a real browser against the running app
- **Multi-round independent AI code review, not self-graded:** two separate review passes found and closed real gaps (a spoofable rate-limit header, a duplicated security-header bug), every fix backed by a regression test
- Gmail Guard live-verified against a real Gmail account; Splunk HEC delivery live-verified against a real Splunk Enterprise collector

**Engineering depth, not just feature count:** Gmail Pub/Sub ingestion handles real production weirdness - OIDC-authenticated push, Gmail's own indexing-lag races, a dead-letter retry queue with bounded attempts. That's proof the team handled production conditions, not just toy uploads.

**Complexity with brakes:** the system fuses 7 signal groups plus conversation-thread and network-history context, but is disciplined enough to cap scores and label uncertainty rather than force a confident-sounding wrong answer.

Visual: make the pipeline the main graphic. Keep technology as a thin logo strip.

---

## Slide 4 - Feasibility & Viability

### Feasibility
**Working prototype today, not a concept.**

- Runs locally end-to-end
- 769 backend tests green
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

- OCR for Indic scripts (Hindi and regional languages) - today's OCR reads English/Latin script only
- Rendered-page screenshots and visual brand matching for landing pages (today: static, script-free inspection)
- Calibrated probability scores (Brier score, reliability diagrams)
- Learned multimodal fusion model, replacing today's rule-based score caps
- Live-account verification of the Gmail label/quarantine actions, and SSO/OIDC identity for roles (both exist for testing today: the Gmail actions are unit-tested against a fake Gmail service only, and roles use per-person bearer tokens)

Phrase to use: **"Truthful forensics beats fake certainty."**

---

## Slide 5 - Impact & Benefits

### Impact Numbers
**Seconds, not guesswork.**

- **~50-65 ms median analysis time (p95 under 80 ms), server-measured** with the BERT model loaded, on the local-only path (no live enrichment) - two 100-run benchmarks (engine-only and full API path incl. case storage), raw data in `benchmarks/`; exact figure varies with machine load
- **~1-1.5 s for a first-time live enrichment** (DNS/RDAP/geo/AbuseIPDB, measured across six real domains - `benchmarks/enrichment_timing.json`), and back to ~35 ms for repeat lookups thanks to caching. Network-dependent, so quote it as "about a second," not a guarantee
- **99.32% held-out ML accuracy, 0.49% false-positive rate**
- **7 scored evidence groups**, plus enrichment/attribution/campaign layers and conversation-thread + network-history context, converging into one verdict
- **0 known vulnerabilities** in a `pip-audit` scan of all 85 packages in a clean install that mirrors the Docker image, and an `npm audit` of all 102 frontend dependencies; CycloneDX SBOMs generated for both backend (85 components) and frontend (59 components). The clean-environment scan caught outdated `setuptools` CVEs that a dev-environment scan had missed - fixed by pinning

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

## Judging-Criteria Alignment (Internal - Use to Prep, Don't Put On a Slide)

SIH judges score against a fixed rubric. Here's what to point to for each criterion, using only things that are actually built and tested - nothing aspirational.

| # | Criterion | Weight | What to point to |
|---|---|---|---|
| 1 | Novelty of the Idea | 10% | AI-manipulation/prompt-injection detection (the tool defends itself, not just the user); truthful attribution instead of fake attacker identity; quishing + conversation-aware BEC as underserved attack surfaces |
| 2 | Complexity & Architecture | 15% | Multi-window BERT inference, RFC-compliant SPF/DKIM/DMARC/ARC engine, hash-chained + Bitcoin-anchored evidence store, typed cross-case evidence graph, SIEM dispatcher - 7+ fused signal groups with one converging verdict |
| 3 | Clarity & Prescribed Format | 10% | Strict 6-slide template, one-email-journey demo narrative instead of a module list, clean RFC/legal citations throughout, explicit `Built` vs `Roadmap` separation on every slide |
| 4 | Feasibility & Viability | 15% | Runs fully local, external APIs optional with graceful fallback, 769 automated tests, modular swappable pipeline |
| 5 | Practicability & Applicability | 15% | Gmail Guard browser extension + Pub/Sub push mean zero new inbox habit; PDF/CEF/Splunk exports slot into existing SOC tooling |
| 6 | Sustainability & Security | 10% | CSP/HSTS/Permissions-Policy, 0 known dependency vulnerabilities, rate-limiting with spoof-resistant proxy trust, zero-paid-API core |
| 7 | Scale of Impact | 10% | Directly addresses quishing/UPI fraud and BEC payment diversion - both named as emerging, underserved threats in the roadmap research (Slide 6) |
| 8 | User Experience (UX) | 10% | Cross-case evidence graph, conversation-aware BEC checks, analyst notes/assignment and triage workflow - built to be used, not just demoed once |
| 9 | Future Progression | 5% | Roadmap is explicitly research-grounded (5 papers, Slide 6), not a wishlist - Indic-script OCR, calibrated scoring, multilingual detection |

**How to use this table:** if a judge's question maps to one of these rows, answer with the specific thing in that row - not a generic "we built a lot of features" answer. Specificity is what separates a 9 from a 7 on a rubric like this.

---

## Judge Q&A Cheat Sheet (The Hard Questions, Answered Honestly)

Every one of these was actually asked or actually investigated during development - not hypothetical. Answer directly; don't get defensive. Honesty here is a strength, not a weakness - it's what separates a real prototype from a slide deck.

**Q: How do we know your attribution weights (summing to 110, not 100) aren't arbitrary?**
A: The 9 positive factors intentionally sum to 110, with the final score capped at `min(100, ...)`. That's deliberate headroom: a case missing one weak signal (e.g. geolocation, worth only 5 points) can still reach a perfect 100 instead of being permanently capped below it for one unavailable, low-value factor. It's a documented design choice, tested (`test_all_nine_positive_factors_applied_still_caps_at_exactly_100`), not an oversight.

**Q: Your rate-limiting trusts a reverse proxy's forwarded-IP header - isn't that spoofable?**
A: Only when explicitly enabled (`TRUSTED_PROXY_HOPS` opt-in, off by default) and only from a direct connection in an IP allowlist (`TRUSTED_PROXY_IPS`) - fails closed otherwise. An unrecognized direct connection's forged header is never trusted. In a multi-proxy chain, every hop between the app and the client must itself be a trusted proxy (exact IPs or CIDR ranges); the first untrusted address from the right is taken as the client, so a forged prefix is never reached.

**Q: Does Gmail Guard use an official Gmail API?**
A: The push-ingestion path (Gmail Pub/Sub) does, with OIDC-authenticated webhooks. The browser-extension banner reads Gmail's own page markup to show a live risk score inline - that's inherently coupled to Gmail's frontend, which we say plainly rather than oversell as an official integration. It's live-verified today; the Pub/Sub path is the production-grade one.

**Q: Is access control real?**
A: The roles are real, the case-assignment field is not. With `ROLE_TOKENS` set, every API route enforces a viewer / analyst / admin role from a per-person bearer token (unknown routes default to admin-only), every audit-chain event is stamped with the actor, and a four-eyes rule stops the person who analyzed a case from approving it. It is application-level access control, not an identity provider: there is no SSO, and "assignment" itself remains a free-text triage label. Left unset, the app runs open exactly as before.

**Q: The PS asks for alerts before user interaction - do you do that?**
A: At two levels, and we are precise about each. The pre-delivery SMTP gateway analyses a message before it reaches any mailbox and holds high-risk ones for analyst review - proven end to end over real SMTP, but it is a gateway model for an institution's own mail flow, not an interception of Gmail. Inside Gmail, the extension shows the risk banner and, once a high-risk verdict is in, asks for confirmation on link clicks (best effort, not a security boundary). Gmail label/quarantine actions exist but are unit-tested against a fake Gmail service only; we have not run them against a live account and do not claim to.

**Q: Bitcoin anchoring - can you prove a case's timestamp right now, live?**
A: The anchor is submitted immediately and is independently verifiable, but Bitcoin confirmation genuinely takes hours, not seconds - that's how the underlying protocol works, and we're not going to pretend otherwise. We have a real demo proof, submitted ahead of time and now **confirmed in Bitcoin block 968372** (`demo/bitcoin_proof/demo_proof.json`; run `demo_proof.py check` to re-verify it live against a public block explorer). It anchors the real hash-chain head of a sample-case session - proof that the head hash existed by that block, not proof the email is genuine. Confirmation for a fresh case still takes hours, and we say so.

**Q: A prior AI review claimed you fixed a "SQLite deadlock" - did you?**
A: We stress-tested that exact claim with 20 real concurrent threads and it never reproduced - so we didn't claim a fix for a bug we couldn't confirm existed. We did remove a redundant second database connection in the note/assignment code path as legitimate hardening, but we're precise about the difference between "fixed a proven bug" and "removed a theoretical risk."

**Q: How real is your 99.32% accuracy?**
A: It's a held-out test-split result on 33,527 emails the model never trained on, from an exact-deduplicated random split - a legitimate number, not a real-world guarantee. We haven't yet run a campaign-held-out or near-duplicate-safe benchmark (template-level near-duplicates across campaigns could still leak signal between train and test) - that's explicitly on our own roadmap, not swept under the rug. Real-world traffic will also drift from any training distribution; that's exactly why the pipeline never lets the ML score stand alone - it's fused with cryptographic sender authentication.

---

## Complete Feature Status Checklist (Master Reference)

**This is a reference list, not slide copy.** Pull only 4-6 items per slide (see Slide 2/3/4 above). Two tiers, never mix them on a slide or in a demo:
- **✅ Built & verified today** - real, working, tested code. Safe to say "built," "works," "live."
- **🔜 Planned (research-informed roadmap)** - not yet built. Say "planned" or "next phase." If a judge asks to see it, say so honestly - that honesty is this project's credibility.

### ✅ Built & Verified Today

**Detection**
- ✅ Team-trained BERT phishing classifier - 99.32% accuracy, 0.49% false-positive rate, 33,527 held-out test emails (exact-dedup random split; a campaign/near-duplicate-held-out benchmark is on the roadmap, not yet run)
- ✅ Sliding-window inference defeats truncation-shift evasion - the model used to only see the first 256 tokens; padding an email with junk text pushed the real payload out of view entirely. Overlapping windows across the full message closed this: detection on the team's own attack re-run went from 0/100 to 95/100
- ✅ AI-manipulation / prompt-injection detection (hidden CSS, zero-width Unicode) - now also checks a homoglyph-normalized copy of the text, closing a Cyrillic-lookalike disguise gap the raw-text check alone missed
- ✅ Adversarial NLP-evasion detector (homoglyph + zero-width raw-vs-normalized probability delta)
- ✅ Authentication-aware ML fusion - a content-only signal from a cryptographically verified sender no longer inflates the score
- ✅ Social-engineering language rules (credential pressure, payment diversion, verification avoidance)
- ✅ Language coverage router and Hindi/Hinglish rules - detects Devanagari and other scripts, romanized Hindi and code-mixed text; marks the English-trained model as outside its validated coverage (banner + playbook step); applies transparent localized credential/payment/verification-avoidance rules that reuse the English rules' finding titles. Keyword heuristics, not a multilingual model, and not accuracy evidence
- ✅ Quishing and image-only phishing detection - QR codes in PNG/JPEG/GIF/BMP/WEBP images and on the first two pages of PDFs are decoded and scored like any link; text inside the same images and pages is read by OCR (RapidOCR/ONNX, models shipped inside the wheel, English/Latin script only, at most 3 images/pages and 12 s per message) and analysed like body text - rules, language check, link extraction and the classifier - while the stored body stays untouched. Image-only messages are flagged. OCR is an aid, not proof; Indic scripts are not read
- ✅ Conversation-aware BEC detection - flags mid-thread payment/UPI-ID changes, reply-to domain swaps, and thread-history anomalies that a single-email scan can't see

**Authentication & Origin**
- ✅ Full SPF, DKIM, DMARC (RFC 9989, incl. subdomain `sp` policy per RFC 7489 S6.6.3), ARC (RFC 8617) verification
- ✅ Trust-boundary separation: receiver-attested "earliest reliable node" kept distinct from the header-reported chain
- ✅ Every relay hop explicitly labeled "receiver trust not established" unless attested
- ✅ Network-behavior-over-time tracking - compares a sender's first/last-seen relay and reputation history across cases in the current session, not just a single external lookup
- ✅ Cross-session indicator ledger - a keyed-HMAC-hashed record of indicators (sender, link, reply address, attachment hash, relay IP) with first/last seen and counts, so an analysis shows what appeared in earlier analyses across sessions. Stores no case content and no raw values, excludes demo samples, expires after a retention window (default 90 days), and never raises triage by itself. On Windows set `LEDGER_KEY` rather than relying on file permissions

**Infrastructure & Reputation**
- ✅ Relay geolocation (IP/ISP/ASN, source + timestamp recorded per lookup)
- ✅ Tor-exit-node matching
- ✅ AbuseIPDB hosting/proxy/VPN classification
- ✅ Domain/DNS/RDAP intelligence
- ✅ URL structural analysis + PhishTank matching
- ✅ VirusTotal attachment-hash reputation + opt-in sandbox upload (parallelized lookups)
- ✅ Static attachment inspection - executable signatures, PDF action markers, Office macros, encryption markers, plus a YARA-style declarative rule set (HTML smuggling, macro auto-exec, RTF exploit objects, .lnk shortcuts, PDF embedded files, encoded script droppers, double extensions, RTL-override filenames, disk images) and archive checks for zip-slip path traversal, zip-bomb expansion ratios and nested archives - every finding carries a rule ID; nothing is executed or decompressed
- ✅ Static landing-page inspection (analyst-triggered) - fetches one linked page and describes it: title, forms, password fields, cross-domain form posts, meta refresh, frames, external scripts, brand-vs-domain cues, a structure hash. No JavaScript, cookies or rendering. SSRF-hardened: only public web hosts on ports 80/443/8080/8443; DNS resolved once and the connection pinned to the validated address; every redirect re-validated; 512 KB and 8 s hard caps enforced during the read (a slow-drip server cannot hold a worker); TLS verified, never bypassed; only URLs from that case are accepted; explicit confirmation because the destination sees the server's IP. Not a rendered screenshot

**Attribution & Evidence**
- ✅ Attribution Confidence Engine - transparent 0-100 weighted score, hard-capped low when origin is undetermined; validated against a 17-scenario labeled matrix (17/17 in the expected band, 13/13 ordering checks hold - `benchmarks/attribution_validation_matrix.md`). Validates ordering and banding of the hand-set weights, not a calibrated probability
- ✅ Campaign correlation - shared indicators + a hybrid body-similarity stack: character-shingle Jaccard, TF-IDF cosine and 64-bit SimHash over digit/URL-masked word tokens. Two tiers: both signals agreeing tightly can group cases; a moderate match only draws a context-only link and never merges cases
- ✅ Cross-case evidence graph - typed nodes (case, sender address/domain, relay IP, URL, attachment hash, reply-to, thread ID) linked by shared indicators, each link tagged `strong` or `context_only` confidence rather than one flat "connected" line
- ✅ Distinct triage priority states (urgent / review / incomplete / routine) - separate from the uncalibrated evidence score
- ✅ SHA-256 hash-chained tamper-evident event log with an independent chain-integrity verify check
- ✅ Bitcoin-blockchain anchoring via OpenTimestamps - a real demo proof is confirmed in block 968372 and re-verifiable on demand
- ✅ Optional Fernet at-rest field encryption

**Compliance & Privacy**
- ✅ DPDP-conscious export masking - Aadhaar (Verhoeff-checksum validated), PAN, UPI, mobile numbers, auto-masked in every export
- ✅ Optional email-address masking (`j***@domain`, off by default because sender addresses are forensic evidence) and a masking summary in every export - counts of what was masked by type, never the values
- ✅ Redacted export mode - content/identity withheld, case ID and hash retained
- ✅ Electronic-evidence support pack (Markdown, one click) - case manifest, SHA-256 of the original message and report, the hash-chained custody trail for that case, method statement, limitations, and a DRAFT declaration table for a human signer. Support material only: it does not certify admissibility and the certificate format must be confirmed with counsel

**Real-Time Ingestion**
- ✅ Gmail Pub/Sub server-side push ingestion - live-verified on a real account
- ✅ "Gmail Guard" browser extension - live-verified end-to-end against real Gmail, in-page risk banner
- ✅ Pre-delivery gateway (opt-in via `GATEWAY_SMTP_PORT`) - an SMTP endpoint that analyses each message before any mailbox, delivers clean mail with X-PRAHARI-* headers, and holds urgent or score-60+ mail in a quarantine with a hold/release/discard workflow logged in the audit chain. Analysis exceptions hold the message; capacity and storage failures answer SMTP 451 so nothing is delivered and the sender retries. Proven end to end over real SMTP in the test suite and in the running app. A gateway model for an institution's own mail flow, not a Gmail integration
- ✅ Click-time link warning in Gmail Guard - once a high-risk verdict is installed, ordinary link clicks in the message body show a confirmation dialog with the real destination (Google redirect wrappers unwrapped; dangerous schemes cannot be opened). Best effort, not a security boundary: it does not cover clicks before the scan finishes, the context-menu "open in new tab", or Gmail's own scripts
- ✅ Gmail label/quarantine actions (opt-in via `GMAIL_ACTION_MODE`: off / dry-run / label / quarantine) - reversible only (adds labels, at most removes from the inbox; never deletes, trashes or sends), failures recorded not raised, every outcome in the audit chain. Unit-tested against a fake Gmail service; NOT verified against a live Gmail account, and needs the gmail.modify scope

**Reporting & SOC Integration**
- ✅ PDF (with real Unicode/Devanagari text shaping - Hindi renders correctly, not as `?`) / JSON / CSV / CEF exports - the CSV is sectioned (indicators, findings, URLs, authentication, attachments) with spreadsheet-formula-injection neutralised, and JSON exports carry a schema version
- ✅ Live-verified Splunk HEC delivery
- ✅ STIX 2.1 export - a bundle of only the adverse indicators (risky URLs, mismatched reply addresses, flagged attachment hashes, Tor-matched relays), TLP:AMBER marked, no message content, deterministic IDs. Validated with the reference `stix2` library and `stix2-patterns` (bundle parses, every pattern valid, including hostile-quoting cases). Not yet exercised against a live MISP instance
- ✅ Case list, single-case view, campaign/connection view, review-and-acknowledge workflow

**Investigation Workflow**
- ✅ Full-text case search across subject, sender, recipient, findings and indicators - not just a client-side filter on the summary list
- ✅ Analyst notes per case, with a live character-count hint on the verification note field
- ✅ Evidence-driven next-step playbook - every suggested action (verify out-of-band, block link destinations, quarantine attachments, preserve evidence, report to CERT-In / the 1930 cyber-fraud helpline) appears only when the case contains the evidence that triggers it, and states why. Suggestions, not automated actions
- ✅ Case ownership / assignment label for triage (a label, not access control - see the role-based items below)
- ✅ Role-based access control (opt-in via `ROLE_TOKENS`) - per-person bearer tokens with viewer / analyst / admin roles enforced on every API route (unknown writes default to admin-only; fails closed if configured but no valid entry; only the exact self-authenticated Gmail routes are exempt); authenticated people share one workspace so a reviewer can open an analyst's case; per-person rate limits; sign-in screen in the UI
- ✅ Actor-stamped audit chain and four-eyes rule - every hash-chained event records the authenticated actor (or a named system component such as the gateway or Gmail push) and the chain still verifies; the person who analyzed a case cannot approve it (a hold is always allowed; `FOUR_EYES=0` for single-person demos). Authenticated app role, not legal identity

**Security Hardening**
- ✅ Content-Security-Policy, Strict-Transport-Security and Permissions-Policy headers - CSP live-verified in a real browser against the deployed app's actual map tiles, not just theoretically correct
- ✅ Dangerous URL schemes explicitly flagged instead of silently dropped: `javascript:`/`data:`/`vbscript:` at full severity (including case, whitespace and control-character obfuscation), and handler schemes (`file:`, `search-ms:`, the `ms-*` family used in Follina-style exploits) at review level
- ✅ Opt-in, IP-allowlisted trusted-reverse-proxy handling for rate-limiting - `X-Forwarded-For` is never trusted from an unrecognized direct connection, closing a spoofable-identity gap
- ✅ Mobile-responsive layout and an automated accessibility audit (`security/ACCESSIBILITY_AUDIT.md`): axe-core WCAG 2.1 A/AA clean across 12 UI states, contrast verified on 1,226 text elements (one real failure found and fixed), no horizontal overflow at 375 px. Automated audit only - not a screen-reader test or a WCAG certification
- ✅ Frontend bundle splitting - measured: a single unsplit 542 kB JS bundle became cacheable vendor chunks plus a 67 kB app chunk (total bytes are similar; the win is a small entry chunk and long-lived vendor caching, not less code)
- ✅ CycloneDX SBOMs generated for backend (85 components, from a clean install mirroring the Docker image) and frontend (59 components); `pip-audit` over all 85 backend packages (torch's CPU build is not in PyPI's advisory index and cannot be audited by pip-audit) and `npm audit` over all 102 frontend dependencies both report 0 known vulnerabilities (reproducible - see `security/README.md`)

**Engineering Quality**
- ✅ 769 automated backend tests, frontend build/lint clean (0 oxlint warnings), browser extension 9/9 tests
- ✅ Multi-round independent AI code review on every change, with every finding logged in `security/REVIEW_REGISTER.md` - 32 entries: real bugs fixed with regression tests, plus the claims we investigated and did NOT act on (a SQLite deadlock that never reproduced, non-bugs including a wrongly claimed "no Python 3.12 torch wheel") and known limitations left open

### 🔜 Planned - Research-Informed Roadmap (Not Yet Built)

*Grounded in 5 papers reviewed Sept 2026: SAHF-PD (Electronics 2026), PhishTrace review (J. Cybersecur. Priv. 2026), PhishLumos (IEEE Access 2026), PAM 2025 Enterprise Phishing Networks, BEC Systematic Review (Computers & Security 2025). Full citations on Slide 6.*

**Highest-priority next additions**
- 🔜 OCR for Indic scripts (Hindi and regional languages) - today's OCR reads English/Latin script only
- 🔜 Rendered-page screenshots and visual brand matching for landing pages - today's inspection is static and script-free
- 🔜 Learned multimodal fusion model - replacing today's fixed rule-based score caps

**Foundation hardening**
- 🔜 Live MISP / TAXII exchange (today: STIX 2.1 file export only)
- 🔜 Independent, near-duplicate-safe evaluation suite - our own training script already flags that exact-dedup alone doesn't catch template-level near-duplicates; next step is campaign/source-held-out benchmarks
- 🔜 Calibrated probability scores (Brier score, reliability diagrams) - today's states are distinct, but the score itself stays uncalibrated
- 🔜 Evidence-linked explanations - stable finding IDs that reference exact source location

**Additional roadmap items**
- 🔜 India-specific curated brand/UPI reference set for impersonation detection (the similarity-check mechanism already exists; the curated list doesn't ship by default)
- 🔜 A trained multilingual / code-mixed phishing classifier (Hindi + regional languages) - today: a language-coverage router plus localized keyword rules, and the classifier itself is still English-trained
- 🔜 Broader adversarial-robustness testing (paraphrase attacks - beyond today's truncation-shift, homoglyph and zero-width coverage)
- 🔜 Async job pipeline for slow enrichment (page-fetch, OCR) with retries and resilience
- 🔜 SSO/OIDC identity for roles (today: per-person bearer tokens) and live-account verification of the Gmail label/quarantine actions
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
- Case ownership/assignment is a triage label, not real access control.
- The pre-delivery gateway is a gateway model for an institution's own mail flow, not an interception of Gmail; Gmail label/quarantine actions are verified against a fake service only.
- Click-time warning is best effort, not a security boundary. OCR reads English/Latin script only and is an aid, not proof. Landing-page inspection is static (no JavaScript, no screenshot).
- Role auth is per-person bearer tokens, not SSO. The ledger and OCR are on by default (switch off with `LEDGER_ENABLED=0` / `OCR_ENABLED=0`); roles, the gateway and Gmail actions are off unless configured.
- The gateway holds only urgent or score-60+ messages: a review-level phish (for example a Hinglish credential lure scoring 20) is delivered with an `X-PRAHARI-Triage: review` header, not held.

---

## Visuals To Build

1. **Hero pipeline:** Email in -> forensic case out
2. **Seven evidence layers:** auth, ML, URL, attachment, relay, reputation, evidence
3. **Risk vs solution:** compromised inbox vs PRAHARI case file
4. **Hash-chain proof:** one edited block breaks the chain
5. **Live product screenshot:** Gmail Guard + dashboard
6. **Cross-case evidence graph screenshot:** a real campaign's typed node/edge map (sender -> domain -> relay IP -> URL), strong vs context-only links visually distinct - this is the single most "wow" screenshot in the product, use it big
7. **Conversation BEC panel screenshot:** the exact moment a mid-thread payment/UPI-ID change gets flagged - pairs well with a BEC-loss statistic from Slide 6

**Favorite idea if there's time to build it: an "Evasion Lab" demo panel.** Show the raw phishing probability next to the homoglyph/zero-width-normalized probability side by side for one crafted email, with a plain verdict: "model resisted" or "model fooled." The line that lands: *"Even when the AI isn't fooled, the attempt itself becomes evidence."* Novel, honest, visual, and hard to forget - `result['adversarial']` already computes this data, so it's a UI panel, not new backend logic.

Best slide energy:

**Don't show a tool. Show an investigation.**
