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
- **Quishing + BEC defense:** QR codes hidden inside image and PDF attachments, plus mid-thread payment/UPI changes and reply-to swaps a single-email scan would miss

**Investigate & Prove**
- **Relay geo-map + reputation fusion:** hop-by-hop infrastructure tracing against PhishTank, VirusTotal, AbuseIPDB and Tor exit lists
- **Cross-case evidence graph:** typed nodes (sender, domain, relay IP, URL, attachment hash, thread) linked with per-link confidence, not a flat case list
- **Campaign correlation:** links related emails by shared indicators and a hybrid of character-shingle, TF-IDF and SimHash body-similarity
- **Court-supporting evidence:** SHA-256 hash chain + Bitcoin timestamp anchor - tamper-evident, independently verifiable
- **SOC-ready, DPDP-conscious output:** PDF (correct Hindi/Devanagari rendering), JSON, CSV, CEF, Splunk - Aadhaar, PAN, UPI and mobile numbers auto-masked, optional email masking, and a per-export masking summary

### Uniqueness Box
**Most tools block email. PRAHARI investigates it.**

**AI that detects attacks on AI.** Most phishing tools protect humans from emails; PRAHARI also protects its own automated analyst from hidden instructions and tokenizer tricks designed to fool it.

Novelty:
- **AI-manipulation detection that resists disguise:** hidden prompt-injection and tokenizer-evasion checks that still fire even when the attack text is hidden behind homoglyphs or padded past a naive model's attention window
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
- **633 backend tests passing** - covering Gmail race conditions, dead-letter retries, prompt injection, PII masking, OpenTimestamps, and every fallback state, not just the happy path
- Frontend build/lint clean (0 oxlint warnings); browser extension 3/3 test suites passing
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
- 633 backend tests green
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

- OCR for arbitrary in-image phishing text (QR-code decoding in images and PDFs is already built - OCR is the remaining gap)
- Selective landing-page inspection for unresolved links (isolated worker, no credentials used)
- Calibrated probability scores (Brier score, reliability diagrams)
- Learned multimodal fusion model, replacing today's rule-based score caps

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
| 4 | Feasibility & Viability | 15% | Runs fully local, external APIs optional with graceful fallback, 633 automated tests, modular swappable pipeline |
| 5 | Practicability & Applicability | 15% | Gmail Guard browser extension + Pub/Sub push mean zero new inbox habit; PDF/CEF/Splunk exports slot into existing SOC tooling |
| 6 | Sustainability & Security | 10% | CSP/HSTS/Permissions-Policy, 0 known dependency vulnerabilities, rate-limiting with spoof-resistant proxy trust, zero-paid-API core |
| 7 | Scale of Impact | 10% | Directly addresses quishing/UPI fraud and BEC payment diversion - both named as emerging, underserved threats in the roadmap research (Slide 6) |
| 8 | User Experience (UX) | 10% | Cross-case evidence graph, conversation-aware BEC checks, analyst notes/assignment and triage workflow - built to be used, not just demoed once |
| 9 | Future Progression | 5% | Roadmap is explicitly research-grounded (5 papers, Slide 6), not a wishlist - image OCR, calibrated scoring, multilingual detection |

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

**Q: Is "case assignment" real access control?**
A: No, and we don't claim it is. It's a lightweight, free-text ownership label for solo/small-team triage, not authentication or RBAC. Real multi-analyst access control is explicitly on the roadmap, not claimed as built.

**Q: Bitcoin anchoring - can you prove a case's timestamp right now, live?**
A: The anchor is submitted immediately and is independently verifiable, but Bitcoin confirmation genuinely takes hours, not seconds - that's how the underlying protocol works, and we're not going to pretend otherwise. We submit a real demo proof ahead of time (`demo/bitcoin_proof/`) so a Bitcoin-confirmed proof can be verified live; check its status with `demo_proof.py check` before presenting, and if it has not confirmed yet, say so and show the pending state honestly.

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
- ✅ Quishing (QR-in-attachment) detection - QR codes hidden inside PNG/JPEG/GIF/BMP/WEBP images and on the first two pages of PDF attachments (rendered at bounded resolution, with tolerant fallback decoders) are decoded and scored through the same URL reputation pipeline as a normal link. (OCR on arbitrary in-image text is not built - stated honestly, see Roadmap)
- ✅ Conversation-aware BEC detection - flags mid-thread payment/UPI-ID changes, reply-to domain swaps, and thread-history anomalies that a single-email scan can't see

**Authentication & Origin**
- ✅ Full SPF, DKIM, DMARC (RFC 9989, incl. subdomain `sp` policy per RFC 7489 S6.6.3), ARC (RFC 8617) verification
- ✅ Trust-boundary separation: receiver-attested "earliest reliable node" kept distinct from the header-reported chain
- ✅ Every relay hop explicitly labeled "receiver trust not established" unless attested
- ✅ Network-behavior-over-time tracking - compares a sender's first/last-seen relay and reputation history across cases in the current session, not just a single external lookup

**Infrastructure & Reputation**
- ✅ Relay geolocation (IP/ISP/ASN, source + timestamp recorded per lookup)
- ✅ Tor-exit-node matching
- ✅ AbuseIPDB hosting/proxy/VPN classification
- ✅ Domain/DNS/RDAP intelligence
- ✅ URL structural analysis + PhishTank matching
- ✅ VirusTotal attachment-hash reputation + opt-in sandbox upload (parallelized lookups)
- ✅ Static attachment inspection - executable signatures, PDF action markers, Office macros, encryption markers, plus a YARA-style declarative rule set (HTML smuggling, macro auto-exec, RTF exploit objects, .lnk shortcuts, PDF embedded files, encoded script droppers, double extensions, RTL-override filenames, disk images) and archive checks for zip-slip path traversal, zip-bomb expansion ratios and nested archives - every finding carries a rule ID; nothing is executed or decompressed

**Attribution & Evidence**
- ✅ Attribution Confidence Engine - transparent 0-100 weighted score, hard-capped low when origin is undetermined; validated against a 17-scenario labeled matrix (17/17 in the expected band, 13/13 ordering checks hold - `benchmarks/attribution_validation_matrix.md`). Validates ordering and banding of the hand-set weights, not a calibrated probability
- ✅ Campaign correlation - shared indicators + a hybrid body-similarity stack: character-shingle Jaccard, TF-IDF cosine and 64-bit SimHash over digit/URL-masked word tokens. Two tiers: both signals agreeing tightly can group cases; a moderate match only draws a context-only link and never merges cases
- ✅ Cross-case evidence graph - typed nodes (case, sender address/domain, relay IP, URL, attachment hash, reply-to, thread ID) linked by shared indicators, each link tagged `strong` or `context_only` confidence rather than one flat "connected" line
- ✅ Distinct triage priority states (urgent / review / incomplete / routine) - separate from the uncalibrated evidence score
- ✅ SHA-256 hash-chained tamper-evident event log with an independent chain-integrity verify check
- ✅ Bitcoin-blockchain anchoring via OpenTimestamps
- ✅ Optional Fernet at-rest field encryption

**Compliance & Privacy**
- ✅ DPDP-conscious export masking - Aadhaar (Verhoeff-checksum validated), PAN, UPI, mobile numbers, auto-masked in every export
- ✅ Optional email-address masking (`j***@domain`, off by default because sender addresses are forensic evidence) and a masking summary in every export - counts of what was masked by type, never the values
- ✅ Redacted export mode - content/identity withheld, case ID and hash retained

**Real-Time Ingestion**
- ✅ Gmail Pub/Sub server-side push ingestion - live-verified on a real account
- ✅ "Gmail Guard" browser extension - live-verified end-to-end against real Gmail, in-page risk banner

**Reporting & SOC Integration**
- ✅ PDF (with real Unicode/Devanagari text shaping - Hindi renders correctly, not as `?`) / JSON / CSV / CEF exports - the CSV is sectioned (indicators, findings, URLs, authentication, attachments) with spreadsheet-formula-injection neutralised, and JSON exports carry a schema version
- ✅ Live-verified Splunk HEC delivery
- ✅ Case list, single-case view, campaign/connection view, review-and-acknowledge workflow

**Investigation Workflow**
- ✅ Full-text case search across subject, sender, recipient, findings and indicators - not just a client-side filter on the summary list
- ✅ Analyst notes per case, with a live character-count hint on the verification note field
- ✅ Case ownership / assignment label for solo/small-team triage (not access control - see Q&A Cheat Sheet)

**Security Hardening**
- ✅ Content-Security-Policy, Strict-Transport-Security and Permissions-Policy headers - CSP live-verified in a real browser against the deployed app's actual map tiles, not just theoretically correct
- ✅ Dangerous URL schemes explicitly flagged instead of silently dropped: `javascript:`/`data:`/`vbscript:` at full severity (including case, whitespace and control-character obfuscation), and handler schemes (`file:`, `search-ms:`, the `ms-*` family used in Follina-style exploits) at review level
- ✅ Opt-in, IP-allowlisted trusted-reverse-proxy handling for rate-limiting - `X-Forwarded-For` is never trusted from an unrecognized direct connection, closing a spoofable-identity gap
- ✅ Mobile-responsive layout and an automated accessibility audit (`security/ACCESSIBILITY_AUDIT.md`): axe-core WCAG 2.1 A/AA clean across 12 UI states, contrast verified on 1,226 text elements (one real failure found and fixed), no horizontal overflow at 375 px. Automated audit only - not a screen-reader test or a WCAG certification
- ✅ Frontend bundle splitting - measured: a single unsplit 542 kB JS bundle became cacheable vendor chunks plus a 67 kB app chunk (total bytes are similar; the win is a small entry chunk and long-lived vendor caching, not less code)
- ✅ CycloneDX SBOMs generated for backend (85 components, from a clean install mirroring the Docker image) and frontend (59 components); `pip-audit` over all 85 backend packages (torch's CPU build is not in PyPI's advisory index and cannot be audited by pip-audit) and `npm audit` over all 102 frontend dependencies both report 0 known vulnerabilities (reproducible - see `security/README.md`)

**Engineering Quality**
- ✅ 633 automated backend tests, frontend build/lint clean (0 oxlint warnings), browser extension 3/3 test suites
- ✅ Multi-round independent AI code review on every change, with every finding logged in `security/REVIEW_REGISTER.md` - 14 entries: real bugs fixed with regression tests, plus the claims we investigated and did NOT act on (a SQLite deadlock that never reproduced, two non-bugs) and known limitations left open

### 🔜 Planned - Research-Informed Roadmap (Not Yet Built)

*Grounded in 5 papers reviewed Sept 2026: SAHF-PD (Electronics 2026), PhishTrace review (J. Cybersecur. Priv. 2026), PhishLumos (IEEE Access 2026), PAM 2025 Enterprise Phishing Networks, BEC Systematic Review (Computers & Security 2025). Full citations on Slide 6.*

**Highest-priority next additions**
- 🔜 OCR for arbitrary in-image phishing text - QR-code decoding inside image and PDF attachments is already built (see checklist above); reading free text inside images is the remaining gap
- 🔜 Selective landing-page inspection for unresolved links - isolated worker, screenshot + credential-form detection, no credentials used
- 🔜 Learned multimodal fusion model - replacing today's fixed rule-based score caps

**Foundation hardening**
- 🔜 Independent, near-duplicate-safe evaluation suite - our own training script already flags that exact-dedup alone doesn't catch template-level near-duplicates; next step is campaign/source-held-out benchmarks
- 🔜 Calibrated probability scores (Brier score, reliability diagrams) - today's states are distinct, but the score itself stays uncalibrated
- 🔜 Evidence-linked explanations - stable finding IDs that reference exact source location
- 🔜 Persistent, cross-session network-behavior history - today's version compares within the current session's stored cases only

**Additional roadmap items**
- 🔜 India-specific curated brand/UPI reference set for impersonation detection (the similarity-check mechanism already exists; the curated list doesn't ship by default)
- 🔜 Multilingual / code-mixed phishing *detection* (Hindi + regional languages) - export rendering already handles Devanagari correctly; the ML classifier itself is still English-trained
- 🔜 Broader adversarial-robustness testing (paraphrase attacks - beyond today's truncation-shift, homoglyph and zero-width coverage)
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
- Case ownership/assignment is a triage label, not real access control.

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
