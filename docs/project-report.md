# PRAHARI - Technical Report

**Team:** Cache-Me-Maybe | **PS:** SIH26106 - AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform | **Theme:** Blockchain & Cybersecurity | **Category:** Software

Status of this document: describes the prototype as it exists in this repository. Every figure is either measured (source given) or explicitly marked. Requirement-by-requirement status against the problem statement is in `docs/acceptance-matrix.md`; the submitted idea deck is `presentation/PRAHARI_SIH26106_submission.pdf`.

## 1. Problem and approach
Phishing and business-email-compromise (BEC) are the dominant entry point for enterprise breaches; a filter that only blocks a message leaves the analyst without the evidence needed to attribute infrastructure, link campaigns, or support a legal process. PRAHARI treats a suspicious email as a **forensic case**: it classifies the content, cryptographically checks who sent it, traces the relay infrastructure, correlates it with other cases, and stores the result in a tamper-evident log that can be exported to a SOC. Design principle: report what the evidence supports, label uncertainty, never invent an attacker identity.

## 2. Architecture
- **Backend:** Python / FastAPI. One analysis pipeline (`engine.analyze`) is reached by four entry points - `.eml` upload, pasted raw source, Gmail Pub/Sub push, and a browser extension - so results are identical regardless of arrival path.
- **Frontend:** React + Vite dashboard: case list, relay map, evidence tabs, cross-case evidence graph, conversation-BEC and network-history panels, review/notes/assignment workflow, redacted and masked exports.
- **Storage:** session-scoped SQLite, hash-chained event log, optional Fernet field encryption, configurable retention.
- **Extension:** Manifest V3 "Gmail Guard" shows an in-page risk banner using the same backend.

Pipeline: parse headers/body/attachments -> SPF/DKIM/DMARC/ARC -> BERT + AI-manipulation scan -> URL and attachment analysis (incl. QR decoding in images and PDFs) -> relay map and IP/domain intelligence -> conversation and network-history context -> attribution confidence -> campaign correlation -> hash-chained store -> export.

## 3. Detection
- **NLP classifier:** `bert-base-uncased` fine-tuned by the team on 356,836 rows deduplicated to 335,264 (exact-normalized duplicates and label conflicts removed). Held-out test split of 33,527 emails: **99.32% accuracy, 0.49% false-positive rate** (`training/output/phishing-bert-v1/final/training_report.json`). Caveat: exact-dedup random split; a campaign- or near-duplicate-held-out benchmark has not been run.
- **Truncation-evasion hardening:** the model sees 256 tokens; padding an email pushed the payload out of view. Inference now slides overlapping windows over the whole message (max 8) and takes the worst window. On the team's own attack script (100 held-out phishing emails): **0/100 detected before, 95/100 after**.
- **AI-manipulation detection:** hidden prompt-injection content (CSS-hidden text, zero-width characters, HTML comments) and instruction-like phrasing, also matched against a homoglyph-normalized copy so Cyrillic look-alikes do not evade it; separate raw-vs-normalized model-probability delta flags evasion attempts.
- **Authentication-aware fusion:** a scary-looking message from a DKIM/DMARC-aligned sender is not escalated on content alone.
- **Rules:** credential pressure, payment diversion, verification avoidance, executive-payment cues; deceptive-domain, display-name and link-mismatch checks.
- **Quishing and image-only phishing:** QR codes in image attachments and on the first two PDF pages are decoded (OpenCV; PDF pages rasterized with pypdfium2 at bounded resolution, tolerant fallback decoders). Text in the same images and pages is read by OCR (RapidOCR/ONNX, English/Latin script only, models shipped in the wheel; at most 3 images/pages and 12 s per message) and analysed like body text - rules, language check, link extraction and the classifier - while the stored body is unchanged. OCR is an aid, not proof.
- **Conversation-aware BEC:** mid-thread payment/UPI-ID changes, reply-to domain swaps and thread anomalies, matched by Message-ID/References with a conservative fallback.
- **Language coverage:** script/language detection (Devanagari and other scripts, Hinglish, code-mixed); when text is outside the English model's validated coverage the UI and playbook say so, and transparent Hindi/Hinglish rules for credential pressure, payment diversion and verification avoidance apply. Keyword heuristics, not a multilingual model.
- **Attachments:** hashes, executable/PDF-action/macro/encryption markers, a YARA-style declarative rule set (HTML smuggling, macro auto-exec, RTF objects, `.lnk`, encoded droppers, double extensions, RTL-override names) and archive checks for zip-slip, zip-bomb ratios and nesting - static only, nothing executed.
- **URLs:** structural checks, PhishTank feed matching, `javascript:`/`data:`/`vbscript:` flagged at full severity, `file:`/`search-ms:`/`ms-*` handler schemes at review level.

## 4. Authentication and origin
Full SPF, DKIM, DMARC (RFC 9989, including subdomain policy) and ARC (RFC 8617) verification against live DNS. Relay hops are always labelled "header-reported; receiver trust not established" unless an HMAC receiver attestation bound to the original bytes is supplied, in which case an "earliest reliable node" is distinguished from the claimed chain. Geolocation (ISP/ASN/location), Tor-exit matching, AbuseIPDB hosting/proxy/VPN classification and RDAP/DNS domain intelligence describe **infrastructure, not a person**.

## 5. Evidence and attribution
- **Attribution confidence:** transparent 0-100 weighted score; nine positive factors intentionally sum to 110 and are capped at 100, penalties for Tor/proxy/new-domain/conflicts/failed ARC, hard cap of 20 when origin is undetermined. Validated against a 17-scenario labelled matrix (17/17 in the expected band, 13/13 ordering checks; `benchmarks/attribution_validation_matrix.md`). This validates ordering, not calibration - it is not a probability.
- **Campaign correlation:** shared reply-address/URL/attachment-hash/thread indicators plus a hybrid body-similarity stack (character-shingle Jaccard, TF-IDF cosine, SimHash). Strong agreement can group cases; moderate agreement only draws a context-only link. Thresholds are heuristic, tuned on a small fixture set.
- **Cross-case evidence graph:** typed nodes (case, sender, domain, relay IP, URL, attachment hash, reply-to, thread) with per-link `strong`/`context_only` confidence.
- **Analyst guidance and exchange:** a per-case, evidence-triggered next-step playbook; STIX 2.1 export of adverse indicators only (TLP:AMBER, no message content; validated with the reference stix2 library, not yet tested against a live MISP); a one-click electronic-evidence support pack (manifest, hashes, custody trail, draft declaration for a human signer - support material, not a certificate).
- **Cross-session memory:** a keyed-HMAC-hashed indicator ledger (no raw values, no case content, demo samples excluded, 90-day default retention) surfaces indicators seen in earlier analyses across sessions; informational only.
- **Landing pages:** analyst-triggered static inspection of one linked page (forms, password fields, cross-domain posts, brand cues) with SSRF hardening - public hosts only, DNS pinned, redirects re-validated, size and time caps enforced during the read, TLS verified, no JavaScript. Not a rendered screenshot.
- **Custody:** SHA-256 hash-chained event log with an independent verify; optional OpenTimestamps anchoring of the chain head into Bitcoin (a pending proof is created immediately; confirmation takes hours; a real demo proof is confirmed in Bitcoin block 968372, independently verified against a public block explorer); supports, but does not issue, a BSA 2023 s.63 certificate.

## 5b. Alerts before interaction, roles and audit
- **Pre-delivery gateway (opt-in):** an SMTP endpoint (aiosmtpd) analyses each message before any mailbox, delivers clean mail with X-PRAHARI headers, and holds urgent or score-60+ mail in a quarantine with hold/release/discard logged in the audit chain. Analysis exceptions hold the message; capacity/storage failures answer SMTP 451 so the sender retries. Proven over real SMTP in tests and in the running app. It is a gateway model for an institution's own mail flow, not a Gmail interception.
- **Inside Gmail:** the extension's banner, plus a click-time confirmation dialog once a high-risk verdict is installed (best effort, not a security boundary). Optional Gmail label/quarantine actions (reversible; never delete/trash/send; needs gmail.modify) are unit-tested against a fake Gmail service and were tried by hand on a live Gmail account by the team (manual check, not in the automated suite).
- **Roles (opt-in, `ROLE_TOKENS`):** per-person bearer tokens with viewer/analyst/admin roles enforced on every route (unknown writes default to admin), shared authenticated workspace, per-person rate limits, actor-stamped audit events (chain still verifies), and a four-eyes rule. Application-level access control, not SSO or legal identity.

## 6. Privacy, security and engineering
- DPDP-conscious exports: Aadhaar (Verhoeff-validated), PAN, UPI and Indian mobile numbers masked; optional email masking; per-export masking summary (counts only); redacted mode. Best-effort, not certified DLP.
- Hardening: CSP and Permissions-Policy on every response, HSTS when HTTPS is asserted, spoof-resistant proxy trust for rate limiting (allowlisted IPs/CIDRs, multi-hop chain verification), per-session and per-peer limits, decompression/pixel-count bounds, CSV formula-injection neutralisation.
- Supply chain: CycloneDX SBOMs (backend 96 components, frontend 59); `pip-audit` over a clean install mirroring the Docker image (96 packages) and `npm audit`: 0 known vulnerabilities (torch's CPU build cannot be scanned by pip-audit).
- Review process: independent, partly AI-assisted review passes with every finding logged, including non-bugs and unfixed limits, in `security/REVIEW_REGISTER.md`.
- Accessibility: automated axe-core WCAG 2.1 A/AA audit clean across 12 UI states, contrast verified on 1,226 text elements, no horizontal overflow at 375 px (audit predates the Investigator leads panel and the Primary class chip) (`security/ACCESSIBILITY_AUDIT.md`); not a screen-reader test.

## 7. Evaluation (measured)
| Metric | Result | Source |
|---|---|---|
| Backend automated tests | 808 passing | `pytest backend -q -p no:cacheprovider` |
| ML accuracy / false-positive rate | 99.32% / 0.49% on 33,527 held-out emails | `training_report.json` |
| Truncation-evasion detection | 0/100 -> 95/100 | team attack script re-run |
| Local analysis latency (BERT loaded, no enrichment) | ~70-75 ms median, p95 ~90 ms (re-measured 2026-09-25) | `benchmarks/` (2 x 100 runs) |
| Live enrichment latency | median 4.0 s for the first request in a fresh process; median 1.9 s for later new domains with feeds warm (worst 4.0 s); median 50.5 ms fully cached (measured 2026-09-25, no paid-API keys) | `benchmarks/live_enrichment_timing.json` |
| Attribution matrix | 17/17 scenarios, 13/13 orderings | `benchmarks/attribution_validation_matrix.md` |
| Gmail Guard, Splunk HEC | live-verified against a real Gmail account and a real Splunk Enterprise collector | `docs/development-log.md` |
| Frontend | lint clean (oxlint); production build clean, app chunk 81.8 kB plus vendor/map chunks | build output, 2026-09-25 |

## 8. Limitations (stated, not hidden)
Infrastructure location is not attacker location. 99.32% is a held-out figure, not a real-world guarantee, and no campaign-held-out benchmark exists yet. The classifier is English-trained. Gmail Guard depends on Gmail's private page markup. Case assignment is a label, not access control. OCR reads English/Latin script only. Roles are per-person tokens, not SSO. Gmail label/quarantine actions are verified against a fake service only, and the click-time warning is best effort. Campaign thresholds are heuristic. The Docker image has not been built on this machine (no Docker); dependency resolution for its target platform was verified separately.

Configuration of the optional features (all off unless set, except the ledger and OCR): `ROLE_TOKENS`, `FOUR_EYES`, `GATEWAY_SMTP_PORT`/`GATEWAY_SMTP_HOST`/`GATEWAY_HOLD_SCORE`, `GMAIL_ACTION_MODE`/`GMAIL_ACTION_MIN_SCORE`, `LEDGER_ENABLED`/`LEDGER_KEY`/`LEDGER_RETENTION_DAYS`, `OCR_ENABLED`, `LANDING_INSPECT_ENABLED`.

## 9. Roadmap
OCR for Indic scripts; rendered landing-page screenshots and visual brand matching; calibrated probabilities (Brier/reliability); learned multimodal fusion; campaign/near-duplicate-held-out evaluation; multilingual and code-mixed detection; SSO/OIDC identity for roles (today: per-person tokens); analyst-feedback loop and drift monitoring.

## 10. References
RFC 7208 (SPF), RFC 6376 (DKIM), RFC 9989 (DMARC), RFC 8617 (ARC), RFC 5322; Devlin et al., BERT (2019); OpenTimestamps; BSA 2023 s.63; FBI IC3 reports; CERT-In/PIB 2025 incident data; SAHF-PD (Electronics 2026), PhishTrace review (J. Cybersecur. Priv. 2026), PhishLumos (IEEE Access 2026), PAM 2025 enterprise phishing networks, BEC systematic review (Computers & Security 2025). Full citations:
- Yuan et al., "LLM-Based Multimodal Feature Extraction and Hierarchical Fusion for Phishing Email Detection," *Electronics* 2026, 15(2):368. https://doi.org/10.3390/electronics15020368
- Laleb, Le & Nguyen, "Digital Forensics and Phishing Defense: A Literature Review and Gap Analysis," *J. Cybersecur. Priv.* 2026, 6(4):116. https://doi.org/10.3390/jcp6040116
- Chiba, Nakano & Koide, "PhishLumos: From a Single URL to Campaign-Level Phishing Mitigation," *IEEE Access* 2026. https://doi.org/10.1109/ACCESS.2026.3696597
- Luo et al., "Characterizing the Networks Sending Enterprise Phishing Emails," PAM 2025.
- Almutairi, Kang & Alhashimy, "Business email compromise: A systematic review of understanding, detection, and challenges," *Computers & Security* 158 (2025) 104630. https://doi.org/10.1016/j.cose.2025.104630
- CERT-In cyber-incident data 2025 (PIB): https://www.pib.gov.in/PressReleasePage.aspx?PRID=2244504&lang=1&reg=3

## Addendum 2026-09-25: PS-wording gaps and independent evaluation

Added: curated brand lookalike / display-name spoofing checks (`brands.py`), known-bad relay infrastructure feeds (`known_bad.py`: abuse.ch Feodo, Spamhaus DROP; open relay
not detected), gateway-signed receiver receipts (`GATEWAY_RECEIPT_KEY`), investigator leads from RDAP (`leads.py`), and a documented five-class decision table
(`classification.py`, not a trained model). Independent evaluation (`benchmarks/external_evaluation.md`): 98% recall on 150 phishing messages from a 2025 public corpus, but a
37% false-positive rate on 300 legitimate 2003 messages (mostly promotional newsletters); the five-class table catches 33% of that real phishing as phishing/fraud/impersonation, with 23 false positives in 300 legitimate messages, despite 0.91 accuracy on hand-written synthetic fixtures. Investigator leads are now live-checked against public RDAP; gateway receipts remain local-demo verified.
