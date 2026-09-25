# PRAHARI - Technical Report

**Team:** Cache-Me-Maybe | **PS:** SIH26106 - AI-Powered Email Threat Detection, Geo-Location and Forensic Intelligence Platform | **Theme:** Blockchain & Cybersecurity | **Category:** Software

Status of this document: describes the prototype as it exists in this repository. Every figure is either measured (source given) or explicitly marked. Requirement-by-requirement status against the problem statement is in `PS_ACCEPTANCE.md`; slide copy is in `PPT_DATA_WINNING.md`.

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
- **Quishing:** QR codes in image attachments and on the first two pages of PDFs are decoded (OpenCV; PDF pages rasterized with pypdfium2 at bounded resolution, tolerant fallback decoders) and scored as ordinary links.
- **Conversation-aware BEC:** mid-thread payment/UPI-ID changes, reply-to domain swaps and thread anomalies, matched by Message-ID/References with a conservative fallback.
- **Attachments:** hashes, executable/PDF-action/macro/encryption markers, a YARA-style declarative rule set (HTML smuggling, macro auto-exec, RTF objects, `.lnk`, encoded droppers, double extensions, RTL-override names) and archive checks for zip-slip, zip-bomb ratios and nesting - static only, nothing executed.
- **URLs:** structural checks, PhishTank feed matching, `javascript:`/`data:`/`vbscript:` flagged at full severity, `file:`/`search-ms:`/`ms-*` handler schemes at review level.

## 4. Authentication and origin
Full SPF, DKIM, DMARC (RFC 9989, including subdomain policy) and ARC (RFC 8617) verification against live DNS. Relay hops are always labelled "header-reported; receiver trust not established" unless an HMAC receiver attestation bound to the original bytes is supplied, in which case an "earliest reliable node" is distinguished from the claimed chain. Geolocation (ISP/ASN/location), Tor-exit matching, AbuseIPDB hosting/proxy/VPN classification and RDAP/DNS domain intelligence describe **infrastructure, not a person**.

## 5. Evidence and attribution
- **Attribution confidence:** transparent 0-100 weighted score; nine positive factors intentionally sum to 110 and are capped at 100, penalties for Tor/proxy/new-domain/conflicts/failed ARC, hard cap of 20 when origin is undetermined. Validated against a 17-scenario labelled matrix (17/17 in the expected band, 13/13 ordering checks; `benchmarks/attribution_validation_matrix.md`). This validates ordering, not calibration - it is not a probability.
- **Campaign correlation:** shared reply-address/URL/attachment-hash/thread indicators plus a hybrid body-similarity stack (character-shingle Jaccard, TF-IDF cosine, SimHash). Strong agreement can group cases; moderate agreement only draws a context-only link. Thresholds are heuristic, tuned on a small fixture set.
- **Cross-case evidence graph:** typed nodes (case, sender, domain, relay IP, URL, attachment hash, reply-to, thread) with per-link `strong`/`context_only` confidence.
- **Analyst guidance and exchange:** a per-case, evidence-triggered next-step playbook; STIX 2.1 export of adverse indicators only (TLP:AMBER, no message content; validated with the reference stix2 library, not yet tested against a live MISP); a one-click electronic-evidence support pack (manifest, hashes, custody trail, draft declaration for a human signer - support material, not a certificate).
- **Custody:** SHA-256 hash-chained event log with an independent verify; optional OpenTimestamps anchoring of the chain head into Bitcoin (a pending proof is created immediately; confirmation takes hours; a real demo proof is confirmed in Bitcoin block 968372, independently verified against a public block explorer); supports, but does not issue, a BSA 2023 s.63 certificate.

## 6. Privacy, security and engineering
- DPDP-conscious exports: Aadhaar (Verhoeff-validated), PAN, UPI and Indian mobile numbers masked; optional email masking; per-export masking summary (counts only); redacted mode. Best-effort, not certified DLP.
- Hardening: CSP and Permissions-Policy on every response, HSTS when HTTPS is asserted, spoof-resistant proxy trust for rate limiting (allowlisted IPs/CIDRs, multi-hop chain verification), per-session and per-peer limits, decompression/pixel-count bounds, CSV formula-injection neutralisation.
- Supply chain: CycloneDX SBOMs (backend 85 components, frontend 59); `pip-audit` over a clean install mirroring the Docker image and `npm audit`: 0 known vulnerabilities (torch's CPU build cannot be scanned by pip-audit).
- Review process: independent review passes (Codex/GPT, Antigravity) with every finding logged, including non-bugs and unfixed limits, in `security/REVIEW_REGISTER.md`.
- Accessibility: automated axe-core WCAG 2.1 A/AA audit clean across 12 UI states, contrast verified on 1,226 text elements, no horizontal overflow at 375 px (`security/ACCESSIBILITY_AUDIT.md`); not a screen-reader test.

## 7. Evaluation (measured)
| Metric | Result | Source |
|---|---|---|
| Backend automated tests | 645 passing | `pytest backend` |
| ML accuracy / false-positive rate | 99.32% / 0.49% on 33,527 held-out emails | `training_report.json` |
| Truncation-evasion detection | 0/100 -> 95/100 | team attack script re-run |
| Local analysis latency (BERT loaded, no enrichment) | ~50-65 ms median, p95 < 80 ms | `benchmarks/` (2 x 100 runs) |
| Live enrichment latency | ~1.1-1.4 s first lookup; ~35 ms cached | `benchmarks/enrichment_timing.json` |
| Attribution matrix | 17/17 scenarios, 13/13 orderings | `benchmarks/attribution_validation_matrix.md` |
| Gmail Guard, Splunk HEC | live-verified against a real Gmail account and a real Splunk Enterprise collector | `PS_PROGRESS.md` |
| Frontend | lint clean (oxlint), bundle 542 kB unsplit -> vendor chunks + 67 kB app chunk | build output |

## 8. Limitations (stated, not hidden)
Infrastructure location is not attacker location. 99.32% is a held-out figure, not a real-world guarantee, and no campaign-held-out benchmark exists yet. The classifier is English-trained. Gmail Guard depends on Gmail's private page markup. Case assignment is a label, not access control. No OCR of free text inside images. Network history is session-scoped. Campaign thresholds are heuristic. The Docker image has not been built on this machine (no Docker); dependency resolution for its target platform was verified separately.

## 9. Roadmap
OCR for in-image text; selective landing-page inspection; calibrated probabilities (Brier/reliability); learned multimodal fusion; campaign/near-duplicate-held-out evaluation; multilingual and code-mixed detection; RBAC; persistent cross-session indicator history; analyst-feedback loop and drift monitoring.

## 10. References
RFC 7208 (SPF), RFC 6376 (DKIM), RFC 9989 (DMARC), RFC 8617 (ARC), RFC 5322; Devlin et al., BERT (2019); OpenTimestamps; BSA 2023 s.63; FBI IC3 reports; CERT-In/PIB 2025 incident data; SAHF-PD (Electronics 2026), PhishTrace review (J. Cybersecur. Priv. 2026), PhishLumos (IEEE Access 2026), PAM 2025 enterprise phishing networks, BEC systematic review (Computers & Security 2025) - full citations in `PPT_DATA_WINNING.md`.
