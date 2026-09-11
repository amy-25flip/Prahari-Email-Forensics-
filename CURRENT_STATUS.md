# Prototype Acceptance Status

Date: 2026-09-10. Local entry point: backend/main.py. Use the project .venv. Hosting is deliberately deferred until local acceptance work is finished.

**This is the oldest of the three status docs (110 tests, pre-attribution-engine).** `PS_PROGRESS.md`
explicitly supersedes it, and `PS_ACCEPTANCE.md` is the current authoritative acceptance matrix (231
tests, as of 2026-09-11). Read those two first; this file is kept as a historical snapshot of what was
true on 2026-09-10, not a current status. In particular, every item below describing exact-match-only
campaign correlation, hash-only attachment reputation with no dynamic execution, or checkpoints with no
independent timestamping/encryption is now out of date -- see `PS_PROGRESS.md`'s 2026-09-11 entries for
fuzzy campaign correlation, VirusTotal sandbox upload, ARC chain verification, OpenTimestamps blockchain
checkpoint anchoring, and at-rest field encryption, all added after this file was last dated.

## Implemented and Tested

- Original .eml upload and pasted email parsing; local BERT classification; grouped evidence score and separate analyst-review priority.
- Sender/reply mismatch checks, BEC language patterns, URL structure checks and current/stale PhishTank matching.
- SPF using supplied SMTP context; DKIM verification including qualified pasted-input behavior; DMARC current-DNS alignment with explicit unknown states.
- Public-IP geolocation, ISP/ASN metadata, relay map and offline fallback. OpenStreetMap tiles visually verified in the browser.
- Sender-domain MX, NS, A and AAAA records; IANA-bootstrapped registry RDAP metadata, including registration date and registrar when available. Live google.com lookup verified.
- Evidence Conflict Detector, case search/history, shared-indicator connections, PDF/JSON/CSV and CEF exports, hash-chain verification.
- Splunk HTTPS HEC and Wazuh JSON-log connectors with explicit send controls and minimal payloads. Local file and real mock-HTTPS tests passed. (Stale: Splunk HEC has since been verified against a real live collector, not just mocks — see PS_PROGRESS.md's 2026-09-11 fourth-pass entry. Wazuh remains unverified against a live server.)
- Configurable retention, peer rate limits, upload time/size limits, security headers, dependency inventories and CycloneDX SBOMs.

Verification: 110 backend tests passed using the project runtime. Frontend production build and lint passed. Browser checks covered analysis, evidence integrity, PDF export, connections and desktop/mobile layout. Saved session checkpoints detect tail truncation against a securely retained copy; they are not independently signed or timestamped. Small prior NLP diagnostic matched 62 of 64 dataset labels; unknown pretrained-data overlap prevents treating that as independent accuracy.

## Not Yet Complete

1. Original Google .eml investigation and independently adjudicated real-email testing. The raw Google email has since been provided and tested (see PS_PROGRESS.md's 2026-09-11 third-pass entry) -- this line is now stale; broader real-email testing beyond that one message is still pending.
2. Trusted receiver ingestion for establishing a reliable relay boundary. Current path observations are explicitly unverified; the system cannot reliably identify a human actor from raw headers alone.
3. Dedicated VPN/Tor/open-relay/botnet intelligence. Tor exit-list matching plus opt-in AbuseIPDB usage-type/abuse-score classification (`ABUSEIPDB_API_KEY`) now cover hosting/proxy/VPN signal as community-reported classification; open-relay and botnet-specific coverage remains unavailable.
4. Broader sender/domain/IP campaign correlation and calibrated attribution assessment. Campaign correlation is still exact-match only (shared reply addresses, exact URLs and attachment hashes). A calibrated attribution-confidence engine now exists (`backend/attribution.py`): a transparent, weighted 0-100 score over eight evidence factors, hard-capped at low confidence whenever origin evidence is undetermined — it scores trust in available evidence, not actor identity.
5. Complete attachment threat analysis and a validated multi-class threat taxonomy. Current BERT is binary; attachments are inventoried and extension-flagged, not malware-scanned. Opt-in VirusTotal hash reputation (`VIRUSTOTAL_API_KEY`, capped at 4 lookups per analysis) now adds multi-engine verdicts for known-hash attachments; this is still not dynamic/sandboxed execution and an unknown hash is not a clean verdict.
6. Automated mailbox/pre-delivery alert ingestion. Current workflow is analyst-driven upload/paste, not an email gateway.
7. Richer masking controls and independent checkpoint custody. Downloadable checkpoint comparison, retention and minimal SIEM/CEF output exist; exports of full reports may contain personal data.
8. Real Wazuh/Splunk ingestion verification, public deployment, container/host security review, and final demo/PPT/PS acceptance review.

The optional email-to-agent action gateway and injection research features remain deferred. This status does not claim the full problem statement is complete or provide a percentage-based readiness guarantee.
