# Problem Statement Implementation Checkpoint

2026-09-10. This file supersedes earlier remaining-work lists in CURRENT_STATUS.md for the additions below. Hosting remains deferred.

## Added in This Pass

- Candidate campaign grouping from exact URLs, reply addresses, attachment hashes and message/reply thread IDs. Shared sender addresses, domains and reported public IPs are shown as context but cannot alone create a campaign. Duplicate raw emails and mixed demo/live pairs are excluded. Groups are session-local and recomputed after case deletion; they are not confirmed campaigns.
- Full/redacted export toggle covering PDF, JSON, CSV and CEF. The allowlisted redacted projection removes content, identities, headers, links, attachments and infrastructure details. Case ID, timestamp and original hash remain linkable. Stored originals are unchanged. Redacted CSV intentionally contains no indicators.
- Static executable signatures, PDF action markers, ZIP directory macro/encryption checks. No attachments are executed or decompressed. These are suspicious-content checks, not malware verdicts.
- Duplicate/malformed header checks, relay timestamp reversal checks and display-name email-address mismatch detection. Clock skew, forwarding and legitimate unusual formats remain possible explanations.
- Hybrid threat categories from the existing binary model plus explicit rules; not a trained multiclass model. Categories and origin hypotheses have visible limitations. Supplemental findings escalate routine/incomplete triage to review without artificially changing the evidence score.
- Exact-IP Tor exit snapshot correlation with fresh/stale/unavailable states. Source: https://check.torproject.org/torbulkexitlist. Live retrieval returned 1,335 IPs during verification. No message data is sent to this list provider. Historical Tor use is not established by a current list match; VPN/open-relay/botnet coverage is not implemented.
- Session analyst hold/approval decisions with required notes, server-side acknowledgement for elevated findings, and hash-chained review events. Alerts are visible before recording approval. No email delivery, quarantine, mailbox monitoring or release is performed; there is no independently authenticated reviewer identity.

## Verification

- 118 backend tests passed; frontend build and lint passed.
- Browser tests passed for review acknowledgement/approval, masked JSON download, checkpoint roundtrip, campaign grouping and desktop/mobile overflow checks.
- The local demo runs at http://127.0.0.1:8012 using the project's .venv.
- Build retains a non-failing JavaScript chunk-size warning. Tests retain a Starlette test-client deprecation warning.

## Still Incomplete Against Full PS Coverage

1. Independently trusted receiver boundary and earliest reliable source identification. Analyst-supplied SMTP context remains conditional, not independently verified.
2. Broader deceptive-brand/lookalike and executive-impersonation coverage; validated category quality and comprehensive obfuscated-URL/BEC evaluation.
3. Broader VPN/open-relay/botnet intelligence and hosting fingerprints. Current coverage is DNS/RDAP, ISP/ASN and Tor snapshot matching.
4. Reliable, validated confidence-based infrastructure attribution. Current origin confidence is undetermined and compromise flags are hypotheses.
5. Full acceptance testing on independently adjudicated real emails, including the missing original Google .eml, false-positive assessment and end-to-end latency measurement.

External collector verification, container review and hosting are still pending separately. Optional agent gateway and sandbox expansion remain deferred. This checkpoint does not claim full PS completion or production readiness.

## Added 2026-09-10 (second pass): attribution confidence, IP/attachment reputation, deployment config

- **Attribution confidence engine** (`backend/attribution.py`): a transparent 0-100 score over eight weighted evidence factors (receiver attestation, SPF/DKIM/DMARC alignment, domain registration age, header-conflict absence, IP-reputation availability, geolocation availability) minus four penalties (Tor match, hosting/proxy/VPN classification, newly registered domain, header conflicts). Every factor is listed whether it applied or not, so the score is auditable. Hard-capped at 20/100 whenever origin evidence is undetermined, regardless of other signals — no combination of secondary evidence can substitute for a trusted origin. This is a weighted transparency score, not a calibrated statistical probability or proof of actor identity; it answers "how much should an investigator trust this email's origin evidence," which is a distinct question from the existing evidence/fraud score.
- **IP reputation intelligence** (`backend/ip_reputation.py`, AbuseIPDB, opt-in, requires `ABUSEIPDB_API_KEY`): per-hop usage-type classification (hosting/proxy/VPN/ISP), abuse-confidence score, Tor flag, total reports. Extends origin traceability beyond the existing Tor-exit-list-only coverage toward the PS's "VPN, open relay, botnet" correlation ask — still limited to what AbuseIPDB's community reports capture, not a dedicated VPN/botnet detector.
- **Attachment hash reputation** (`backend/attachment_reputation.py`, VirusTotal, opt-in, requires `VIRUSTOTAL_API_KEY`): looks up existing attachment SHA-256 hashes against VirusTotal's multi-engine verdicts. Capped at 4 lookups per analysis (VirusTotal free-tier rate limit); uncapped attachments are explicitly marked `not_checked`, never silently treated as clean. Only a hash is sent, never file content — still no dynamic/sandboxed execution.
- Both new modules follow the existing enrichment convention exactly (gated by the same `enrich`/`live` flag, `requests`-based, explicit timeouts, in-memory TTL cache, never raise to the caller, absent API key degrades to `status: disabled`) and are exposed in `/api/health` as `ip_reputation.configured`/`attachment_reputation.configured`.
- Frontend: new dedicated `AttributionConfidence` panel (score, band, full factor breakdown, caveats) plus `ip_reputation`/`attachment_reputation` sections added to the existing threat-assessment panel.
- `render.yaml` added for Docker-based deployment to Render with a persistent `/data` disk and env vars for the new and existing optional integrations (marked `sync: false` so secrets are entered in the Render dashboard, never committed).
- Verification: 169 backend tests passed (148 existing + 21 new covering disabled/no-network, missing-key, rate-limit, cache-hit and score-bounds behavior for all three new modules); frontend build and lint passed; local end-to-end smoke test via the built app confirmed the new panels render correctly on a real fixture with no crashes, including the all-disabled (no API keys configured yet) path.

## Still incomplete after this pass

1. **API keys not yet configured** — `ABUSEIPDB_API_KEY`/`VIRUSTOTAL_API_KEY` need to be obtained and set before IP/attachment reputation produce live data; until then they report `disabled`, which is the intended safe default, not a bug.
2. **Git history is behind the working tree** — most backend modules (including everything added in the first 2026-09-10 pass) and recent frontend/Dockerfile changes were never committed. This must be resolved before any GitHub-based deployment (e.g. Render) will actually deploy current code.
3. Signed/timestamped checkpoints, SQLite at-rest encryption, automated mailbox ingestion, and malware sandboxing remain out of scope, per the acceptance status above — not attempted in this pass.
4. Public deployment itself (Render) is configured (`render.yaml`, Dockerfile) but not yet executed. `render.yaml` targets Render's **free** tier (512MB RAM) by cost constraint — BERT-base plus PyTorch overhead realistically needs closer to 1GB, so this is a real risk of out-of-memory crashes under load, mitigated only by `low_cpu_mem_usage=True` on model load (reduces the loading-time memory spike, not steady-state usage). Free tier also has no persistent disk, so `/data` (case history, PhishTank cache) does not survive a redeploy and may not survive Render recycling an idle instance — this needs to be observed empirically once deployed, not assumed. If it doesn't hold up, the fallback is a paid Standard instance (~$25/mo, 2GB RAM) or further model memory optimization (quantization), neither attempted yet.
5. Validation against a real phishing `.eml` (e.g. the originally referenced Google email) is still pending.
