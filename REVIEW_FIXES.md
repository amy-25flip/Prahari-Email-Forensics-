# Review fixes - 2026-09-11

## Implemented

- Attachment hash reputation now contributes findings, evidence score and triage before saving the
  report. One adverse engine verdict adds 15 reputation points; at least three malicious verdicts
  add 60 and require urgent review. Reputation is capped at 60, total score at 100. This is a heuristic,
  not a calibrated probability or a confirmed malware verdict. Unknown/unavailable/zero-positive
  lookups do not establish safety. Only hashes belonging to this report are considered.
- VirusTotal requests share a thread-safe process-wide sliding-minute quota (default four), honor
  server Retry-After backoff, reuse cached results and avoid concurrent duplicate hash requests.
  VIRUSTOTAL_REQUESTS_PER_MINUTE may be changed to match an authorized plan. A four-uncached-lookup
  per-analysis budget remains. Multiple worker processes do not share this limiter; use one worker
  or implement a distributed limiter before scaling out. Requests do not follow redirects with keys.
- Attribution now reads actual header/routing checks, deduplicates repeated warnings and awards no
  missing-evidence bonus. Missing domain age is not positive evidence. Attribution is heuristic,
  not statistically calibrated identity confidence.
- URL scoring separates contextual account/redirect wording from suspicious evidence. Redirects
  between subdomains of the same registrable domain do not by themselves add risk; deceptive
  destinations, insecure targets and separate private-suffix tenants remain detectable.
- Ready-model labels benign and legitimate both map to the legitimate category when no findings
  contradict them. An unavailable model does not establish legitimacy.
- Gmail Guard caches successful results only, retries failures, restores banners after DOM replacement,
  respects urgent triage, preserves raw bytes and handles non-default Gmail account paths.

## Verification

- Backend: 189 tests passed, including attachment findings, saved-report integrity and shared quota.
- Extension: three Node regression tests passed; isolated synthetic browser scenario passed.
- Frontend production build and lint passed. Build retains a non-blocking large-bundle warning.

## Not established by these fixes

- Live Gmail end-to-end behavior and cross-context session cookies remain unverified.
- The pretrained NLP model can still produce false positives. These changes remove an incorrect
  URL contribution; they do not retrain or calibrate the model or guarantee a zero score for Google.
- SPF requires trusted receiver context; DKIM requires original bytes and available DNS. Unknown
  authentication must not be changed to pass merely because a message appears official.
- No hosting deployment, model training or new optional feature expansion was performed.
