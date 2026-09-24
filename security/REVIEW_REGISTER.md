# Independent review register

Every finding below came from an independent review pass (Codex/GPT, or the Antigravity AI review) and was checked against the real code before acting. "Not a bug" and "known limitation" entries are kept on purpose - an honest register lists what we did NOT fix and why.

| # | Source | Finding | Severity | Verdict | Resolution / regression test |
|---|---|---|---|---|---|
| 1 | Codex round 2 | `tokens_covered` overstated coverage for sliding-window inference (reported 698 tokens for a 500-token message) | Medium | Real | Fixed; `test_tokens_covered_*` in `backend/test_local_model.py` |
| 2 | Codex round 2 | CSP `style-src 'self'` would likely break Leaflet/React inline styling | Medium | Real | `style-src 'self' 'unsafe-inline'`; `script-src` kept strict; `test_csp_header_present_on_every_response` |
| 3 | Codex round 2 | `TRUSTED_PROXY_HOPS` alone trusted `X-Forwarded-For` from any direct connection | Medium | Real | Added `TRUSTED_PROXY_IPS` allowlist, fails closed; `test_peer_identity_ignores_xff_from_an_untrusted_direct_peer_even_with_hops_set` |
| 4 | Codex final review | Security-header middleware duplicated across `boundary()` and `response_security()` | Low | Real | Consolidated into `response_security()` |
| 5 | Codex final review | "New investigation" reset React state but not the file input's DOM value (re-selecting the same .eml did nothing) | Low | Real | Fixed in `App.jsx` |
| 6 | Codex final review | Multi-hop `X-Forwarded-For` chains are only verified at the direct peer, not per hop | Low | Real, deferred | Not fixed: correct for the single-proxy deployment; per-hop CIDR validation is the next step |
| 7 | Codex PPT review | Latency claim had no backing artifact | - | Real | Measured; `benchmarks/` (engine-only and full API path, 100 runs each) |
| 8 | Codex PPT review | SBOM component counts conflated with pip-audit dependency counts; HSTS claimed unconditionally; Splunk "account" wording; accuracy claim lacked near-duplicate caveat | - | Real | Corrected in `PPT_DATA_WINNING.md` |
| 9 | Antigravity | Claimed SQLite self-deadlock in `store.add_note()` | Critical (claimed) | Not reproduced | 20-thread concurrent stress test never deadlocked; redundant second DB connection removed as hardening only |
| 10 | Antigravity | DNS TXT records decoded with strict ASCII (non-ASCII record could raise mid-authentication) | Low | Real | `errors='replace'` in `authentication.py` |
| 11 | Antigravity | Missing `set_seed(42)` in training | - | Not a bug | Hugging Face `TrainingArguments` already defaults `seed=42` |
| 12 | Antigravity | DMARC walk queries `_dmarc.<TLD>` | - | Not a bug | Intentional: RFC 9989 allows public-suffix (`psd`) DMARC records |
| 13 | Antigravity | "Attribution weights balanced to 100" | - | Inaccurate claim | Weights intentionally sum to 110 and are capped at 100; documented + `test_all_nine_positive_factors_applied_still_caps_at_exactly_100` |

Known limitations we did not fix: multi-hop proxy chain verification (#6); case ownership is a free-text label, not access control; Gmail Guard depends on Gmail's private page markup.
