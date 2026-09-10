# Authentication and review checkpoint

> For the latest September 10 implementation and test status, see CURRENT_STATUS.md and SECURITY_CHECKPOINT.md. Historical test totals and SIEM limitations below are superseded by those documents. Original Google .eml verification is still pending.

SPF uses pyspf with explicit connecting IP, envelope MAIL FROM and HELO from receiver logs. These inputs remain analyst-supplied, not independently trusted. Arbitrary Authentication-Results headers cannot establish a pass.

DKIM checks up to four signatures on submitted bytes. Pasted emails are also checked: valid signatures can pass, but unsuccessful pasted checks remain inconclusive because copying can change signed content. Original .eml upload remains preferable. Unknown alignment is shown as not established. DMARC assesses current DNS, not delivery-time DNS. DNS outages do not add failure penalties.

IP enrichment uses HTTPS ipwho.is, public addresses only, bounded results and caching. Locations identify approximate infrastructure, not people. OpenStreetMap tiles are optional and include attribution; the local atlas is the offline fallback. Public provider availability and production terms require review.

The evidence score remains a grouped heuristic, not a calibrated fraud probability. A separate provisional review policy escalates corroborated warning signs without inflating the numeric score. Original evidence, decisions and explanations are retained in case records and PDF/JSON exports.

Verification: 77 backend tests passed, frontend build/lint passed, desktop/mobile workflow checks passed. A small 64-row NLP diagnostic matched 62 existing labels, with one false positive and one false negative. Label quality and overlap with pretrained training data are unknown; these are not production accuracy results.

Remaining: original Google email investigation, trusted receiver ingestion, independently adjudicated real-email validation, live-map acceptance, actual SIEM delivery, SBOM/security audit and public deployment. Optional email-agent features are deferred. No claim of universal detection or production readiness.
