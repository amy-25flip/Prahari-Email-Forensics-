# Email authentication notes

SPF uses pyspf with explicit connecting IP, envelope MAIL FROM and HELO from receiver logs. These inputs remain analyst-supplied, not independently trusted. Arbitrary Authentication-Results headers cannot establish a pass.

DKIM checks up to four signatures on submitted bytes. Pasted emails are also checked: valid signatures can pass, but unsuccessful pasted checks remain inconclusive because copying can change signed content. Original .eml upload remains preferable. Unknown alignment is shown as not established. DMARC assesses current DNS, not delivery-time DNS. DNS outages do not add failure penalties.

IP enrichment uses HTTPS ipwho.is, public addresses only, bounded results and caching. Locations identify approximate infrastructure, not people. OpenStreetMap tiles are optional and include attribution; the local atlas is the offline fallback. Public provider availability and production terms require review.

The evidence score remains a grouped heuristic, not a calibrated fraud probability. A separate provisional review policy escalates corroborated warning signs without inflating the numeric score. Original evidence, decisions and explanations are retained in case records and PDF/JSON exports.
