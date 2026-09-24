# Attribution confidence - validation matrix

Each scenario is a hand-built evidence set with the band an analyst would expect, decided from
the evidence before running the engine. This checks that the hand-set weights produce the
*intended ordering and banding*. It does not calibrate the score into a probability - the
engine's own policy string says so.

Bands: low < 35, moderate 35-69, high >= 70. Weights sum to 110 and the score is capped at 100 by design.

**Result: 17/17 scenarios in the expected band; 13/13 ordering checks hold.**

| ID | Scenario | Expected | Actual | Score | Match | Factors applied |
|---|---|---|---|---|---|---|
| S01 | Receiver-attested, fully authenticated, old domain, clean IP, valid ARC | high | high | 100 | yes | +receiver_attested, +spf_aligned, +dkim_aligned, +dmarc_pass, +domain_registration, +no_header_conflicts, +ip_reputation_available, +geolocation_available, +arc_chain_valid |
| S02 | Same as S01 plus a Tor exit match | high | high | 85 | yes | +receiver_attested, +spf_aligned, +dkim_aligned, +dmarc_pass, +domain_registration, +no_header_conflicts, +ip_reputation_available, +geolocation_available, +arc_chain_valid, -tor_exit_match |
| S03 | Receiver-attested, nothing else known | moderate | moderate | 35 | yes | +receiver_attested |
| S04 | Authenticated + old domain + clean IP, but no receiver attestation (headers only) | moderate | moderate | 65 | yes | +spf_aligned, +dkim_aligned, +dmarc_pass, +domain_registration, +no_header_conflicts, +ip_reputation_available, +geolocation_available |
| S05 | S04 plus a Tor exit match | moderate | moderate | 40 | yes | +spf_aligned, +dkim_aligned, +dmarc_pass, +domain_registration, +no_header_conflicts, +ip_reputation_available, +geolocation_available, -tor_exit_match |
| S06 | S04 but the sender domain is newly registered | moderate | moderate | 45 | yes | +spf_aligned, +dkim_aligned, +dmarc_pass, +no_header_conflicts, +ip_reputation_available, +geolocation_available, -newly_registered_domain |
| S07 | S04 plus two header/relay conflicts | moderate | moderate | 35 | yes | +spf_aligned, +dkim_aligned, +dmarc_pass, +domain_registration, +ip_reputation_available, +geolocation_available, -header_conflicts |
| S08 | Origin undetermined: everything else perfect | low | low | 20 | yes | +spf_aligned, +dkim_aligned, +dmarc_pass, +domain_registration, +no_header_conflicts, +ip_reputation_available, +geolocation_available, +arc_chain_valid |
| S09 | Origin undetermined, Tor + hosting IP + new domain + failed ARC | low | low | 0 | yes | +spf_aligned, +dkim_aligned, +dmarc_pass, +no_header_conflicts, +ip_reputation_available, +geolocation_available, -tor_exit_match, -hosting_or_proxy_ip, -newly_registered_domain, -arc_chain_failed |
| S10 | No evidence at all | low | low | 0 | yes | (none) |
| S11 | Header chain usable, but unauthenticated and nothing else | low | low | 15 | yes | +no_header_conflicts, +geolocation_available |
| S12 | Receiver-attested but with two header conflicts | low | low | 15 | yes | +receiver_attested, -header_conflicts |
| S13 | Receiver-attested but reported node is hosting/proxy infrastructure | low | low | 30 | yes | +receiver_attested, +ip_reputation_available, -hosting_or_proxy_ip |
| S14 | Forwarded mail: DKIM aligned + valid ARC + clean chain + geo (BOUNDARY: scores exactly 35, the low/moderate cutoff) | moderate | moderate | 35 | yes | +dkim_aligned, +no_header_conflicts, +geolocation_available, +arc_chain_valid |
| S15 | S01 with a failed ARC chain instead of a valid one | high | high | 85 | yes | +receiver_attested, +spf_aligned, +dkim_aligned, +dmarc_pass, +domain_registration, +no_header_conflicts, +ip_reputation_available, +geolocation_available, -arc_chain_failed |
| S16 | Receiver-attested, authenticated, new domain, hosting IP, Tor match | moderate | moderate | 40 | yes | +receiver_attested, +spf_aligned, +dkim_aligned, +dmarc_pass, +no_header_conflicts, +ip_reputation_available, +geolocation_available, -tor_exit_match, -hosting_or_proxy_ip, -newly_registered_domain |
| S17 | S14 without geolocation (just under the cutoff) | low | low | 30 | yes | +dkim_aligned, +no_header_conflicts, +arc_chain_valid |

## Ordering checks (stronger evidence must score strictly higher)

| Check | Holds |
|---|---|
| S01 (100) > S03 (35) | yes |
| S01 (100) > S04 (65) | yes |
| S04 (65) > S05 (40) | yes |
| S04 (65) > S06 (45) | yes |
| S04 (65) > S07 (35) | yes |
| S03 (35) > S12 (15) | yes |
| S03 (35) > S13 (30) | yes |
| S04 (65) > S11 (15) | yes |
| S01 (100) > S15 (85) | yes |
| S01 (100) > S16 (40) | yes |
| S16 (40) > S13 (30) | yes |
| S04 (65) > S08 (20) | yes |
| S01 (100) > S02 (85) | yes |

Known boundary: S14 scores exactly 35, the low/moderate cutoff; S17 (same, minus geolocation) falls just below. Reproduced by `backend/test_attribution_matrix.py`.
