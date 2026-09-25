# PRAHARI live demo script (about 4 minutes)

**Setup (before you go on stage):**
- Backend on `http://127.0.0.1:8010`, frontend on `http://localhost:5173` (see the repo README or the two commands the team used). Open the site once and confirm the header shows the model as ready.
- Use only the three built-in samples (Analyze page, samples list). They were run against the current build on 2026-09-25 and behave as below. **Do not paste real newsletters or marketing mail on stage**: the classifier flags many of them (37% on our external test), so it is the one demo that can go wrong.
- Turn external enrichment ON only if the network is reliable. Live enrichment takes about 1 to 3 seconds (about 3 s for the very first request). If the Wi-Fi is bad, leave it off and say "local checks only".
- Have the Gmail Guard banner open in a real Gmail tab as a backup screenshot.

| Step | Sample | What you should see | What to say |
|---|---|---|---|
| 1 | **Account verification request** | Score 75, High, priority Urgent, primary class **phishing** (high confidence), model 100%, findings: Reply-To differs, suspicious URL, credential pressure | "One suspicious email in. Watch it become a case: not just a score, but why." Point at the findings list and the primary-class chip. |
| 2 | Same case, Evidence tab | Authentication, relay hops, geo-map, attribution confidence, investigator leads (if enrichment is on) | "We trace the infrastructure and say how far to trust it. We never name a person; the leads panel tells an officer who to send a takedown or legal request to." |
| 3 | **Changed invoice instructions** | Score 55 Review, priority Urgent, primary class **fraud-related**, findings: payment diversion, verification avoidance | "Different attack, no phishing link: a payment-change scam. The classifier and rules agree it is fraud, not just phishing." |
| 4 | **Engineering newsletter** | Score 0, Low, primary class **legitimate** | "And a normal email is left alone: we don't cry wolf on clean mail." (This is a safe legitimate example, unlike a real marketing newsletter.) |
| 5 | Evidence graph tab | Cases linked by shared indicators (strong vs context-only links) | "Related emails are linked into campaigns by shared indicators. This is the part a single-email scanner cannot do." |
| 6 | Export the PDF (or JSON) | Masked export with hashes | "Every case is hash-chained and Bitcoin-anchored, exported with Aadhaar / PAN / UPI masked." Mention the confirmed proof in block 968372 only if asked. |
| 7 (optional) | Gateway | Quarantine screen with a held message | "Optionally the same engine sits in front of a mail server and holds high-risk mail before any mailbox." |

**Say out loud (don't wait to be asked):** "Our classifier scored 99.32% on its own held-out split, but on an independent 2025 phishing set it caught 98% and it also flags 37% of old promotional newsletters. That is why flagged cases go to analyst review, and retraining with modern legitimate mail is our next step."

**If something breaks:** switch to screenshots; say "the network was unavailable, so the app shows 'unavailable' rather than guessing" (true: every external check degrades to an explicit unavailable state).

**Do not claim:** open-relay detection; naming the sender; a trained five-class model; deployment in a container (unless the Docker build has been done); a real institutional mail-server validation of the gateway.
