# External evaluation on independent public corpora (measured 2026-09-25)

Reproduce: `python evaluation/run_external_eval.py --download` then `python evaluation/run_external_eval.py --per-corpus 150`
(fixed seed 20260925; data is git-ignored). Nothing was tuned on these sets. The full pipeline (real BERT model) ran on every message.

**Sources:** Jose Nazario phishing corpus, `phishing-2025` mailbox (479 hand-classified phishing messages, CC-BY-4.0, attribution: Jose Nazario);
Apache SpamAssassin public corpus `20030228_easy_ham` (2,500) and `20030228_hard_ham` (250), legitimate mail. 150 random messages per corpus.

| Decision rule (flagged = positive) | Phishing caught (of 150) | Legitimate wrongly flagged (of 300) | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|---|
| Model label = phishing | 147 | 111 (easy 12, hard 99) | 0.570 | 0.980 | 0.721 | 0.370 |
| Evidence score >= 25 | 146 | 119 (easy 31, hard 88) | 0.551 | 0.973 | 0.704 | 0.397 |
| Evidence score >= 45 | 40 | 24 (easy 6, hard 18) | 0.625 | 0.267 | 0.374 | 0.080 |
| Gateway hold (urgent or score >= 60) | 8 | 5 (easy 1, hard 4) | 0.615 | 0.053 | 0.098 | 0.017 |
| Five-class primary in {phishing, fraud-related, impersonated} | 8 | 1 (easy 1, hard 0) | 0.889 | 0.053 | 0.101 | 0.003 |
| Five-class primary not legitimate/undetermined | 147 | 199 | 0.425 | 0.980 | 0.593 | 0.663 |

**What this shows, honestly:**
- The model flags almost all 2025 phishing (98% recall) but also flags 37% of 2003 legitimate mail, mostly the *hard ham* (mailing-list and
  newsletter-style messages: 99/150). The 99.32% held-out figure comes from the same distribution as training and must not be read as
  real-world accuracy. The two classes here differ in era and source, so the false-positive rate is partly an era/style mismatch, but it is
  still a real limitation, not something to explain away.
- The five-class table catches only 5% (8 of 150) of these real phishing messages, though it now rarely misfires on legitimate mail (1 of 300) as phishing/fraud/impersonation. Its rules fire on explicit
  credential/payment wording and lookalike brands; real 2025 phishing (short lures, attachment/link-only, non-English) mostly does not
  match them, so they land in *suspicious* through the model. The 0.91 accuracy on our synthetic fixtures does not transfer.
- The most defensible use today: the score/model as a review-priority signal with high recall and a substantial false-positive burden, not an automatic verdict.

**Caveats:** class separation may reflect era/header style rather than intent; the legitimate mail is 2003-era; the phishing is one person's
inbox; no training-overlap check was possible (training corpus not stored here); samples are small.

**Operating points.** The high-recall review queue (score >= 25) is what produces the large false-positive count. The gateway's hold rule
(urgent or score >= 60) keeps false positives near 2% but catches only 5% of this phishing on its own, because most messages are scored by the
model alone (30 points) and no rule corroborates them.

**Why the false positives are not fixed by a rule.** On a separate dev split (100 unused hard-ham messages, 100 easy_ham_2, 150 phishing-2024) the
false positives were promotional newsletters (CNET, Motley Fool, sweepstakes) with model probabilities of 99%+. Raising the model threshold
(90 -> 99.5) still flags 22% of that hard ham while losing recall, and list/bulk headers do not separate them from phishing. The real fix is
retraining with modern legitimate newsletters as negatives. What was changed: the case view now labels such cases "model-only signal" (no rule
corroborates it) so an analyst does not read them as a verdict. Nothing was tuned on the test sample.

**Five-class rule additions (developed on a separate dev split, then measured once here).** Two generic cues seen in 2024 phishing were added:
Latin/look-alike-character mixing in display names (for example `Wеllsfаrgo Bank`) and password-expiry / undelivered-mail lures with a link from a sender that
is not DMARC-authenticated. On the dev split (150 phishing-2024, 200 legitimate) this lifted threat-class recall to 21% (32/150) with 1 false positive in 200 (measured before a later change that requires an urgency cue for expiry lures and corroboration for QR links, which lowers recall slightly); on this
2025 test sample the gain is smaller (5%), because these lures are less common in that year's mailbox. The classifier itself is unchanged, so the 37% newsletter false-positive rate stands.
