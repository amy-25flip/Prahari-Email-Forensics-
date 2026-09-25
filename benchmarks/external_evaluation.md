# External evaluation on independent public corpora (measured 2026-09-25)

Reproduce: `python evaluation/run_external_eval.py --download` then `python evaluation/run_external_eval.py --per-corpus 150`
(fixed seed 20260925; data is git-ignored). Nothing was tuned on these sets. The full pipeline (real BERT model) ran on every message. The held-out test command was run once after the five-class rule additions below.

**Sources:** Jose Nazario phishing corpus, `phishing-2025` mailbox (479 hand-classified phishing messages, CC-BY-4.0, attribution: Jose Nazario);
Apache SpamAssassin public corpus `20030228_easy_ham` (2,500) and `20030228_hard_ham` (250), legitimate mail. 150 random messages per corpus.

| Decision rule (flagged = positive) | Phishing caught (of 150) | Legitimate wrongly flagged (of 300) | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|---|
| Model label = phishing | 147 | 111 (easy 12, hard 99) | 0.570 | 0.980 | 0.721 | 0.370 |
| Evidence score >= 25 | 146 | 119 (easy 31, hard 88) | 0.551 | 0.973 | 0.704 | 0.397 |
| Evidence score >= 45 | 40 | 24 (easy 6, hard 18) | 0.625 | 0.267 | 0.374 | 0.080 |
| Gateway hold (urgent or score >= 60) | 8 | 5 (easy 1, hard 4) | 0.615 | 0.053 | 0.098 | 0.017 |
| Five-class primary in {phishing, fraud-related, impersonated} | 49 | 23 (easy 2, hard 21) | 0.681 | 0.327 | 0.441 | 0.077 |
| Five-class primary not legitimate/undetermined | 147 | 204 | 0.419 | 0.980 | 0.587 | 0.680 |

**What this shows, honestly:**
- The model flags almost all 2025 phishing (98% recall) but also flags 37% of 2003 legitimate mail, mostly the *hard ham* (mailing-list and
  newsletter-style messages: 99/150). The 99.32% held-out figure comes from the same distribution as training and must not be read as
  real-world accuracy. The two classes here differ in era and source, so the false-positive rate is partly an era/style mismatch, but it is
  still a real limitation, not something to explain away.
- The five-class table now catches 33% (49 of 150) of these real phishing messages as phishing/fraud/impersonation, up from the earlier 5%, but the cost is real: 23 legitimate messages were threat-classed, 21 of them from hard ham. Treat the five-class output as a review hypothesis, not an automatic verdict. Its 0.91 accuracy on synthetic fixtures still does not transfer cleanly.
- The most defensible use today: the score/model as a review-priority signal with high recall and a substantial false-positive burden, plus evidence labels that explain why a case was raised.

**Caveats:** class separation may reflect era/header style rather than intent; the legitimate mail is 2003-era; the phishing is one person's
inbox; no training-overlap check was possible (training corpus not stored here); samples are small.

**Operating points.** The high-recall review queue (score >= 25) is what produces the large false-positive count. The gateway's hold rule
(urgent or score >= 60) keeps false positives near 2% but catches only 5% of this phishing on its own, because most messages are scored by the
model alone (30 points) and no rule corroborates them strongly enough to hold.

**Why the false positives are not fixed by a simple rule.** On a separate dev split (100 unused hard-ham messages, 100 easy_ham_2, 150 phishing-2024) the
false positives were promotional newsletters (CNET, Motley Fool, sweepstakes) with model probabilities of 99%+. Raising the model threshold
(90 -> 99.5) still flags 22% of that hard ham while losing recall, and list/bulk headers do not separate them from phishing. The real fix is
retraining with modern legitimate newsletters as negatives. What was changed: the case view labels such cases "model-only signal" when no rule
corroborates it, so an analyst does not read them as a verdict. Nothing was tuned on the test sample.

**Five-class rule additions (developed on a separate dev split, then measured once here).** Generic file-share, mailbox/voicemail/delivery-failure,
invoice/payment and identity-mismatch lures were added with guardrails: link evidence is required, authenticated senders are not threat-classed by these lure rules alone, and authentication/identity context decides whether the hypothesis is phishing, fraud-related or impersonated. On this 2025 test sample, threat-class recall rose to 33% (49/150) with 23 false positives in 300 legitimate messages. It is no longer a rare-false-alarm mode: precision is about 68%.
