# Five-class decision table: evaluation on synthetic fixtures

**What this is:** `backend/classification.py` is a deterministic decision table (precedence documented in its docstring) over the
existing model, authentication and rule evidence. It is **not a trained five-class model**, and the classes are review hypotheses.

**What it was measured on:** 75 hand-written **synthetic** messages (15 per class) in `backend/five_class_fixtures.py`, run with the
real pipeline and the real BERT model (`python backend/run_five_class.py`). They are not real mail and not independent of the
author; results show the table behaves as designed on these cases, not real-world accuracy. Hard negatives are included
(legitimate bank/KYC notices, authenticated senders).

| Class | Recall | Precision | n |
|---|---|---|---|
| legitimate | 10/15 (0.67) | 10/11 (0.91) | 15 |
| suspicious | 13/15 (0.87) | 13/16 (0.81) | 15 |
| impersonated | 15/15 (1.00) | 15/15 (1.00) | 15 |
| phishing | 15/15 (1.00) | 15/16 (0.94) | 15 |
| fraud_related | 15/15 (1.00) | 15/15 (1.00) | 15 |

Overall accuracy: 68/75 = 0.907.

**Known misses (kept, not tuned away):** the model raises "high phishing probability" on three genuine-style notices (HDFC statement,
GitHub sign-in, SBI transaction alert), which the table demotes to *suspicious* rather than *phishing* because a model score alone never
decides phishing; a legitimate Paytm KYC reminder trips the "Credential pressure" wording rule and is called *phishing*; one bland
"business opportunity" spam and one webinar invite come back legitimate/undetermined because nothing adverse fires.
