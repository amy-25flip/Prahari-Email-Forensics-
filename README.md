# PRAHARI

AI-powered email threat detection, geolocation and forensic intelligence platform, built by team Cache-Me-Maybe for Smart India Hackathon problem statement 26106 (AICTE Cyber Security Cell).

PRAHARI takes a suspicious email (`.eml`, pasted source, Gmail, or an SMTP gateway) and turns it into an investigation case: sender authentication (SPF, DKIM, DMARC, ARC), phishing and social-engineering detection, lookalike-domain and brand checks, relay tracing with geolocation and reputation matching, attribution confidence, campaign correlation, and a hash-chained evidence trail with an optional Bitcoin timestamp anchor. Cases export to PDF, JSON, CSV, CEF, STIX 2.1 and Splunk, with Indian identifiers (Aadhaar, PAN, UPI, mobile) masked.

It locates email infrastructure, not people. Scores and classes are review aids for an analyst, not verdicts. See [`docs/acceptance-matrix.md`](docs/acceptance-matrix.md) for what is built against the problem statement, what is not, and the measured limits.

## Layout

| Path | What is in it |
|---|---|
| `backend/` | FastAPI app (`main.py`), analysis engine (`engine.py`), detectors, evidence store, tests (`test_*.py`) |
| `frontend/` | React + Vite analyst interface |
| `browser-extension/` | Gmail Guard, a Chrome (MV3) extension that shows the risk banner inside Gmail |
| `training/` | Model fine-tuning and evaluation scripts (checkpoints are not in git) |
| `evaluation/` | Harness for testing on public email corpora that were not used in training |
| `benchmarks/` | Latency, attribution and evaluation results with the scripts that produced them |
| `security/` | SBOMs, audit output, accessibility audit, review register |
| `demo/` | Bitcoin timestamp proof, demo script, pipeline diagram |
| `docs/` | Requirement status, project report, protocol notes |
| `presentation/` | Submission deck copy and templates |

## Run locally

Requirements: Python 3.12+ (3.14 is what we develop on), Node 22.

```bash
python -m venv .venv
.venv/Scripts/pip install torch --index-url https://download.pytorch.org/whl/cpu
.venv/Scripts/pip install -r backend/requirements.txt
.venv/Scripts/pip install --no-deps rapidocr==3.9.2
```

Backend (port 8010; 8000 is left free for a local Splunk):

```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8010
```

Frontend (Vite proxies `/api` to the backend):

```bash
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open the URL Vite prints. `npm run build` produces a bundle the backend serves on the same origin. API docs are at `/docs`.

**Model.** The classifier is a BERT model we fine-tuned. The checkpoint is large and not stored in git: put it at `training/output/phishing-bert-v1/final/` or set `MODEL_ID`. Without it the app falls back to the public `ealvaradob/bert-finetuned-phishing` model, which must be downloaded once (inference uses local files only). If no model is available the app says so instead of inventing a score.

Optional integrations (all off by default, configured through environment variables): VirusTotal and AbuseIPDB keys, Gmail push, Splunk HEC, role tokens (`ROLE_TOKENS`), the SMTP gateway (`GATEWAY_SMTP_PORT`). Enrichment lookups only run when enabled per analysis, and every external check degrades to an explicit "unavailable".

## Tests

```bash
python -m pytest backend -q        # about 4-5 minutes
cd frontend && npx oxlint src && npm run build
cd browser-extension && node test-extension.cjs
```

## Demo

Analyze the three built-in samples (newsletter, account verification, changed invoice) from the Investigate page, then open Connections to see related cases linked. `demo/DEMO_SCRIPT.md` has a timed walkthrough.

## Deployment

The `Dockerfile` and `render.yaml` describe a same-origin container deployment. The image has not been built or deployed yet, so treat it as a recipe rather than a verified deployment. If you deploy it: mount persistent storage at `/data`, serve over HTTPS with `COOKIE_SECURE=1`, run a single worker at first (the model is loaded per process), and configure request limits and storage quotas at the host.

## Known limits

- The classifier flags many promotional newsletters as phishing (about 37% of a 2003 legitimate-mail sample in our external test). Flagged cases go to analyst review; retraining with modern legitimate mail is the next step. Details in `benchmarks/external_evaluation.md`.
- The five-class classification is a documented decision table over model, authentication and rule evidence, not a trained model.
- Open-relay detection is not offered (it needs active probing). Sender identity is never named: investigator leads name the registrar and network owners to contact.
- The SMTP gateway is a model for an organisation's own mail flow, not an interception of Gmail.

Full detail: `docs/acceptance-matrix.md` and `docs/project-report.md`.
