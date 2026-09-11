# AI-Powered Email Threat Detection

> Historical setup notes. For the September 10 verified feature list and outstanding work, use CURRENT_STATUS.md, SECURITY_CHECKPOINT.md and SIEM_CONFIGURATION.md. SIEM connectors, configurable retention, request limits, domain intelligence and saved evidence checkpoints now exist. Use the project .venv rather than global Python. The older limitations below describe the earlier checkpoint, not the current acceptance status.

This update extends the existing FastAPI/React project. The entry point is `backend/main.py`. The older Flask experiment (`backend/app.py` and its `analyzer.py`/`dkim_checker.py`/`url_scanner.py`/`ml_classifier.py` dependencies) was never used by this release and has been deleted (2026-09-11) after confirming nothing referenced it; the selection API uses `engine.py`.

## Run Locally

Install `backend/requirements.txt` in a Python environment. CPU PyTorch is sufficient for inference. Download the model once with Hugging Face `snapshot_download('ealvaradob/bert-finetuned-phishing')`; runtime uses local files only. No model training or corpus modification is part of this update.

Backend: from `backend`, run `python -m uvicorn main:app --host 127.0.0.1 --port 8000`.

Frontend: from `frontend`, run `npm ci`, then `npm run dev -- --host 127.0.0.1`. Vite proxies `/api` to port 8000. Open the URL printed by Vite. Start backend before opening the frontend.

Build the frontend with `npm run build`, then restart the backend. FastAPI serves the built frontend on the same origin, so no localhost URL is embedded in the deployed application. Auto-docs are at `/docs`.

## What Works

- Original-byte .eml upload, raw email paste, three labeled fixtures.
- Process-cached local pretrained BERT; missing model is shown explicitly, without made-up confidence.
- MIME parsing, structural URL analysis, display-link mismatch detection, attachment hashes, and grouped risk evidence.
- DKIM verification against current DNS when enrichment is enabled and original bytes are available.
- Conservative DMARC pass through aligned verified DKIM and an observed DMARC record. SPF remains unknown without trustworthy receiver/envelope context.
- Opt-in HTTPS public-IP geolocation; no email body transmission to an AI API.
- Private browser session, SQLite case history, shared-indicator graph, PDF/JSON/CSV exports.
- Original evidence and report hashes, transactional audit chain, integrity verification and deletion.

## Demo

Analyze the newsletter fixture, then the account-verification and invoice fixtures. Open Connections: the latter two share a reply address. Every fixture is processed by the same pipeline and is visibly labeled. Documentation IPs have no real geographic attribution. Upload a real .eml and opt into enrichment to attempt real infrastructure lookup. APIs can return unavailable.

## Hosting

The Dockerfile builds a same-origin app and downloads model artifacts at image-build time. It is a deployment recipe, not proof of a completed cloud deployment. Build and smoke-test the image before publishing. Mount private persistent storage at `/data`; require HTTPS and set `COOKIE_SECURE=1`. Use one worker initially to avoid duplicating the model. Benchmark RAM/CPU requirements; do not choose an undersized free service without testing cold start and memory.

Before a public URL is submitted, configure host-level request/body/time limits and IP-based rate limiting, total storage quotas, and scheduled expiration cleanup (current expiration runs when requests arrive). Session rate limiting is not a substitute for these controls. Do not enable proxy header trust for arbitrary clients. Review the model/provider licenses and deployment account terms. Request logs should exclude bodies and cookies.

## Honest Limitations

This release uses a pretrained model, not the team's retrained dataset model. Its probabilities are uncalibrated and its first 512 tokens are analyzed. Independent accuracy/latency evaluation is pending.

The risk score is a grouped heuristic, not a fraud probability. No header trust boundary has been configured: all relay paths are unverified header reports, not a human sender's location. SPF is not fully verified. Missing authentication is not failure. Current DNS is not historical DNS.

PhishTank URL reputation uses a periodically refreshed local cache. Only exact normalized URL matches count; absence from the feed is not a clean verdict. Feed timestamps, stale status, and match provenance are retained with each report. No email URLs are sent to the feed provider. Brand-directory matching, full malware scanning, pre-delivery blocking, and SIEM delivery are not implemented. No phishing drill was performed. Graph relationships are candidate connections, not confirmed campaigns. Fixture and uploaded analyses are visible only inside the current session.

Audit verification detects alteration relative to the current local log. It cannot prove integrity after an attacker rewrites the entire log or truncates its tail. No independent signed checkpoint is configured. PDF core fonts replace unsupported characters; JSON is the lossless report. Session data expires after 24 hours; background maintenance purges expired sessions approximately every minute while the app is running. Secure deletion does not establish physical erasure on SSDs or backups.

Run `python -m pytest backend/test_selection.py -q` with `backend` on PYTHONPATH. Tests use temporary databases and disable model loading. Run a separate live-model smoke test before the demo.
