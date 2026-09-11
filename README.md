# sih26106-email-forensics

AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform (AICTE PS #26106).

See `CURRENT_STATUS.md`, `PS_ACCEPTANCE.md` and `PS_PROGRESS.md` for what's implemented and what isn't.
See `SELECTION_README.md` for how to run it locally.

## Deployment

Configured for deployment to Render (free tier) via `render.yaml` and the root `Dockerfile` -- not yet
deployed live (deprioritized by explicit user instruction; local demo is the actual submission
requirement, see `PS_PROGRESS.md`). Render's free tier has no persistent disk, so `/data` (case
history, PhishTank cache) will not survive a redeploy or idle-recycle once deployed. Hugging Face Spaces was
considered but ruled out: as of this project's build, Spaces' Docker SDK requires a paid plan — only
Static Spaces (no backend execution at all) and a limited free Gradio/ZeroGPU allowance are free, neither
of which can run this app's FastAPI backend. Render's free tier (512MB RAM) is a real out-of-memory risk
for the BERT model plus PyTorch runtime — mitigated with `low_cpu_mem_usage=True` on model load, but not
eliminated. This needs to be observed empirically once deployed, not assumed to work.
