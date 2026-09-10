---
title: AI Email Threat Detection
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8000
pinned: false
---

# sih26106-email-forensics

AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform (AICTE PS #26106).

See `CURRENT_STATUS.md`, `PS_ACCEPTANCE.md` and `PS_PROGRESS.md` for what's implemented and what isn't.
See `SELECTION_README.md` for how to run it locally.

## Deployment

Deployed as a Hugging Face Space (Docker SDK) using the root `Dockerfile` — the YAML block above is
Spaces' required metadata header (`sdk: docker`, `app_port: 8000` matching the app's exposed port).
Free-tier Spaces give 16GB RAM (vs. typical PaaS free tiers around 512MB), which comfortably fits the
BERT model + PyTorch runtime. Free tier still sleeps after inactivity and has no persistent storage by
default, so case history does not survive a restart unless Spaces' paid persistent-storage add-on
(mounted at `/data`, matching this app's existing `DATA_DIR=/data`) is enabled later.
