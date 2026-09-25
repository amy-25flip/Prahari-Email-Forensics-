# Security artifacts - how to reproduce

| Artifact | Command (run from repo root) |
|---|---|
| Python dependency audit | build a clean venv (`pip install torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu`, then `pip install -r backend/requirements.txt`, then `pip install --no-deps rapidocr==3.9.2` - rapidocr hard-depends on the full opencv-python, which would clash with the pinned headless build), then `pip_audit --path <venv>/Lib/site-packages -f json -o security/python-audit-updated.json` - auditing a dev venv instead is misleading (it includes tooling that does not ship) |
| Frontend dependency audit | `cd frontend && npm audit --json > ../security/npm-audit.json` |
| Backend SBOM (CycloneDX) | `cyclonedx-py environment .venv/Scripts/python.exe -o security/backend-sbom.cdx.json` (use a clean venv matching requirements.txt) |
| Frontend SBOM (CycloneDX) | `cd frontend && npx @cyclonedx/cyclonedx-npm --output-file ../security/frontend-sbom.cdx.json` |

Scope, stated honestly: dependency audits only catch vulnerabilities already published in advisory databases - not zero-days, and not flaws in our own code. Last run: 2026-09-25 - pip-audit over a CLEAN venv mirroring the Dockerfile (CPU torch, requirements.txt, then rapidocr installed --no-deps): 96 packages audited, 0 known vulnerabilities (torch's `+cpu` build is not on PyPI, so pip-audit skips it); npm audit: 102 frontend dependencies, 0 known vulnerabilities.
See `REVIEW_REGISTER.md` for findings from independent code reviews.

