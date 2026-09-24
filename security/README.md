# Security artifacts - how to reproduce

| Artifact | Command (run from repo root) |
|---|---|
| Python dependency audit | `.venv/Scripts/python.exe -m pip_audit --local -f json -o security/python-audit-updated.json` |
| Frontend dependency audit | `cd frontend && npm audit --json > ../security/npm-audit.json` |
| Backend SBOM (CycloneDX) | `cyclonedx-py environment .venv/Scripts/python.exe -o security/backend-sbom.cdx.json` (use a clean venv matching requirements.txt) |
| Frontend SBOM (CycloneDX) | `cd frontend && npx @cyclonedx/cyclonedx-npm --output-file ../security/frontend-sbom.cdx.json` |

Scope, stated honestly: dependency audits only catch vulnerabilities already published in advisory databases - not zero-days, and not flaws in our own code. Last run: 2026-09-24 - pip-audit: 141 installed Python packages (runtime + test tooling), 0 known vulnerabilities; npm audit: 102 frontend dependencies, 0 known vulnerabilities.
See `REVIEW_REGISTER.md` for findings from independent code reviews.

Known gap: the backend CycloneDX SBOM (`backend-sbom.cdx.json`) was generated before `pypdfium2` (PDF QR detection) was added to `requirements.txt`; regenerate it from a clean venv with the command above before final submission. See also `ACCESSIBILITY_AUDIT.md`.
