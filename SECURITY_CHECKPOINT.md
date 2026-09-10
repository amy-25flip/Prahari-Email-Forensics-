# Security and Dependency Checkpoint

Date: 2026-09-10

The active local runtime is the project's .venv, not global Python. Global Python was not upgraded or removed. Backend requirements now match the tested project environment. Model loading is offline, with remote-code trust disabled and safetensors required.

## Audits

- Python runtime closure: 53 installed packages. pip-audit 2.10.1 reported no known vulnerabilities in the updated inventory.
- Frontend package lock: npm audit reported zero known vulnerabilities.
- Backend CycloneDX SBOM generated with cyclonedx-bom 7.3.1 from the complete installed runtime requirements closure.
- Frontend CycloneDX SBOM generated from package-lock.json with npm sbom.

The initial global runtime inventory reported 16 vulnerability entries in eight packages. The project environment already contained newer library versions; requirements and the demo launcher were aligned to it, with the missing pyspf dependency installed. Audits are point-in-time advisory checks, not proof of absence of vulnerabilities. Model weights, OS packages, and a future Linux container image require separate review. The Windows runtime lock is an inventory, not a portable Linux lockfile. Original model training data, licensing suitability, and model provenance require review before distribution.

## Application Controls

- Original byte preservation, hash-chained evidence events, session isolation and no-store API responses.
- Configurable RETENTION_HOURS from 1 to 168 (default 24); new sessions inherit the setting. Existing sessions retain their creation-time expiry.
- Upload byte limit, 15-second body-read timeout, analysis concurrency cap, per-session analysis limit and per-peer mutation limit.
- Peer rate limiting does not trust client-supplied forwarding headers. A reverse proxy must enforce its own correctly configured client limits; in-app limits are single-process and aggregate requests sharing one visible IP.
- Security headers on HTML and API responses. Cookies use HttpOnly and SameSite=Strict; production HTTPS requires COOKIE_SECURE=1.
- Optional external enrichment sends only public IPs and sender domains, not message bodies. Registry personal contact information is not collected.
- SIEM is explicitly initiated and sends only minimal metadata to an administrator-configured destination.

## Remaining Security Boundaries

No automatic trusted mailbox ingestion is configured. Uploaded Authentication-Results and Received headers remain untrusted. Downloadable session checkpoints detect changed history and tail truncation when compared against an intact separately retained copy. They are not independently notarized, signed or timestamped; an attacker controlling both copies defeats this comparison. Session expiration also removes the evidence required for comparison. SQLite evidence is not application-level encrypted; use OS/storage encryption and access restrictions. Deletion does not guarantee physical erasure from SSDs or backups. There is no malware sandbox, complete attachment-content scanner, general prompt-injection filter, or guaranteed actor attribution.
