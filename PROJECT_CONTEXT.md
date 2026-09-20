# SIH26106 — Project Context Handoff

**Read this first if you're a fresh Claude Code session (or any AI agent, or a human) picking this project up cold.** Written 2026-09-19 specifically because the owner was about to reinstall Claude Code and didn't want to lose the accumulated context of this project. Nothing here is aspirational — every claim was fact-checked against the actual code at the time of writing.

---

## 1. What this project is

**Team:** Cache-Me-Maybe · **PS:** SIH26106 — "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform" · **Theme:** Blockchain & Cybersecurity · **Category:** Software · Smart India Hackathon 2026.

Current stage: the team cleared Terna Engineering College's internal hackathon (4 Sept 2026, 50 teams shortlisted) and is now at the **national idea-submission stage** — a 6-slide PDF evaluated by ministry/PSU subject-matter-expert reviewers, no live jury. Evaluation criteria (verbatim from the real Terna/Intellecta guidelines): clarity of problem understanding, uniqueness/innovation, technical feasibility, completeness (no template violations), and relevance/impact/scalability. **Strict 6-slide limit on the official template — exceeding it or altering the template risks outright disqualification.**

**Repo location:** `D:\sih26106` (moved here from `C:\Users\Admin\sih26106` on 2026-09-16/17 — verified fully intact after the move, one stale path in `.claude/launch.json` was found and fixed).

**GitHub remote:** `https://github.com/amy-25flip/sih26106-email-forensics`, branch `main`. Latest commit at time of writing: `22e0dc6`.

The prototype is considered **feature-complete** by the team — the current focus is final polish, submission materials, and process (not new features), unless the owner explicitly redirects.

---

## 2. What's actually built (backend: Python/FastAPI, frontend: React/Vite)

### Core detection pipeline (every email, however it arrives)
- **Team-trained BERT phishing classifier** — fine-tuned `bert-base-uncased` on 356,836 rows, deduplicated to 335,264 (21,572 exact-normalized-duplicate and label-conflicting rows removed to prevent train/test leakage — the key is the lowercased, whitespace-collapsed subject+body, so this removes *exact* overlaps, NOT fuzzy/template campaign near-duplicates; that fuzzy similarity exists only in `backend/campaigns.py`, not in the ML split). Held-out (deduped random-split) test: **99.32% accuracy, 99.28% F1, 99.96% ROC-AUC** — a deduped random-split figure, not a real-world generalization guarantee. See `training/output/phishing-bert-v1/final/training_report.json` for the real confusion matrix.
- **Full email authentication**: SPF, DKIM, DMARC, and ARC (RFC 8617) — `backend/authentication.py`, `backend/arc_verification.py`. DMARC is evaluated per **RFC 9989** (current standard, successor to RFC 7489 — `backend/authentication.py` names it explicitly in its own output).
- **Relay-path parsing & geo/infrastructure intelligence** — `backend/routing.py`, `backend/geolocation.py`. Deliberately conservative: every parsed `Received` hop is reported with `'trust': 'Header-reported; receiver trust not established'` — the project **never** claims to isolate a verified "true origin" or locate a human attacker, only infrastructure. This is a load-bearing design decision, not an oversight — don't let anyone (including a well-meaning reviewer) talk you into overclaiming here.
- **URL & attachment reputation** — `backend/reputation.py`, structural URL analysis in `backend/engine.py`'s `scan_url()`, PhishTank matching, opt-in VirusTotal hash/sandbox lookups (`backend/attachment_reputation.py`). Attachment handling is hash/reputation-based with opt-in sandbox upload — not sandbox-grade malware verdicting by default.
- **Attribution Confidence Engine** (`backend/ps_assessment.py` and related) — transparent 0–100 score, hard-capped low whenever true origin can't be verified.
- **Campaign correlation** — shared indicators plus fuzzy body-similarity clustering (character-shingle Jaccard) — `backend/campaigns.py`.
- **Tamper-evident evidence** — SHA-256 hash chaining, optional Fernet at-rest encryption, independently anchored to the **Bitcoin blockchain via OpenTimestamps** — `backend/store.py`, `backend/blockchain_timestamp.py`. Framed as supporting a **BSA 2023 Section 63** electronic-evidence certificate (India's current provision, in force since July 2024, succeeding — not identical to — IEA Section 65B), not as issuing one itself (that needs a human signatory).
- **SOC/export integration** — PDF/JSON/CSV/CEF exports with a redacted mode (`backend/privacy.py`), **live-verified Splunk HEC delivery** (`backend/siem.py`). Wazuh support exists in code but is explicitly *not* claimed as live-verified (`siem.py`'s own status string admits agent/server ingestion isn't confirmed).

### The novelty feature — AI-manipulation / prompt-injection detection
`backend/prompt_injection.py`, wired into `backend/engine.py`. Detects content crafted to manipulate an automated classifier or LLM-based analyst assistant — **not just the human reader**. Hidden instructions via invisible inline CSS (`display:none`/`visibility:hidden`/zero font-size/zero opacity) or zero-width Unicode (ZWSP, ZWNJ, ZWJ, word-joiner, BOM). 16 tuned instruction patterns, DOM-aware hidden-content walking (`_HiddenTextExtractor` class — correctly handles malformed/nested HTML via a tag-matching stack, not just a single flag). Severity-aware: ordinary invisible marketing preheader text scores zero, only an actual instruction pattern inside hidden content raises alarm. **51 dedicated tests.** Scope is deliberately narrow and stated in the code's own comments: only inline hidden-CSS styles are recognized, class-based CSS/`mso-hide`/off-screen positioning are known, intentional gaps.

This went through 3 rounds of independent Codex review during development, each finding and fixing real bugs (a stack-corruption bug in the DOM walker on mismatched HTML tags; instruction-pattern regexes that were first too broad, then too narrow).

### Real-time Gmail ingestion — two separate, independently-built paths
1. **Server-side (live-tested against a real Gmail account, confirmed working):** Google Cloud Pub/Sub pushes a notification the instant new mail lands in a watched inbox; `backend/gmail_integration.py` + `/api/gmail/push` in `backend/main.py` fetch, analyze, and store it automatically. Real case ID from a live test: `e55fd74a10e47226`.
   - Two genuine production bugs were found and fixed via live testing (not caught by the test suite alone): (a) a present-but-blank `Subject:` header wrongly rejected (Subject is legitimately optional per RFC 5322), and (b) a real Gmail API history-indexing-lag race condition (Gmail's own indexing can lag its own Pub/Sub notification by a few seconds) — fixed with a retry-then-defer mechanism (`EmptyHistoryDiff` exception, 503 response so Pub/Sub retries rather than silently losing the message).
   - A further hardening pass fixed a gap where a transient Gmail API error (5xx/429 on `fetch_raw`) got zero retries at the notification level (unlike the app's own 429s) — now retried the same way, while still failing fast on permanent errors (404, etc.).
   - Delivery is **best-effort at-least-once, not exactly-once** — and honestly so. A later hardening pass closed the last silent-loss window: a message whose in-request retries are all exhausted for a *transient* reason (our own 429, or a 5xx/429 from Gmail) is now recorded in a persistent **dead-letter queue** (`record_failed_message`/`pending_retry_message_ids` in `gmail_integration.py`) and retried on subsequent push notifications, bounded by a per-message attempt cap, even after the watermark advances past it. Genuinely permanent failures (malformed/oversized email, deleted/forbidden message) are deliberately not retried. So "live-tested, working" is accurate, but describe it as best-effort ingestion with a bounded retry/dead-letter path, not guaranteed delivery.
   - Results don't belong to any one analyst's browser session, so they surface in a dedicated **"Gmail Alerts" tab** in the frontend (`frontend/src/GmailAlerts.jsx`), gated by a bearer token (`GMAIL_CASES_READ_TOKEN` env var), polling `/api/gmail/cases` every 15s.
2. **Client-side — "Gmail Guard" browser extension** (`browser-extension/`): watches Gmail's own web page, and the moment you open an email, replicates Gmail's internal "Show original" request to fetch the raw source, sends it to the same backend `/api/analyze` endpoint, injects a risk banner directly into Gmail's own interface. Built, passing unit test suite (`node --test browser-extension/test-extension.cjs`, 3/3), and **live-verified end-to-end against a real Gmail account on 2026-09-20** — a live `POST /api/analyze` from the extension was confirmed in the backend log with the risk banner rendered in Gmail. Getting there required adapting to three current-Gmail changes discovered during that test: (a) the session token now lives only in the page's main-world global `GM_ID_KEY`, read via `chrome.scripting` in the MAIN world (needs the new `scripting` permission), (b) `view=om` now returns an HTML "Show original" viewer page instead of raw bytes, and (c) the raw RFC822 source is HTML-escaped inside a `<pre>`, so it's extracted and unescaped. **Remaining caveats (still state these):** it depends on Gmail's undocumented markup, so any Gmail frontend change can break it (re-verify after Gmail updates); and it reconstructs the source from the viewer page rather than obtaining bit-identical original bytes, so its hash is over that reconstruction. The banner UI was redesigned as a Material-style card. So Gmail Guard may now be described as **live-verified with those two caveats — no longer "live demo pending."**

### Frontend
React + Vite, redesigned around a minimal dashboard (stat cards, collapsed advanced detail, always-visible safety caveats). A top-level `ErrorBoundary` (`frontend/src/ErrorBoundary.jsx`) wraps the whole app so any future null-guard gap degrades to a message instead of a white screen. `SandboxSubmit` has a `key` prop tied to case+attachment identity (fixed a real bug: React was reusing component instances across case switches, leaking stale sandbox-analysis state).

### Testing state
**386 backend automated tests (pytest), all passing.** Frontend build and lint (oxlint) clean. The whole codebase has been through multiple full rounds of independent Codex review (backend line-by-line, frontend, deployment config) across the project's lifetime — every finding fixed and re-verified.

### Known, already-accepted limitations (documented on purpose, not hidden)
- Geo-infrastructure intelligence locates relay infrastructure, not a human attacker — the app says this directly.
- 99.32% is a held-out test-split figure, not a real-world generalization guarantee.
- Render.com's free tier (if deployed there) has no persistent disk — case history doesn't survive a redeploy/idle-recycle. Known, accepted tradeoff, not a bug.
- Gmail Guard scrapes Gmail's undocumented internal markup (not a public API) — will break silently if Google changes Gmail's frontend.

---

## 3. Submission materials status

- **`PPT_CONTENT_DRAFT.md`** — the full slide-by-slide content plan, mapped 1:1 onto the real official template placeholders (verified against the actual `SIH2026-IDEA-Presentation-Format.pptx`, not inferred). Extensively fact-checked and multiply Codex-reviewed. Read this file's own "Notes for whoever builds the slides" section for the full history of what was fixed and why.
- **`PROJECT_SUMMARY_FOR_PPT.md`** — a broader project summary for a teammate to build slides from, also Codex-reviewed.
- **`SIH26106_Cache-Me-Maybe.pptx`** — the actual built PowerPoint file, constructed by editing the real official template's slide XML directly (not built from scratch), validated clean (schema/relationship/content-type checks pass), exactly 6 content slides (the template's own 7th "delete before submitting" instructions slide was removed).
- **A genuine judging simulation was run**: Codex was set up as a real, demanding SIH-judge persona (grounded in the actual Terna/Intellecta guidelines, with real web research — it was honest that it found no official AICTE-specific rubric and said so rather than inventing one) and scored this submission across 3 rounds: **83/100 (shortlisted) → 88/100 ("Improved")** after addressing its specific feedback (trimmed Slide 2 density, fixed two overclaim phrasings, added a concrete investigation-walkthrough visual to Slide 3, shortened the BSA Section 63 claim, reworded impact/cost numbers).

**One unverified risk, flagged by that judging pass**: Slide 1's title-metadata text box measures (via `python-pptx`, not a visual render — no LibreOffice is installed in this environment) as possibly extending close to/past the footer bar boundary. This is 100% pre-existing official-template geometry — untouched by any edit made this session, only the label *values* were filled in — but it has never been visually confirmed. **Open the file in real PowerPoint and eyeball Slide 1 before submitting.**

### Still outstanding
1. Team ID on Slide 1 is a placeholder (`[To be assigned on sih.gov.in]`) — fill in once assigned.
2. Visual QA of the PPTX in real PowerPoint (see above).
3. Export to PDF for the actual portal upload (PDF only, no PPT/Word).
4. Rotate the AbuseIPDB and VirusTotal API keys hardcoded in `backend/serve_local.py` (gitignored, never committed, but still sitting in plaintext locally — rotate them and be careful not to zip that file into any manual submission bundle).
5. Gmail Guard extension still needs a real live-Gmail test if you want it demo-ready for Q&A.

---

## 4. Multi-agent workflow established this session

Three AI CLI tools are set up on this machine, with very different trust/reliability levels learned the hard way:

- **Codex CLI** (`codex exec --sandbox read-only|workspace-write --skip-git-repo-check -`, heredoc-piped prompt) — **the reliable one.** Durably pre-authorized via the owner's own global `~/.claude/CLAUDE.md` (a standing decision, not per-call chat approval). Has a genuinely working OS-level sandbox on this machine. Used dozens of times across this project for review and occasional implementation handoffs with zero gating needed. It also has real web-search access in this environment (confirmed: it did honest, cited web research when asked to become a "judge" persona).
- **Gemini CLI** (`gemini`) — **deprioritized.** Google has retired the standalone `gemini` CLI's free "Login with Google" path for individual accounts — attempting it returns `IneligibleTierError` pointing users to Antigravity instead. Without that, `gemini` only has free-tier API-key auth (5 requests/window), which makes it useless for anything beyond a trivial one-shot prompt. Don't bother routing real work through plain `gemini` CLI on this machine.
- **Antigravity CLI** (`agy`, at `C:\Users\Admin\AppData\Local\agy\bin\agy.exe`, not on PATH by default) — real, genuinely authenticated on the owner's Pro account (confirmed via `amaryempalle@gmail.com` OAuth), and has a broader toolset than Codex/Gemini in some respects (browser automation, image generation, subagent orchestration, web search). **But headless (`agy -p ...`) reliability is poor**: it tends to attempt a `run_command` tool call as an orientation step even for trivial prompts, and headless mode has no human to approve that confirmation — the whole response comes back empty when it happens. This is unpredictable, not reliably avoidable via prompt instructions alone.
  - **Established, explicit agreement with the owner: ask in chat before every individual `agy` invocation — no standing/blanket authorization**, even though the owner offered it directly at one point. Claude's own safety guardrails (categories: "Create Unsafe Agents", "Self-Modification") independently blocked two different attempts to set up autonomous, unsupervised agent-to-agent communication with Antigravity, even after explicit in-chat "I give you full authority" — this reflects a considered position, not just caution for its own sake: an AI agent should not grant itself standing authority to run another AI agent with real shell/file execution rights unsupervised. If the owner wants that changed, it has to be done by them directly in their own Claude Code settings (a `Bash(agy:*)` permission rule), not via chat instruction.
  - This does **NOT** apply to Codex — that's separately, durably authorized and has a real sandbox; keep using it freely.
  - The reliable way to use Antigravity for real work: the owner pastes a prepared prompt into the actual Antigravity app themselves (where they're present to approve things), and it writes findings to a file that gets read back. This pattern already produced one genuinely useful result (`antigravity_notes.md` — a real, correct diagnosis of its own headless-mode bug, which is why the settings.json permission story above is now understood).

---

## 5. Environment quirks worth knowing (this specific Windows machine)

- **Python on this machine (`Python314`) silently defaults some I/O to cp1252, not UTF-8**, when a script writes to a redirected file without an explicit encoding. This caused a real, confusing bug: a genuine, correct en-dash (U+2013) got written as a single stray cp1252 byte (`0x96`) into a file, which then broke `codex exec`'s UTF-8 stdin parsing entirely ("input is not valid UTF-8"). Always pass `encoding='utf-8'` explicitly on every `open()` call in ad-hoc scripts on this machine, and if something chokes on "invalid UTF-8", suspect this first.
- **No LibreOffice installed** — `soffice` is unavailable, so there's no way to render a `.pptx`/`.docx` to an actual image/PDF for visual QA in this environment. `markitdown` (text extraction) and `python-pptx` (structural/geometry inspection) are both installed and were used as the best available substitute — real, but not a substitute for actually opening the file.
- **`backend/tmp-pytest-codex-gmail/`** is a pytest artifact directory that can get Windows-locked (permission-denied) after a crashed/backgrounded test run. It's now in `.gitignore`; if you see permission errors mentioning it, it's a stale leftover, not a real problem — pass `--ignore=tmp-pytest-codex-gmail` to pytest or just leave it alone.
- A stray, **completely unrelated** file (`antigravity_websites_challenge_brief.md` — a different CTF competition's challenge notes) turned up in the repo root during this session, apparently misplaced from an unrelated task/session. It was deliberately excluded from every commit. Worth the owner cleaning it up or confirming what it is, but it's not part of this project.

---

## 6. Working norms established across this whole project (the actual "how to work on this")

- **Every claim that goes into submission materials or gets said to a judge must be fact-checked against the real, current code** — never trust a draft's own prior claims without re-verifying, especially numbers (test counts, accuracy figures, RFC numbers have drifted before — e.g. DMARC's RFC number changed mid-project when the standard itself was superseded).
- **Independent Codex review before any push, every time** — not a rubber stamp; findings get fixed and re-verified, not just noted.
- **Honest caveats beat overclaiming, consistently** — the project's strongest material (per Codex's own repeated feedback, including while acting as a simulated judge) is exactly the parts that say plainly what ISN'T proven yet (Gmail Guard's live-test status, the BSA Section 63 boundary, "infrastructure not human attacker") rather than the parts that oversell.
- **Never commit scratch review logs** (`codex_*.md`, `agy_*.txt`, `antigravity_*.md`, `gemini_*.md`) — these accumulate in the repo root as a working audit trail across the whole project but are deliberately never staged; only real source/deliverable changes get committed. Always stage explicitly by filename, never `git add -A`/`git add .`, given how much scratch material sits alongside real work in this repo root.
