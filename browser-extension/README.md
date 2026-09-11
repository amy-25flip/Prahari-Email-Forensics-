# Gmail Guard — real-time browser-extension scanning

Addresses the PS's "real-time alerts before user interaction" requirement for Gmail's web UI. This is a
different reliability class from the backend's API integrations (AbuseIPDB, VirusTotal, ipwho.is, IANA RDAP):
those are documented, stable REST APIs. This extension works by replicating Gmail's own undocumented
"Show original" request. **It is not an official Gmail integration and can break if Google changes Gmail's
markup.** Treat it as a working demo of the concept, not a hardened production component — it has not been
tested end-to-end against a live Gmail account by the assistant that built it (that would require logging
into your Gmail, which it will not do; you need to load and test this yourself).

## What it does

1. A content script watches Gmail's DOM for an opened message.
2. It replicates Gmail's "Show original" request (`view=om`) to fetch the message's raw RFC822 source,
   using your existing Gmail session — no separate login or OAuth needed.
3. It sends that raw source to the backend's existing `POST /api/analyze?enrich=true` endpoint (the same
   endpoint the web app uses) via the extension's background service worker.
4. It injects a risk banner directly into the Gmail message view: evidence score, risk band, attribution
   confidence, and top findings — before you click any links or reply.
5. Successful results are cached for one hour in the current Gmail page, keyed by account, backend and
   message. Recreated message views restore the banner. Reloading the page clears this cache.
   Failed scans retry with bounded backoff rather than being recorded as successful scans.
6. Original message bytes are preserved during transfer; messages over 1 MiB are rejected.

## Regression checks

Run `node --test browser-extension/test-extension.cjs` from the repository root. These tests cover
retry/cache state and original-byte transfer. Synthetic browser checks also cover banner restoration,
urgent triage, account paths and safe text rendering. These do not replace testing live Gmail markup.

## Install (unpacked, for testing)

1. Make sure the backend is running and reachable (defaults to `http://localhost:8000`; open the extension
   popup to change it — e.g. once deployed to Render).
2. In Chrome, go to `chrome://extensions`, enable **Developer mode** (top right).
3. Click **Load unpacked** and select this `browser-extension/` folder.
4. Open Gmail (`mail.google.com`) in a tab and open any email. Watch the bottom-right status badge and
   the injected banner above the message.

## Known limitations — read before demoing

- **Fragile by nature.** Message detection (`[data-message-id]`) and the session token extraction (`ik`)
  are scraped from Gmail's current markup, not a public API. If Gmail's frontend changes, this breaks
  silently until fixed — the status badge will show "last scan failed" or "no open email detected" if so.
- **Cross-context session cookie behavior is unverified.** The extension relies on the backend's existing
  session-cookie mechanism (`credentials: 'include'`) to group scanned emails into a session/case history.
  Whether that cookie is shared reliably between the extension's background service worker and a normal
  browser tab open on the same backend origin has not been empirically confirmed — test this yourself by
  opening the deployed/local app in a tab after scanning a few emails and checking whether they appear in
  case history. If they don't, each extension scan is still functionally correct (it returns and stores its
  own result), it just won't cross-reference with the main app's case list.
- **Not pre-delivery.** This detects and alerts when *you* open an email in Gmail's web UI — after Gmail has
  already delivered it to your inbox, before you've acted on it. True pre-delivery interception requires
  mail-transfer-agent-level access (a Postfix milter, an Exchange transport agent, or a Google Workspace
  admin console integration) that only an institutional mail administrator can grant — not achievable from
  a browser extension, regardless of implementation quality.
- **Gmail web only**, and only the `mail.google.com` origin (not the Android/iOS Gmail apps).
- Every scanned email is sent to your configured backend with full enrichment (`enrich=true`), which in turn
  may call AbuseIPDB/VirusTotal/ipwho.is/IANA with the email's public IPs and sender domain (never the body
  or attachments beyond attachment hashes) if those integrations are configured. Be mindful of this before
  pointing the extension at a shared/production backend with real mail.
