// Click-time protection: once a high-risk verdict is installed for the opened Gmail message, ordinary link clicks inside its body
// (click and middle-click) ask for confirmation before the browser follows them. Best effort, NOT a security boundary: it does not
// cover clicks made before the scan finishes, browser actions outside click events (e.g. the context-menu 'open in new tab'),
// or navigation triggered by Gmail's own scripts. Runs only on the message body and only for high-risk verdicts; sends nothing anywhere.
globalThis.GmailGuardClickGuard = (() => {
  const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:']

  function shouldGuard(result) {
    return !!result && (result.triage?.priority === 'urgent' || (typeof result.score === 'number' && result.score >= 60))
  }

  function describeLink(href, base = 'https://mail.google.com/') {
    let url
    try { url = new URL(href, base) } catch { return { ok: false, href: String(href || ''), host: '', dangerous: false, internal: false } }
    // Google wraps outbound links as https://www.google.com/url?q=<real>; show and judge the real destination.
    if ((url.hostname === 'www.google.com' || url.hostname === 'google.com') && url.pathname === '/url') {
      const real = url.searchParams.get('q') || url.searchParams.get('url')
      if (real) { try { url = new URL(real) } catch { /* keep the wrapper */ } }
    }
    const dangerous = DANGEROUS_SCHEMES.includes(url.protocol)
    const internal = !dangerous && /(^|\.)mail\.google\.com$/.test(url.hostname) && url.protocol === 'https:'
    return { ok: true, href: url.href, host: url.host, scheme: url.protocol, dangerous, internal }
  }

  function install(container, result, doc, win) {
    let overlay = null
    let opener = null

    function close() {
      if (overlay) { overlay.remove(); overlay = null }
      doc.removeEventListener?.('keydown', onKey, true)
      if (opener?.focus) { try { opener.focus() } catch { /* element gone */ } }
      opener = null
    }
    function onKey(event) { if (event.key === 'Escape' && overlay) { event.preventDefault(); close() } }

    function build(info, anchor) {
      const priority = result.triage?.priority || 'high-risk'
      const box = doc.createElement('div')
      box.className = 'etd-guard-overlay'
      box.setAttribute('role', 'alertdialog')
      box.setAttribute('aria-modal', 'true')
      box.setAttribute('aria-labelledby', 'etd-guard-title')
      const card = doc.createElement('div')
      card.className = 'etd-guard-card'
      const title = doc.createElement('h2')
      title.id = 'etd-guard-title'
      title.textContent = 'Stop - this message was rated ' + priority
      const why = doc.createElement('p')
      why.textContent = `Gmail Guard scored this email ${result.score}/100. You clicked a link inside it that goes to:`
      const dest = doc.createElement('code')
      dest.className = 'etd-guard-dest'
      dest.textContent = info.ok ? info.href : String(info.href).slice(0, 300)
      const advice = doc.createElement('p')
      advice.textContent = info.dangerous
        ? 'This link runs code or embeds content directly and cannot be opened from here. Do not use it.'
        : 'If you did not expect this message, do not sign in or enter payment details on the next page. Confirm with the sender through a separate channel.'
      const row = doc.createElement('div')
      row.className = 'etd-guard-actions'
      const cancel = doc.createElement('button')
      cancel.type = 'button'
      cancel.className = 'etd-guard-cancel'
      cancel.textContent = 'Stay safe (do not open)'
      cancel.addEventListener('click', event => { event.preventDefault(); close() })
      row.appendChild(cancel)
      if (info.ok && !info.dangerous) {
        const open = doc.createElement('button')
        open.type = 'button'
        open.className = 'etd-guard-open'
        open.textContent = 'Open anyway'
        open.addEventListener('click', event => { event.preventDefault(); close(); win.open(info.href, '_blank', 'noopener,noreferrer') })
        row.appendChild(open)
      }
      for (const node of [title, why, dest, advice, row]) card.appendChild(node)
      box.appendChild(card)
      return { box, cancel }
    }

    function onClick(event) {
      const anchor = event.target?.closest?.('a[href]')
      if (!anchor || !container.contains(anchor)) return
      const info = describeLink(anchor.getAttribute('href'), doc.baseURI)
      if (info.internal) return
      event.preventDefault()
      event.stopPropagation()
      event.stopImmediatePropagation?.()
      if (overlay) close()
      const { box, cancel } = build(info, anchor)
      overlay = box
      opener = anchor
      doc.body.appendChild(box)
      doc.addEventListener('keydown', onKey, true)
      cancel.focus?.()
    }

    container.addEventListener('click', onClick, true)
    container.addEventListener('auxclick', onClick, true)
    return { remove() { container.removeEventListener('click', onClick, true); container.removeEventListener('auxclick', onClick, true); close() } }
  }

  return { shouldGuard, describeLink, install }
})()
