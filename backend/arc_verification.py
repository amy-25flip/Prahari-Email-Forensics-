"""ARC (Authenticated Received Chain, RFC 8617) verification via dkimpy.

When a message passes through an intermediate relay that rewrites or re-sends it
(a mailing list, a forwarding service, some corporate gateways), that relay can attach
a cryptographically signed ARC seal recording what SPF/DKIM/DMARC looked like from its
vantage point. Validating that seal chain is a real, standards-based trust signal beyond
raw Received headers -- and unlike SPF, needs no analyst-supplied receiver context, since
the signatures are self-contained in the message.

Most email is never re-signed this way, so absence of ARC headers is normal and is not
a failure or a negative signal -- only a broken/invalid chain (cv=fail) is adverse.
"""
import time
import dkim
import dns.resolver

CV_LABELS = {dkim.CV_Pass: 'pass', dkim.CV_Fail: 'fail', dkim.CV_None: 'none'}


def verify(raw, live):
    if not live:
        return {'status': 'unknown', 'detail': 'External DNS verification disabled.'}
    deadline = time.monotonic() + 10
    lookup_failed = False

    def key_lookup(name, timeout=2):
        nonlocal lookup_failed
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            lookup_failed = True
            return b''
        try:
            answer = dns.resolver.resolve(name.decode().rstrip('.'), 'TXT', lifetime=min(2, remaining))
            records = [b''.join(r.strings).decode('ascii') for r in answer]
            return records[0].encode('ascii') if len(records) == 1 else b''
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # A definitive negative answer: the selector genuinely has no published key.
            # This is real evidence of an absent/forged seal, not environmental flakiness
            # -- must not be downgraded below, or a genuinely broken ARC chain could hide
            # behind the same 'unknown' treatment meant for DNS trouble.
            return b''
        except Exception:
            # Transient/environmental failures (timeout, no reachable nameserver, etc.)
            # -- dkimpy can't distinguish these from "no key published" (both collapse to
            # the same b'' return and downstream CV_Fail), so track them separately here
            # to downgrade a 'fail' verdict below instead of confidently penalizing a
            # legitimate sender for a DNS hiccup -- confirmed live against a real Google
            # email where a transient DNS timeout flipped the verdict between pass/fail
            # across identical retries of the same message.
            lookup_failed = True
            return b''

    try:
        cv_result, chain_results, reason = dkim.arc_verify(raw, dnsfunc=key_lookup, timeout=2)
    except Exception as exc:
        return {'status': 'unknown', 'detail': f'ARC chain verification unavailable ({type(exc).__name__}).'}

    def _jsonable(value):
        # dkimpy returns raw header values (d=/cv= etc.) as bytes, which json.dumps
        # can't serialize -- this crashed on the first real email with an actual
        # ARC-Seal chain (test fixtures never exercised this path with real bytes).
        return value.decode('ascii', 'replace') if isinstance(value, bytes) else value

    # dkimpy's ARC.verify_instance() keys these 'instance'/'as-domain'/'cv' (confirmed via
    # inspect.getsource, not assumed) -- there is no 'd' or 'i' key, so the previous
    # ('d', 'i', 'cv') lookup silently matched only 'cv' and dropped which domain sealed
    # each hop from every report. 'as-domain' (the ARC-Seal signer) is used over
    # 'ams-domain' (the ARC-Message-Signature signer) since the seal is what this
    # verification actually authenticates.
    chain = [{'instance': r.get('instance'), 'domain': _jsonable(r.get('as-domain')), 'cv': _jsonable(r.get('cv'))}
             for r in (chain_results or [])]
    if cv_result == dkim.CV_None and not chain:
        return {'status': 'not_present', 'chain_length': 0,
                'detail': 'No ARC headers found; most email is never re-signed by an intermediate relay. This is normal, not a failure.'}
    # dkimpy's ARC.verify() returns Python None (not CV_Fail) specifically when an
    # intermediate hop's own ARC-Seal already reported cv=fail and the chain was
    # terminated there -- a distinct failure path from "we detected a bad signature".
    # Without this, it silently fell into CV_LABELS' 'unknown' fallback and the
    # arc_chain_failed attribution penalty never fired for this case.
    if cv_result is None:
        status = 'fail'
    else:
        status = CV_LABELS.get(cv_result, 'unknown')
    if status == 'fail' and lookup_failed:
        status = 'unknown'
        reason = f'{reason or "validation did not complete"}; at least one DNS key lookup during verification failed or timed out'
    return {'status': status, 'chain_length': len(chain), 'chain': chain, 'detail': _detail_for(status, reason)}


def _detail_for(status, reason):
    reason = reason or 'no further detail available'
    if status == 'pass':
        return ('ARC chain validated: signatures on all forwarding hops are cryptographically intact. '
                'This corroborates the relay path was not tampered with in transit after the first ARC-sealing '
                'hop; it does not by itself prove the original sender\'s identity or cover hops before that point.')
    if status == 'fail':
        return f'ARC chain failed validation ({reason}); the reported relay chain may have been altered after an intermediate hop signed it. Forwarding artifacts and misconfiguration are also possible explanations, not only tampering.'
    return f'ARC chain present but inconclusive ({reason}).'
