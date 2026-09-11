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

    def key_lookup(name, timeout=2):
        remaining = deadline - time.monotonic()
        if remaining <= 0: return b''
        try:
            answer = dns.resolver.resolve(name.decode().rstrip('.'), 'TXT', lifetime=min(2, remaining))
            records = [b''.join(r.strings).decode('ascii') for r in answer]
            return records[0].encode('ascii') if len(records) == 1 else b''
        except Exception:
            return b''

    try:
        cv_result, chain_results, reason = dkim.arc_verify(raw, dnsfunc=key_lookup, timeout=2)
    except Exception as exc:
        return {'status': 'unknown', 'detail': f'ARC chain verification unavailable ({type(exc).__name__}).'}

    chain = [{k: r.get(k) for k in ('d', 'i', 'cv') if k in r} for r in (chain_results or [])]
    if cv_result == dkim.CV_None and not chain:
        return {'status': 'not_present', 'chain_length': 0,
                'detail': 'No ARC headers found; most email is never re-signed by an intermediate relay. This is normal, not a failure.'}
    status = CV_LABELS.get(cv_result, 'unknown')
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
