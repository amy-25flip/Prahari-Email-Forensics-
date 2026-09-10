"""State the provenance of source observations instead of inventing actor confidence."""
import ipaddress


def assess(report,context=None,receiver=None):
    candidates=[]
    for hop in report.get('hops',[]):
        for value in hop.get('sender_ips',hop.get('ips',[])):
            try:
                ip=ipaddress.ip_address(value)
                if ip.is_global and str(ip) not in [x['ip'] for x in candidates]:
                    candidates.append({'ip':str(ip),'hop':hop['index'],'provenance':'untrusted_header'})
            except ValueError: pass
    candidate=candidates[0] if candidates else None
    supplied=str(context['client_ip']) if context else None
    trusted=bool(receiver and context)
    location_ip=supplied if trusted else candidate['ip'] if candidate else None
    location=next((g for g in report.get('geo',[]) if g.get('ip')==location_ip and g.get('status')=='available'),None)
    return {'status':'receiver_attested' if trusted else 'conditional_receiver_context' if context else 'header_observation' if candidate else 'insufficient_evidence',
            'confidence':'authenticated_observation' if trusted else 'conditional' if context else 'low' if candidate else 'undetermined',
            'earliest_reported_public_node':candidate,
            'earliest_reliable_node':{'ip':supplied,'provenance':'receiver_attestation','receiver':receiver['receiver']} if trusted else None,
            'receiver_reported_client':supplied,
            'receiver_ip_in_headers':any(c['ip']==supplied for c in candidates) if context else None,
            'approximate_location':{k:location.get(k) for k in ('country','city','isp','asn')} if location else None,
            'basis':'Original bytes and SMTP context match a recent HMAC attestation from a configured receiver. Reliability depends on receiver security and log accuracy; earlier header nodes remain untrusted.' if trusted else 'SMTP context is supplied by the analyst, not independently authenticated.' if context else 'Received headers can be forged; chronological position alone does not establish reliability.',
            'next_verification':'Compare the receiving server logs and original message to establish a trusted ingress boundary. An ingress server is not necessarily the original sender.',
            'scope':'Qualitative evidence confidence, not a calibrated probability or human location. An email may list both sending and receiving IPs in a single hop.'}
