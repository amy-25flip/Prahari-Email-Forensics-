# Investigator leads live check

Measured: 2026-09-25T18:54:44

Scope: live public RDAP lookups only. Contacts are organisations to ask for abuse/legal follow-up, not actor identity.

## Direct leads lookups
- domain `google.com`: {"abuse_contact": "abusecomplaints@markmonitor.com", "expires_at": "2028-09-14T04:00:00Z", "registered_at": "1997-09-15T04:00:00Z", "registrar": "MarkMonitor Inc."}
- domain `github.com`: {"abuse_contact": "abusecomplaints@markmonitor.com", "expires_at": "2028-10-09T18:20:50Z", "registered_at": "2007-10-09T18:20:50Z", "registrar": "MarkMonitor Inc."}
- domain `cloudflare.com`: {"abuse_contact": "registrar-abuse@cloudflare.com", "expires_at": "2033-02-17T22:07:54Z", "registered_at": "2009-02-17T22:07:54Z", "registrar": "Cloudflare, Inc."}
- ip `8.8.8.8`: {"abuse_contact": "network-abuse@google.com", "country": null, "handle": "NET-8-8-8-0-2", "network": "GOGL", "range": "8.8.8.0-8.8.8.255"}
- ip `1.1.1.1`: {"abuse_contact": "helpdesk@apnic.net", "country": "AU", "handle": "1.1.1.0 - 1.1.1.255", "network": "APNIC-LABS", "range": "1.1.1.0-1.1.1.255"}
- ip `151.101.0.223`: {"abuse_contact": "abuse@fastly.com", "country": null, "handle": "NET-151-101-0-0-1", "network": "SKYCA-3", "range": "151.101.0.0-151.101.255.255"}
- ip `2606:4700:4700::1111`: {"abuse_contact": "abuse@cloudflare.com", "country": null, "handle": "NET6-2606-4700-1", "network": "CLOUDFLARENET", "range": "2606:4700::-2606:4700:ffff:ffff:ffff:ffff:ffff:ffff"}

## main.execute(..., live=True) smoke check rerun
- measured: 2026-09-25T18:57:00
- status: available
  - {"abuse_contact": "abusecomplaints@markmonitor.com", "expires_at": "2028-10-09T18:20:50Z", "kind": "registrar", "registered_at": "2007-10-09T18:20:50Z", "registrar": "MarkMonitor Inc.", "source": "RDAP (IANA bootstrap)", "subject": "github.com"}
  - {"abuse_contact": "noc@github.com", "handle": "NET-140-82-112-0-1", "kind": "network_owner", "network": "GITHU", "range": "140.82.112.0-140.82.127.255", "source": "RDAP (IANA bootstrap)", "subject": "140.82.112.3"}
- elapsed_ms: 4209
