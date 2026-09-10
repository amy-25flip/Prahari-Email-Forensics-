# Receiver Evidence and Reliable Ingress

This implements the PS's earliest-reliable-node capability when authenticated receiver observations exist. It does not make arbitrary Received headers trustworthy, establish the original human sender, or require a staff directory.

## Trust Configuration

The analysis server reads RECEIVER_KEYS_JSON from its process environment: a JSON object mapping receiver identifiers to independent, randomly generated shared secrets of at least 32 bytes. There are no default trusted receivers or demo secrets. Keep this configuration outside Git and outside browser-accessible files.

The matching receiver/log-export system uses RECEIVER_SIGNING_KEY. Only its trusted operator may access this key. Never sign arbitrary analyst-supplied SMTP claims: the client IP, MAIL FROM and HELO must come from receiver records corresponding to the exact retained email bytes. The included receiver_attest.py is an adapter for a trusted log-export workflow, not a mail-server integration or a public signing endpoint.

From backend, the receiver operator can run:

```powershell
python receiver_attest.py --email original.eml --smtp-record receiver-record.json --receiver mx.example
```

The SMTP JSON contains client_ip, mail_from and helo. The command writes a signed receipt to standard output. The receipt contains receiver, issued_at, sha256, smtp and signature. HMAC-SHA256 covers the canonical JSON of all fields except signature: sorted keys, ASCII escaping, comma/colon separators without spaces.

Upload the original .eml and select the receipt in the Receiver-signed evidence control. API clients send the receipt as X-Receiver-Evidence alongside original message/rfc822 bytes. Receipts must be issued within five minutes (60 seconds future clock tolerance). Existing emails may be re-attested only by the trusted receiver against retained records. Reuse for the same bytes is permitted; a receipt is not a one-time authorization token.

## Behavior

- Unknown receivers, invalid signatures, expired receipts, modified bytes and conflicting SMTP context are rejected.
- A valid attestation establishes the configured receiver's observed ingress client, not all preceding relays. Header-reported upstream nodes remain untrusted.
- DNS opt-in is still required for current SPF/DKIM/DMARC checks. Receiver attestation verification itself works offline.
- The UI and PDF report distinguish authenticated observations from unverified header candidates.
- Trust depends on the receiver's accuracy and key security. HMAC is shared-key authentication, not independent public-key notarization or proof of legal admissibility.

## Verification Status

Controlled tests cover valid receipts, changed raw bytes, changed context, bad signatures, old/future timestamps, unknown receivers and pasted-input rejection. No actual institutional mail server has been connected or independently audited.
