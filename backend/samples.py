"""Reserved domains and documentation IPs: illustrative fixtures, not real incidents."""
SAMPLES = [
    {'id': 'newsletter', 'title': 'Engineering newsletter', 'kind': 'Legitimate-style fixture', 'raw': '''From: Engineering Digest <digest@engineering.example>
To: analyst@college.example
Subject: Your September engineering digest
Date: Tue, 08 Sep 2026 09:00:00 +0530
Message-ID: <digest-09@engineering.example>
Return-Path: <digest@engineering.example>
Received: from newsletter.engineering.example (192.0.2.30) by inbox.college.example; Tue, 08 Sep 2026 09:00:00 +0530
Content-Type: text/plain; charset=utf-8

Hello,
Here are this month's engineering talks, research papers and community updates.
The robotics seminar is scheduled for Friday at 4 PM. Attendance is optional.
Read the programme at https://engineering.example/events/september.
Thank you for being part of our community.
The Engineering Digest team
'''},
    {'id': 'account', 'title': 'Account verification request', 'kind': 'Credential-phishing fixture', 'raw': '''From: College IT Support <support@college-help.example>
To: faculty@college.example
Subject: Urgent: verify your account to prevent suspension
Date: Tue, 08 Sep 2026 10:00:00 +0530
Message-ID: <account-01@college-help.example>
Return-Path: <bounce@dispatch.example>
Reply-To: recovery@secure-desk.example
Received: from mail.dispatch.example (198.51.100.24) by inbox.college.example; Tue, 08 Sep 2026 10:00:00 +0530
Content-Type: text/html; charset=utf-8

<p>Your account will be suspended within 24 hours. Verify your password immediately to avoid losing access.</p>
<p><a href="http://college-login.example/verify?redirect=https://secure-desk.example/session">https://college.example</a></p>
<p>Do not contact the helpdesk. Reply to this message for assistance.</p>
'''},
    {'id': 'invoice', 'title': 'Changed invoice instructions', 'kind': 'Payment-diversion fixture', 'raw': '''From: Accounts Office <accounts@vendor-billing.example>
To: finance@college.example
Subject: Confidential: urgent invoice settlement
Date: Tue, 08 Sep 2026 10:15:00 +0530
Message-ID: <invoice-02@vendor-billing.example>
Return-Path: <accounts@vendor-billing.example>
Reply-To: recovery@secure-desk.example
Received: from mail.vendor-billing.example (203.0.113.18) by inbox.college.example; Tue, 08 Sep 2026 10:15:00 +0530
Content-Type: text/plain; charset=utf-8

Please transfer the payment today. Our bank account has changed.
Keep this confidential and bypass the normal approval process.
Do not call the office. Reply to this email to receive the updated bank details.
'''},
]
