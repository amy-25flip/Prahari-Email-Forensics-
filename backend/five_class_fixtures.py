"""Hand-written SYNTHETIC fixtures for the five-class decision table (not real mail, not a training set)."""
LEGIT = [
 ('alerts@hdfcbank.com', 'HDFC Bank', 'Your statement is ready', 'Dear customer, your monthly statement for the account ending 1234 is available in NetBanking. Please verify the details by logging in at hdfcbank.com directly.'),
 ('no-reply@amazon.in', 'Amazon.in', 'Your order has shipped', 'Hi Asha, your order of 2 items has shipped and will arrive on Friday. Track it in Your Orders.'),
 ('priya.sharma@college.example', 'Priya Sharma', 'Lab schedule for next week', 'Hi all, the lab schedule for next week is attached in the shared folder. Please confirm your slot by Monday.'),
 ('team@github.com', 'GitHub', 'New sign-in to your account', 'We noticed a new sign-in from Chrome on Windows. If this was you, no action is needed.'),
 ('billing@electricity.example', 'City Power', 'Your bill for August', 'Your electricity bill of 1,240 rupees is due on the 15th. You can pay through the official app or at any counter.'),
 ('hr@company.example', 'HR Team', 'Holiday calendar', 'Please find the holiday calendar for next year. Reach out to HR with any questions.'),
 ('newsletter@irctc.co.in', 'IRCTC', 'Booking confirmation', 'Your ticket is confirmed for 12 October. PNR 4521879034. Wishing you a pleasant journey.'),
 ('rahul@friend.example', 'Rahul', 'Weekend plans', 'Are we still on for the trip this weekend? I can drive if you share the pickup point.'),
 ('support@paytm.com', 'Paytm', 'KYC update reminder', 'As per RBI guidelines please complete your KYC in the Paytm app before the due date. We will never ask for your OTP or PIN.'),
 ('noreply@sbi.bank.in', 'State Bank of India', 'Transaction alert', 'Your account was debited by 500 rupees on 3 September. If you did not make this transaction contact the branch.'),
 ('prof.mehta@university.example', 'Prof. Mehta', 'Assignment feedback', 'I have reviewed your assignment and left comments. Let us discuss during office hours.'),
 ('orders@flipkart.com', 'Flipkart', 'Your refund is processed', 'The refund for your returned item has been processed and will reflect in 5 to 7 working days.'),
 ('accounts@vendor.example', 'Vendor Accounts', 'Invoice 4471 for September', 'Attached is invoice 4471 for the services delivered in September. Payment terms are 30 days as agreed in the contract.'),
 ('security@accounts.google.com', 'Google', 'Security alert', 'Your Google account was used to sign in on a new device. Review this activity at myaccount.google.com if it was not you.'),
 ('meetings@company.example', 'Calendar', 'Meeting moved to 3 pm', 'The project review has moved to 3 pm in room B. Agenda is unchanged.'),
]
PHISHING = [
 ('security@hdfc-secure-login.example', 'HDFC Bank', 'Verify your account immediately', 'Your account will be suspended. Verify your account password now at http://hdfc-secure-login.example/verify to avoid closure.'),
 ('support@paypa1-alert.example', 'PayPal', 'Account limited', 'We noticed unusual activity. Verify your account password at http://paypa1-alert.example/login within 24 hours or your account will be suspended.'),
 ('alert@sbi-kyc-update.example', 'SBI Alerts', 'KYC expired', 'Your KYC has expired. Verify your account and password here http://sbi-kyc-update.example/kyc or your account will be suspended today.'),
 ('noreply@microsoft-365-support.example', 'Microsoft Support', 'Password expires today', 'Your password expires today. Verify your account password at http://microsoft-365-support.example/reset to keep access.'),
 ('service@netflix-billing.example', 'Netflix', 'Payment failed', 'Your payment failed. Verify your account password at http://netflix-billing.example/update or your account will be suspended.'),
 ('info@icici-netbanking.example', 'ICICI Bank', 'Card blocked', 'Your card is blocked. Verify your account and password at http://icici-netbanking.example/unblock now.'),
 ('helpdesk@apple-id-verify.example', 'Apple ID', 'Apple ID locked', 'Your Apple ID is locked. Verify your account password at http://apple-id-verify.example/unlock immediately or account will be suspended.'),
 ('dept@incometax-refund.example', 'Income Tax Department', 'Refund pending', 'You have a tax refund. Verify your account password and bank login at http://incometax-refund.example/claim to receive it.'),
 ('admin@amazon-secure-pay.example', 'Amazon', 'Unusual sign-in', 'Unusual sign-in detected. Verify your account password at http://amazon-secure-pay.example/signin or account will be suspended.'),
 ('support@axisbank-update.example', 'Axis Bank', 'Account suspended', 'Your account is suspended. Verify your account password immediately at http://axisbank-update.example/restore.'),
 ('it@company-helpdesk.example', 'IT Helpdesk', 'Mailbox full', 'Your mailbox is full. Verify your account password at http://company-helpdesk.example/mailbox or your account will be suspended.'),
 ('notice@paytm-rewards.example', 'Paytm', 'Reward waiting', 'Claim your reward. Verify your account password and login at http://paytm-rewards.example/claim within one hour.'),
 ('alerts@dhl-tracking.example', 'DHL', 'Parcel on hold', 'Your parcel is on hold. Verify your account password and pay the fee at http://dhl-tracking.example/pay to release it.'),
 ('mail@google-docs-share.example', 'Google Docs', 'Document shared', 'A document was shared with you. Verify your account password at http://google-docs-share.example/open to view it or your account will be suspended.'),
 ('care@flipkart-refund.example', 'Flipkart Care', 'Refund failed', 'Your refund failed. Verify your account and password at http://flipkart-refund.example/refund now, account suspended otherwise.'),
]
FRAUD = [
 ('ceo@company-mail.example', 'Managing Director', 'Urgent payment', 'Please transfer the payment today. Our bank account changed; use the updated bank details below and keep this confidential.'),
 ('finance@supplier-co.example', 'Supplier Finance', 'New bank details', 'Our bank account has changed. Please transfer the payment of 4,50,000 rupees to the updated bank details and do not call the old contact.'),
 ('barrister@legal-claims.example', 'Barrister Ade', 'Inheritance claim', 'You are the beneficiary of an inheritance of 8 million dollars. Pay the advance fee to release the funds and keep this confidential.'),
 ('lucky@lottery-desk.example', 'Lottery Desk', 'You won', 'Congratulations, you won the lottery of 500000 dollars. Send the advance fee today to claim it. Do not contact anyone else.'),
 ('boss@firm-mail.example', 'Director', 'Gift cards needed', 'I need you to buy gift cards for a client today. Keep this confidential and send me the codes. Do not call me, I am in a meeting.'),
 ('vendor@parts-supply.example', 'Parts Supply', 'Payment update', 'The bank account has changed for future invoices. Transfer the payment to the updated bank details attached and bypass the usual approval as it is urgent.'),
 ('unknown@threat-mail.example', 'Anonymous', 'Pay now', 'We have your private photos. Pay in bitcoin ransom within 48 hours or we publish them. Do not contact anyone.'),
 ('cfo@corp-notice.example', 'CFO', 'Wire request', 'Please transfer the payment for the acquisition today. Updated bank details are below. Keep this confidential until the announcement.'),
 ('hr@job-offers.example', 'Recruiter', 'Job offer fee', 'You are selected. Pay the advance fee for registration to receive your offer. Do not contact the company directly.'),
 ('accounts@contractor.example', 'Contractor', 'Bank change', 'Our bank account changed last week. Transfer the payment to the updated bank details and keep this confidential.'),
 ('officer@relief-fund.example', 'Relief Officer', 'Compensation', 'Compensation of 2 million is waiting for you. Pay the advance fee first, and do not call anyone about this.'),
 ('md@group-mail.example', 'MD Office', 'Confidential task', 'Bypass approval for this vendor and transfer the payment now to the updated bank details. Keep this confidential.'),
 ('sales@investment-hub.example', 'Investment Hub', 'Guaranteed returns', 'Guaranteed returns. Send the advance fee in bitcoin to start. Do not tell your family.'),
 ('landlord@rent-mail.example', 'Landlord', 'Rent account changed', 'My bank account changed. Transfer the payment for rent to the updated bank details and keep this confidential.'),
 ('director@ngo-mail.example', 'NGO Director', 'Donation transfer', 'Please transfer the payment today to the updated bank details and bypass the normal approval. Keep this confidential.'),
]
IMPERSONATED = [
 ('sbi.alerts@gmail.com', 'State Bank of India', 'Notice', 'Hello, this is a notice from the bank. Please contact your branch for details.'),
 ('help@random-host.example', 'Microsoft Support', 'Hello', 'This is Microsoft support. We would like to speak with you regarding your subscription.'),
 ('a@hdfcbank.co', 'HDFC Bank', 'Update', 'We have an update regarding your services. Thank you for banking with us.'),
 ('info@icici-support.example', 'ICICI', 'Customer care', 'Our customer care team is here to help you with any questions about your services.'),
 ('care@amazon-support.example', 'Amazon Customer Care', 'Your query', 'Thank you for contacting us. We are looking into your query and will respond soon.'),
 ('news@paytm-update.example', 'Paytm', 'Newsletter', 'Here is our monthly update about new features in the app. Have a great month.'),
 ('service@netflix-help.example', 'Netflix Support', 'Hello from Netflix', 'We hope you are enjoying your shows. Let us know if you need anything.'),
 ('desk@apple-care.example', 'Apple', 'Service notice', 'This is a service notice about your device warranty. No action needed.'),
 ('mail@irctc-tickets.example', 'IRCTC', 'Travel info', 'General information for travellers about station facilities and timings.'),
 ('team@google-workspace.example', 'Google', 'Workspace update', 'An update about features in your workspace. Learn more on the help pages.'),
 ('hello@axisbank-online.example', 'Axis Bank', 'Greetings', 'Greetings from the bank. We value your relationship with us.'),
 ('office@kotak-alerts.example', 'Kotak', 'Alert service', 'Our alert service keeps you informed about your accounts.'),
 ('info@pnb-india.example', 'Punjab National Bank', 'Branch update', 'Please note the revised branch timings for the coming month.'),
 ('contact@flipkart-care.example', 'Flipkart', 'Hello', 'Thanks for shopping with us. Have a look at our latest catalogue.'),
 ('u@bankofbaroda.example', 'Bank of Baroda', 'Notice', 'This is a general notice regarding working hours during the festival season.'),
]
SUSPICIOUS = [
 ('promo@deals.example', 'Deals', 'Weekend sale', 'Huge discounts this weekend on electronics. Visit http://deals.example/sale for offers. Unsubscribe anytime.'),
 ('unknown@mailer.example', 'Unknown', 'Hello dear', 'I would like to discuss a business opportunity with you. Please reply if interested.'),
 ('survey@feedback.example', 'Survey Team', 'Win a prize', 'Fill this short survey and get a chance to win a phone. http://feedback.example/survey'),
 ('sales@leads.example', 'Sales', 'Boost your traffic', 'We can double your website traffic in a week. Reply for pricing.'),
 ('r@bulk-mail.example', 'Recruiter', 'Job opportunity', 'We have a work from home job paying well. Reply with your resume and phone number.'),
 ('a@promo.example', 'Offers', 'Limited time', 'Limited time offer just for you. Click http://promo.example/offer to view.'),
 ('m@cheap-meds.example', 'Pharmacy', 'Discount medicines', 'Discount medicines delivered fast. Order at http://cheap-meds.example/shop'),
 ('x@unknown-co.example', 'Admin', 'Important notice', 'Important notice about your subscription. Please review the terms at http://unknown-co.example/terms'),
 ('n@crypto-news.example', 'Crypto News', 'Hot coin', 'This coin will rise soon. Learn more at http://crypto-news.example/coin'),
 ('h@seo-help.example', 'SEO Help', 'Website audit', 'We audited your website and found issues. See details http://seo-help.example/audit'),
 ('l@loan-offers.example', 'Loan Offers', 'Instant loan', 'Instant personal loan with no paperwork. Apply now at http://loan-offers.example/apply'),
 ('w@webinar.example', 'Webinar', 'Free webinar', 'Join our free webinar tomorrow. Register at http://webinar.example/join'),
 ('g@gifts.example', 'Gifts', 'Free gift', 'Claim your free gift by visiting http://gifts.example/free today.'),
 ('t@travel-deals.example', 'Travel', 'Cheap flights', 'Cheap flights to Goa. Book at http://travel-deals.example/goa'),
 ('p@print-shop.example', 'Print Shop', 'Cheap printing', 'Business cards at low cost. Order at http://print-shop.example/cards'),
]
CASES = [(cls, *row) for cls, rows in (('legitimate', LEGIT), ('phishing', PHISHING), ('fraud_related', FRAUD), ('impersonated', IMPERSONATED), ('suspicious', SUSPICIOUS)) for row in rows]


def build(addr, name, subject, body):
    import hashlib
    mid = hashlib.sha256((addr + subject).encode()).hexdigest()[:16]
    return (f'From: "{name}" <{addr}>\r\nTo: user@example.org\r\nSubject: {subject}\r\nDate: Mon, 01 Sep 2025 10:00:00 +0000\r\n'
            f'Message-ID: <{mid}@fixture.example>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n').encode()
