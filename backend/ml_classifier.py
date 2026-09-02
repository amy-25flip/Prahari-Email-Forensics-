PHISHING_KEYWORDS = [
    'verify', 'account', 'suspended', 'urgent', 'immediately',
    'click here', 'login', 'password', 'confirm', 'update',
    'limited', 'expire', 'unusual activity', 'security alert',
    'dear customer', 'dear user', 'congratulations', 'winner',
    'prize', 'free', 'act now', 'validate', 'authenticate',
    'your account has', 'billing', 'invoice', 'payment required'
]

URGENCY_PATTERNS = [
    'within 24 hours', 'immediately', 'urgent', 'expires today',
    'action required', 'final notice', 'last chance', 'today only'
]

def classify_email(subject, body):
    try:
        from transformers import pipeline
        text = f"{subject} {body}"[:512]
        classifier = pipeline(
            'text-classification',
            model='ealvaradob/bert-finetuned-phishing',
            truncation=True
        )
        result = classifier(text)[0]
        return {
            'method': 'bert',
            'label': result['label'],
            'is_phishing': 'phish' in result['label'].lower(),
            'confidence': round(result['score'] * 100, 2)
        }
    except Exception:
        return _keyword_classify(subject, body)

def _keyword_classify(subject, body):
    text = f"{subject} {body}".lower()
    keyword_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in text)
    urgency_hits = sum(1 for p in URGENCY_PATTERNS if p in text)
    total = keyword_hits + (urgency_hits * 2)
    confidence = min(round((total / 15) * 100, 2), 98.0)
    is_phishing = total >= 3

    return {
        'method': 'keyword',
        'label': 'PHISHING' if is_phishing else 'LEGITIMATE',
        'is_phishing': is_phishing,
        'confidence': confidence if is_phishing else round(100 - confidence, 2)
    }