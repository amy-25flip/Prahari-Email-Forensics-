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
    }# Phishing-specific keywords — NOT generic marketing words
PHISHING_KEYWORDS = [
    'verify your account immediately',
    'your account has been suspended',
    'unusual activity detected',
    'confirm your identity',
    'your account will be closed',
    'click here to verify',
    'update your payment information',
    'your account has been compromised',
    'unauthorized access',
    'security alert action required',
    'your password has expired',
    'validate your account',
    'suspended due to',
    'reactivate your account',
]

STRONG_PHISHING = [
    'dear customer', 'dear valued customer', 'dear user',
    'dear account holder', 'kindly update', 'kindly verify',
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

    # check strong phishing phrases first
    strong_hits = sum(1 for p in STRONG_PHISHING if p in text)
    keyword_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in text)

    total = keyword_hits * 2 + strong_hits * 3

    # high bar — needs multiple specific phishing phrases
    is_phishing = total >= 4
    confidence = min(round((total / 10) * 100, 2), 97.0) if is_phishing else round(max(85.0 - total * 5, 50.0), 2)

    return {
        'method': 'keyword',
        'label': 'PHISHING' if is_phishing else 'LEGITIMATE',
        'is_phishing': is_phishing,
        'confidence': confidence
    }