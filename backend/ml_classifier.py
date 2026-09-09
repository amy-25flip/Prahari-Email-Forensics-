"""Compatibility wrapper around process-cached local inference."""
from local_model import classify, load


def classify_email(subject, body):
    result = classify(f'{subject}\n{body}')
    return {'method': 'bert' if result['status'] == 'ready' else 'unavailable',
            'label': result['label'], 'confidence': result.get('confidence'),
            'is_phishing': 'phish' in result['label'].lower(), 'detail': result['detail']}
