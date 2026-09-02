from flask import Flask, request, jsonify, render_template
from analyzer import analyze
from dkim_checker import check_dkim, extract_dkim_header
from url_scanner import scan_urls
from ml_classifier import classify_email

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    data = request.json
    raw_email = data.get('email', '')
    if not raw_email:
        return jsonify({'error': 'No email provided'}), 400

    result = analyze(raw_email)

    # body text
    body = result.get('body')
    if isinstance(body, bytes):
        body = body.decode('utf-8', errors='replace')
    result['body'] = body or ''

    # DKIM
    result['dkim'] = {
        'verification': check_dkim(raw_email),
        'header_info': extract_dkim_header(raw_email)
    }

    # boost score if DKIM fails
    if not result['dkim']['verification']['valid']:
        result['fraud_score'] = min(result['fraud_score'] + 15, 100)

    # URL scan
    url_scan = scan_urls(body)
    result['url_analysis'] = url_scan
    if url_scan['suspicious_count'] > 0:
        result['fraud_score'] = min(
            result['fraud_score'] + (url_scan['suspicious_count'] * 10), 100
        )

    # ML classification
    try:
        ml = classify_email(
            result['headers'].get('subject', ''),
            body
        )
        result['ml_classification'] = ml
        if ml['is_phishing'] and ml['confidence'] > 70:
            result['fraud_score'] = min(result['fraud_score'] + 10, 100)
    except Exception as e:
        result['ml_classification'] = {
            'method': 'error',
            'label': 'unavailable',
            'is_phishing': False,
            'confidence': 0
        }

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)