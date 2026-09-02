from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from analyzer import analyze
from dkim_checker import check_dkim, extract_dkim_header
from url_scanner import scan_urls
from ml_classifier import classify_email

app = FastAPI(title="Email Forensic Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    email: str

@app.get("/")
def root():
    return {"status": "EFP API running"}

@app.post("/analyze")
async def analyze_email(req: EmailRequest):
    raw_email = req.email
    result = analyze(raw_email)

    body = result.get('body')
    if isinstance(body, bytes):
        body = body.decode('utf-8', errors='replace')
    result['body'] = body or ''

    result['dkim'] = {
        'verification': check_dkim(raw_email),
        'header_info': extract_dkim_header(raw_email)
    }

    if not result['dkim']['verification']['valid']:
        result['fraud_score'] = min(result['fraud_score'] + 15, 100)

    url_scan = scan_urls(body)
    result['url_analysis'] = url_scan
    if url_scan['suspicious_count'] > 0:
        result['fraud_score'] = min(
            result['fraud_score'] + (url_scan['suspicious_count'] * 10), 100
        )

    try:
        ml = classify_email(result['headers'].get('subject', ''), body)
        result['ml_classification'] = ml
        if ml['is_phishing'] and ml['confidence'] > 70:
            result['fraud_score'] = min(result['fraud_score'] + 10, 100)
    except Exception:
        result['ml_classification'] = {
            'method': 'error',
            'label': 'unavailable',
            'is_phishing': False,
            'confidence': 0
        }

    return result