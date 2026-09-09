"""Explain review priority separately from an uncalibrated evidence score."""
import math


def high_model_signal(prediction):
    value = prediction.get('phishing_probability')
    return (prediction.get('status') == 'ready' and isinstance(value, (int, float))
            and not isinstance(value, bool) and math.isfinite(value) and 90 <= value <= 100)


def assess(score, findings, prediction, urls):
    titles = {f['title'] for f in findings}
    strong_model = high_model_signal(prediction)
    deceptive_link = any('Displayed URL differs from destination' in u.get('reasons', []) for u in urls)
    payment_pair = {'Payment diversion', 'Verification avoidance'} <= titles
    fresh_match = 'PhishTank URL match' in titles
    corroborated = strong_model and (deceptive_link or 'Credential pressure' in titles or 'Payment diversion' in titles)
    reasons = []
    if fresh_match: reasons.append('A URL matches the current local phishing-feed snapshot.')
    if payment_pair: reasons.append('Payment-change language appears alongside avoidance of independent verification.')
    if corroborated: reasons.append('A strong model phishing signal is supported by credential, payment, or deceptive-link evidence.')
    if score >= 60: reasons.append('The grouped evidence score reaches the high-review threshold.')
    if reasons:
        priority, label = 'urgent', 'Urgent review'
        action = 'Do not act on payment or credential requests until independently verified; avoid opening email links.'
    elif findings or strong_model:
        priority, label = 'review', 'Review required'
        reasons.append('Detection signals require assessment; model probability and evidence score measure different things.')
        action = 'Review the cited findings and verify sensitive requests through an independently known channel.'
    elif prediction.get('status') != 'ready':
        priority, label = 'incomplete', 'Assessment incomplete'
        reasons.append('The NLP model did not return an available prediction, and configured rules found no signals.')
        action = 'Repeat with the model available or perform manual review before relying on this result.'
    else:
        priority, label = 'routine', 'No elevated signals found'
        reasons.append('Available checks found no configured risk indicators; this does not establish safety.')
        action = 'Follow normal verification procedures for sensitive requests.'
    return {'priority': priority, 'label': label, 'reasons': reasons, 'action': action,
            'policy': 'triage-v1; provisional analyst-review policy, not a calibrated fraud probability',
            'score_explanation': 'The score adds capped evidence groups. NLP probability describes the model output, not the probability of fraud. Review priority can escalate without changing the score.',
            'model_corroborated': corroborated}
