"""Language/script coverage and transparent Hindi/Hinglish phishing heuristics.

The content classifier is English-trained. Rather than pretend otherwise, we (1) detect the script and
likely language, (2) tell the analyst when the model is outside its validated coverage, and (3) apply a
small, readable, review-level rule set for Hindi (Devanagari) and Hinglish (romanized Hindi) phrasing.
These are localized heuristics, not a trained multilingual model, and they are not accuracy evidence."""
import re
import unicodedata

SAMPLE_CHARS = 4000
INDIC_AND_OTHER_SCRIPTS = {
    'DEVANAGARI': 'Devanagari', 'BENGALI': 'Bengali', 'GURMUKHI': 'Gurmukhi', 'GUJARATI': 'Gujarati', 'ORIYA': 'Odia',
    'TAMIL': 'Tamil', 'TELUGU': 'Telugu', 'KANNADA': 'Kannada', 'MALAYALAM': 'Malayalam', 'ARABIC': 'Arabic/Urdu',
    'CYRILLIC': 'Cyrillic', 'CJK': 'Chinese/Japanese', 'HANGUL': 'Korean', 'THAI': 'Thai', 'HEBREW': 'Hebrew', 'GREEK': 'Greek',
}
MIXED_THRESHOLD = 0.05
DOMINANT_THRESHOLD = 0.30

# Romanized-Hindi function/phishing words. Ambiguous English homographs (to, me, ho, par, din, lie) are deliberately omitted.
HINGLISH_WORDS = frozenset('''hai hain ka ki ke ko aap aapka aapki aapke apna apne karo karen karein kijiye kariye nahi nahin jaldi turant abhi
band hoga jayega jayegi jaega khata khaata paise paisa bhejo bhejen batana batayein mat kripya dhanyavad shukriya warna varna ghante
liye isliye kya yeh woh sabhi rupaye kripaya dijiye lijiye milega milegi'''.split())

_FLAGS = re.I | re.S
RULES = [
    ('Credential pressure', [
        r'(kyc|otp|pan\s*card|aadhaar|aadhar).{0,40}(update|verify|expire|band|block|link)',
        r'(update|verify|complete)\s+(your\s+)?(kyc|otp)',
        r'(khata|khaata|account)\s+(band|block|freeze|suspend)',
        r'(khata|khaata|account).{0,30}(band|block|suspend).{0,25}(ho\s*jayega|ho\s*jaega|hoga|ho\s*jayegi)',
        r'(केवाईसी|केवाइसी|ओटीपी|आधार|पैन).{0,40}(अपडेट|सत्यापित|बंद|ब्लॉक|समाप्त)',
        r'(खाता|अकाउंट).{0,25}(बंद|ब्लॉक|निलंबित|फ्रीज)',
    ]),
    ('Payment diversion', [
        r'(paise|paisa|rupaye|payment|raashi).{0,40}(bhejo|bhejen|transfer|naye\s+account|new\s+account|naye\s+khate)',
        r'(naye|naya|new)\s+(bank\s+)?(account|khata|khate)\s+(mein|me|par|number)',
        r'upi.{0,30}(bhejo|par\s+bhej|pe\s+bhej)',
        r'(पैसे|भुगतान|राशि).{0,40}(भेजें|भेजो|ट्रांसफर|नए\s+(बैंक\s+)?(खाते|अकाउंट))',
        r'नए\s+(बैंक\s+)?(खाते|अकाउंट)\s+में',
    ]),
    ('Verification avoidance', [
        r'kisi\s+(ko|se)\s+(mat\s+)?(batana|batayein|kahna|kehna)',
        r'(call|phone|sampark)\s+mat\s+kar',
        r'(gopniya|confidential)\s+(rakhein|rakhen|rakho)',
        r'किसी\s+को\s+(मत|न)\s+(बताएं|बताना|बताओ)',
        r'(फोन|कॉल)\s+(मत|न)\s+करें',
    ]),
]
_COMPILED = [(title, [re.compile(p, _FLAGS) for p in patterns]) for title, patterns in RULES]
URGENCY = [re.compile(p, _FLAGS) for p in (
    r'\b(turant|jaldi|abhi)\b.{0,50}\b(verify|update|click|link|bhejo|karo|karein|jama)',
    r'\b(24|48)\s*(ghante|ghanton)\b',
    r'(तुरंत|जल्दी|अभी).{0,40}(सत्यापित|अपडेट|क्लिक|लिंक|भेजें|करें)',
)]


def _script_of(ch):
    if ch.isascii():
        return 'LATIN' if ch.isalpha() else None
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, '')
    first = name.split(' ')[0] if name else ''
    return 'CJK' if first in ('CJK', 'HIRAGANA', 'KATAKANA') else first


def profile(text):
    """Share of letters per script over the first SAMPLE_CHARS characters."""
    counts, total = {}, 0
    for ch in (text or '')[:SAMPLE_CHARS]:
        script = _script_of(ch)
        if script:
            counts[script] = counts.get(script, 0) + 1
            total += 1
    return {k: v / total for k, v in counts.items()} if total else {}


def hinglish_score(text):
    """(distinct romanized-Hindi words, share of Latin words) for Latin-script text."""
    words = re.findall(r'[a-z]+', (text or '')[:SAMPLE_CHARS].lower())
    if not words:
        return 0, 0.0
    hits = [w for w in words if w in HINGLISH_WORDS]
    return len(set(hits)), len(hits) / len(words)


def assess(subject, body):
    text = f'{subject or ""}\n{body or ""}'
    shares = profile(text)
    if not shares:
        return {'language': 'unknown', 'script': 'none', 'model_coverage': 'unknown',
                'note': 'Too little text to determine the language; the content model result may be unreliable.'}
    top_script, top_share = max(shares.items(), key=lambda kv: kv[1])
    non_latin = {k: v for k, v in shares.items() if k != 'LATIN'}
    non_latin_total = sum(non_latin.values())
    if non_latin_total >= DOMINANT_THRESHOLD and top_script != 'LATIN':
        name = INDIC_AND_OTHER_SCRIPTS.get(top_script, top_script.title())
        language = 'hindi-devanagari' if top_script == 'DEVANAGARI' else f'other:{name}'
        return {'language': language, 'script': name, 'model_coverage': 'unsupported',
                'note': f'Text is mainly in {name} script. The content model is English-trained and not validated for it; '
                        'rely on the structural evidence (authentication, links, infrastructure) and localized keyword rules, and have a reader of this language review the message.'}
    if non_latin_total >= MIXED_THRESHOLD:
        return {'language': 'code-mixed', 'script': 'Latin + ' + INDIC_AND_OTHER_SCRIPTS.get(max(non_latin, key=non_latin.get), 'other'),
                'model_coverage': 'unsupported',
                'note': 'Text mixes English with another script. The English-trained content model may under- or over-react; weigh structural evidence more heavily.'}
    distinct, share = hinglish_score(text)
    if distinct >= 3 and share >= 0.12:
        return {'language': 'hinglish', 'script': 'Latin (romanized Hindi)', 'model_coverage': 'unsupported',
                'note': 'Text appears to be romanized Hindi (Hinglish). The content model is English-trained and not validated for it; localized keyword rules are applied and structural evidence should weigh more.'}
    return {'language': 'english', 'script': 'Latin', 'model_coverage': 'supported',
            'note': 'Latin-script text treated as English (the model\'s validated language).'}


def rules(text):
    """Review-level findings from Hindi/Hinglish phrasing. Titles match the English rules so downstream logic treats them alike."""
    text = (text or '')[:100000]
    findings = []
    for title, patterns in _COMPILED:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                findings.append({'group': 'language', 'title': title, 'points': 10,
                                 'detail': f'Localized Hindi/Hinglish phrasing: {match[0][:120]} (keyword heuristic, not a trained multilingual model)'})
                break
    if findings and not any(f['title'] == 'Credential pressure' for f in findings):
        for pattern in URGENCY:
            match = pattern.search(text)
            if match:
                findings.append({'group': 'language', 'title': 'Credential pressure', 'points': 10,
                                 'detail': f'Localized urgency phrasing: {match[0][:120]} (keyword heuristic)'})
                break
    return findings
