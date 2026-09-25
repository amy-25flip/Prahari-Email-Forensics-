import base64

import engine
import language_support as ls
import playbook


def _email(subject, body, extra_parts=''):
    boundary = 'BB'
    return (f'From: a@b.example\r\nTo: c@d.example\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n'
            f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
            f'--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{body}\r\n'
            f'{extra_parts}--{boundary}--').encode('utf-8')


PNG = base64.b64encode(bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea75b5e0b0000000049454e44ae426082')).decode()


def test_english_is_supported_and_others_are_not():
    assert ls.assess('Meeting', 'Please review the attached quarterly report before Friday.')['model_coverage'] == 'supported'
    hindi = ls.assess('सूचना', 'आपका बैंक खाता बंद हो जाएगा। कृपया तुरंत अपना केवाईसी अपडेट करें।')
    assert hindi['language'] == 'hindi-devanagari' and hindi['model_coverage'] == 'unsupported' and 'Devanagari' in hindi['note']
    tamil = ls.assess('அறிவிப்பு', 'உங்கள் கணக்கு முடக்கப்படும் உடனடியாக சரிபார்க்கவும் நன்றி')
    assert tamil['language'] == 'other:Tamil' and tamil['model_coverage'] == 'unsupported'


def test_hinglish_detection_needs_several_distinct_words_and_is_not_fooled_by_english():
    hinglish = ls.assess('Alert', 'Aapka account band ho jayega, kripya turant KYC update karein warna khata block hoga.')
    assert hinglish['language'] == 'hinglish' and hinglish['model_coverage'] == 'unsupported'
    assert ls.assess('Hi', 'I want to go to the park with you tomorrow if it is not raining.')['language'] == 'english'
    assert ls.assess('Hi', 'Please update the account, the ka in the file name is a typo and hai is a name.')['language'] == 'english'


def test_code_mixed_and_empty_text():
    assert ls.assess('Update', 'Your account will be blocked. आपका खाता बंद हो सकता है. Please verify now.')['language'] == 'code-mixed'
    assert ls.assess('', '')['model_coverage'] == 'unknown'
    assert ls.assess('123', '!!! ??? 456')['model_coverage'] == 'unknown'


def test_hindi_and_hinglish_rules_fire_with_english_equivalent_titles():
    kyc = {f['title'] for f in ls.rules('Aapka KYC update karein warna khata band ho jayega')}
    assert 'Credential pressure' in kyc
    pay = {f['title'] for f in ls.rules('Naye account mein paise bhejo turant')}
    assert 'Payment diversion' in pay
    avoid = {f['title'] for f in ls.rules('Yeh kisi ko mat batana aur call mat karna')}
    assert 'Verification avoidance' in avoid
    dev = {f['title'] for f in ls.rules('आपका खाता बंद हो जाएगा। नए बैंक खाते में पैसे भेजें। किसी को न बताएं।')}
    assert dev == {'Credential pressure', 'Payment diversion', 'Verification avoidance'}


def test_rules_do_not_fire_on_benign_text_or_on_urgency_alone():
    assert ls.rules('Hi team, lunch at noon. Aap sab aayein, khana milega. Dhanyavad!') == []
    assert ls.rules('Meeting notes attached. Abhi review karo when free.') == []      # urgency word without another localized rule
    assert ls.rules('') == [] and ls.rules(None) == []


def test_engine_flags_hinglish_phishing_and_reports_language_coverage():
    raw = _email('Zaruri suchna', 'Aapka SBI khata band ho jayega. Turant KYC update karein: http://sbi-kyc.example/verify')
    result = engine.analyze(raw)
    titles = {f['title'] for f in result['findings']}
    assert 'Credential pressure' in titles
    assert result['language']['language'] == 'hinglish' and result['language']['model_coverage'] == 'unsupported'
    assert any('Localized Hindi/Hinglish phrasing' in f['detail'] for f in result['findings'])


def test_english_rule_takes_precedence_and_no_duplicate_titles():
    raw = _email('Notice', 'Please verify your account now. Aapka khata band ho jayega.')
    titles = [f['title'] for f in engine.analyze(raw)['findings'] if f['group'] == 'language']
    assert titles.count('Credential pressure') == 1


def test_image_only_message_is_flagged_and_text_email_is_not():
    part = f'--BB\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: inline\r\n\r\n{PNG}\r\n'
    only = engine.analyze(_email('Invoice', '', part))
    assert any(f['title'] == 'Image-only message' for f in only['findings'])
    with_text = engine.analyze(_email('Invoice', 'Please find the invoice for last month attached, thank you and regards.', part))
    assert not any(f['title'] == 'Image-only message' for f in with_text['findings'])
    assert not any(f['title'] == 'Image-only message' for f in engine.analyze(_email('Hi', ''))['findings'])


def test_playbook_adds_language_and_image_steps():
    steps = playbook.build({'triage': {'priority': 'review'}, 'findings': [{'title': 'Image-only message'}], 'urls': [], 'attachments': [],
                            'authentication': {}, 'language': {'model_coverage': 'unsupported', 'script': 'Devanagari'}})['steps']
    text = ' '.join(s['action'] for s in steps)
    assert 'reader of this language' in text and 'isolated viewer' in text
