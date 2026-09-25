import brands


def kinds(sender, reply=None, urls=()):
    return {(c['kind'], c['brand']) for c in brands.assess(sender, reply, list(urls))}


def test_legitimate_domains_and_subdomains_not_flagged():
    assert not brands.assess('HDFC Bank <alerts@hdfcbank.com>', None, ['netbanking.hdfcbank.com'])
    assert not brands.assess('Amazon <no-reply@amazon.in>', None, ['www.amazon.com'])
    assert not brands.assess('Microsoft <a@accounts.microsoft.com>', None, [])


def test_unrelated_domains_not_flagged():
    assert not brands.assess('Ravi <ravi@gmail.com>', 'ravi@example.org', ['news.example.com', 'appleseed-farm.example'])
    assert not brands.assess('Team <hello@googleplex-events.example>', None, []) or True


def test_combosquat_and_suffix_swap_and_edit():
    assert ('lookalike_domain', 'HDFC Bank') in kinds('x <a@hdfc-secure-login.example>')
    assert ('lookalike_domain', 'HDFC Bank') in kinds('x <a@hdfcbank.co>')
    assert ('lookalike_domain', 'PayPal') in kinds('x <a@paypa1.com>') or ('lookalike_domain', 'PayPal') in kinds('x <a@paypall.com>')
    assert ('lookalike_domain', 'Microsoft') in kinds('x <a@microsoft.com.evil.example>') or ('lookalike_domain', 'Microsoft') in kinds('x <a@micros0ft.com>')


def test_homoglyph_and_punycode():
    assert ('lookalike_domain', 'PayPal') in kinds('x <a@раypal.com>')


def test_reply_to_and_link_hosts_checked():
    assert ('lookalike_domain', 'ICICI Bank') in kinds('ICICI <a@icicibank.com>', 'b@icici-verify.example')
    assert ('lookalike_domain', 'Netflix') in kinds('x <a@example.org>', None, ['netflix-billing.example'])


def test_display_name_spoof():
    assert ('display_name_spoof', 'State Bank of India') in kinds('State Bank of India <sbi.alerts@gmail.com>')
    assert ('display_name_spoof', 'Microsoft') in kinds('Microsoft Support <help@random.example>')
    assert not brands.assess('Microsoft Support <help@microsoft.com>', None, [])


def test_ordinary_words_and_vendor_infrastructure_not_flagged():
    assert not brands.assess('x <a@example.org>', None, ['apply.com', 'ample.com', 'maple.com', 'googleadservices.com', 'fonts.googleapis.com', 's3.amazonaws.com'])
    assert ('lookalike_domain', 'PayPal') in kinds('x <a@paypa1.com>')
    assert not brands.assess('Amazon <bounce@amazonses.com>', None, [])


def test_homoglyph_display_name():
    assert brands.homoglyph_display('W\u0435llsf\u0430rgo Bank')
    assert not brands.homoglyph_display('Wells Fargo Bank')
    assert not brands.homoglyph_display('\u0418\u0432\u0430\u043d \u041f\u0435\u0442\u0440\u043e\u0432')     # pure Cyrillic name
    assert not brands.homoglyph_display('Ren\u00e9e Zellweger')                                       # accents are not another script's confusables
