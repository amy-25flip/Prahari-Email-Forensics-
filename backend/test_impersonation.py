import json
import impersonation
import ps_assessment


def setup(monkeypatch):
    monkeypatch.setenv('PROTECTED_IDENTITIES_JSON',json.dumps([{'name':'Asha Rao','domains':['institution.example'],'addresses':['principal@institution.example']}]))


def test_named_executive_mismatch(monkeypatch):
    setup(monkeypatch)
    result=impersonation.assess('Asha Rao <outside@other.example>',[],'Please pay invoice')
    assert result['checks'][0]['title']=='Protected identity address mismatch'


def test_authorized_identity_not_flagged(monkeypatch):
    setup(monkeypatch)
    assert not impersonation.assess('Asha Rao <principal@institution.example>',[],'invoice')['checks']


def test_other_mailbox_same_domain_not_authorized(monkeypatch):
    setup(monkeypatch)
    assert impersonation.assess('Asha Rao <student@institution.example>',[],'')['checks']


def test_spelling_similarity_requires_action(monkeypatch):
    setup(monkeypatch)
    assert not impersonation.assess('news@institutoin.example',[],'News for everyone')['checks']
    assert impersonation.assess('news@institutoin.example',[],'verify password')['checks']


def test_domain_boundary(monkeypatch):
    setup(monkeypatch)
    assert impersonation.assess('a@other.example',[{'domain':'institution.example.attacker.example'}],'')['checks']
    assert not impersonation.assess('a@institution.example',[{'domain':'mail.institution.example'}],'invoice')['checks']


def test_missing_configuration_uses_india_defaults(monkeypatch):
    # Regression: an admin who never sets PROTECTED_IDENTITIES_JSON at all
    # should still get real, out-of-the-box impersonation coverage for major
    # Indian institutions, not an empty/no-op directory.
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    result=impersonation.assess('a@b.example',[],'')
    assert result['status']=='default'
    assert result['protected_identities']==len(impersonation.INDIA_DEFAULT_IDENTITIES)
    names={e['name'] for e in impersonation.INDIA_DEFAULT_IDENTITIES}
    assert 'State Bank of India' in names and 'NPCI / BHIM UPI' in names


def test_explicit_empty_configuration_is_respected_over_defaults(monkeypatch):
    # An admin who explicitly sets PROTECTED_IDENTITIES_JSON='[]' has
    # deliberately opted out -- that must NOT be silently overridden by the
    # shipped defaults, only a genuinely unset env var falls back to them.
    monkeypatch.setenv('PROTECTED_IDENTITIES_JSON','[]')
    assert impersonation.assess('a@b.example',[],'')['status']=='not_configured'


def test_default_directory_flags_a_lookalike_bank_domain(monkeypatch):
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    result=impersonation.assess('a@other.example',[{'domain':'hdfcbnk.com'}],'verify your account password')
    assert result['checks'] and 'resembles configured domain' in result['checks'][0]['detail']


def test_invalid_configuration_does_not_fall_back_to_defaults(monkeypatch):
    # A set-but-broken env var must fail closed, not silently mask the
    # mistake by falling back to the India defaults.
    monkeypatch.setenv('PROTECTED_IDENTITIES_JSON','{"x":1}')
    assert impersonation.assess('a@b.example',[],'')['status']=='invalid_configuration'


def test_low_score_finding_never_labels_legitimate(monkeypatch):
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    report={'findings':[{'title':'Reply-To domain differs'}],'ml':{'label':'legitimate'},'score':15,'authentication':{'dmarc':{'status':'unknown'}}}
    assert ps_assessment.inspect(b'From: a@b.example\r\n\r\n',report)['categories']==['suspicious']


def test_current_migrated_bank_domains_not_falsely_flagged(monkeypatch):
    # Regression (Codex Medium): RBI mandated all Indian banks migrate to
    # .bank.in (Circular RBI/2025-26/28, deadline 31 Oct 2025, already past).
    # A legitimate email from a bank's CURRENT post-migration domain must not
    # be flagged as impersonating its own legacy pre-migration identity.
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    for sender in ('alerts@bankofbaroda.bank.in','service@pnb.bank.in',
                   'notice@hdfc.bank.in','info@icici.bank.in','alerts@axis.bank.in'):
        result=impersonation.assess(sender,[],'')
        assert result['checks']==[], f'{sender} was falsely flagged: {result["checks"]}'


def test_corrected_icici_and_axis_bank_in_domains_are_the_real_ones(monkeypatch):
    # Regression: a first pass at this list (built without live web search)
    # guessed 'icicibank.bank.in' and 'axisbank.bank.in' by pattern rather
    # than verifying -- both are WRONG. A real Codex web-search pass (with
    # citations) found the actual current official domains are icici.bank.in
    # and axis.bank.in. Lock in the corrected values, and confirm the old
    # guessed-but-wrong domains are no longer what's expected (so a future
    # accidental revert back to the pattern-guessed form would fail this).
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    icici = next(e for e in impersonation.INDIA_DEFAULT_IDENTITIES if e['name'] == 'ICICI Bank')
    axis = next(e for e in impersonation.INDIA_DEFAULT_IDENTITIES if e['name'] == 'Axis Bank')
    assert 'icici.bank.in' in icici['domains'] and 'icicibank.bank.in' not in icici['domains']
    assert 'axis.bank.in' in axis['domains'] and 'axisbank.bank.in' not in axis['domains']


def test_newly_added_institutions_are_recognized_and_not_falsely_flagged(monkeypatch):
    # Spot-check a sample of the institutions added in the 2026-09-23
    # web-search-verified expansion, across banks, UPI apps, and government
    # portals -- not exhaustive, but enough to catch a wiring mistake (e.g. a
    # typo introduced while transcribing the researched domains into code).
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    for sender in ('alerts@kotak.bank.in','service@yes.bank.in','notice@canarabank.bank.in',
                   'support@cred.club','noreply@gst.gov.in','info@irctc.co.in'):
        result=impersonation.assess(sender,[],'')
        assert result['checks']==[], f'{sender} was falsely flagged: {result["checks"]}'


def test_legacy_pre_migration_bank_domains_still_recognized(monkeypatch):
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    for sender in ('alerts@bankofbaroda.in','service@pnbindia.in','notice@hdfcbank.com'):
        result=impersonation.assess(sender,[],'')
        assert result['checks']==[], f'{sender} was falsely flagged: {result["checks"]}'
