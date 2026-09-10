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


def test_missing_and_invalid_configuration(monkeypatch):
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    assert impersonation.assess('a@b.example',[],'')['status']=='not_configured'
    monkeypatch.setenv('PROTECTED_IDENTITIES_JSON','{"x":1}')
    assert impersonation.assess('a@b.example',[],'')['status']=='invalid_configuration'


def test_low_score_finding_never_labels_legitimate(monkeypatch):
    monkeypatch.delenv('PROTECTED_IDENTITIES_JSON',raising=False)
    report={'findings':[{'title':'Reply-To domain differs'}],'ml':{'label':'legitimate'},'score':15,'authentication':{'dmarc':{'status':'unknown'}}}
    assert ps_assessment.inspect(b'From: a@b.example\r\n\r\n',report)['categories']==['suspicious']
