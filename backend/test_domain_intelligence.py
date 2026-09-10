import pytest
import domain_intelligence as di

@pytest.fixture(autouse=True)
def reset():
    di.cache.clear()
    di.bootstrap.update(expires=0,services=[])

def test_disabled_never_network(monkeypatch):
    monkeypatch.setattr(di,'fetch_json',lambda *a:pytest.fail('Unexpected network'))
    assert di.lookup('google.com',False)['status']=='disabled'

@pytest.mark.parametrize('domain',['localhost','x.invalid','x.example','x.test','evil.com/secret','a@google.com'])
def test_invalid_domains_not_queried(monkeypatch,domain):
    monkeypatch.setattr(di,'dns_record',lambda *a:pytest.fail('Unexpected DNS'))
    assert di.lookup(domain,True)['status']=='not_public'

def test_rdap_from_iana_and_redacted(monkeypatch):
    def fetch(url):
        if url=='https://data.iana.org/rdap/dns.json':return {'services':[[['com'],['https://registry.test/v1/']]]}
        assert url=='https://registry.test/v1/domain/example.com'
        return {'events':[{'eventAction':'registration','eventDate':'2000-01-01T00:00:00Z'}],
                'entities':[{'roles':['registrar'],'vcardArray':['vcard',[['fn',{},'text','Registrar']]]},
                            {'roles':['registrant'],'vcardArray':['vcard',[['fn',{},'text','Private Person']]]}]}
    monkeypatch.setattr(di,'fetch_json',fetch)
    result=di.registration('example.com')
    assert result['registrar']=='Registrar'
    assert 'Private Person' not in str(result)

def test_cached_lookup(monkeypatch):
    monkeypatch.setattr(di,'dns_record',lambda *a:{'status':'available','values':['fixture']})
    monkeypatch.setattr(di,'registration',lambda *a:{'status':'available'})
    result=di.lookup('example.com',True)
    assert not result['cached']
    result['dns']['MX']['values'].append('changed')
    assert di.lookup('example.com',True)['dns']['MX']['values']==['fixture']
    assert di.lookup('example.com',True)['cached']

def test_dns_timeout_is_unavailable(monkeypatch):
    def fail(*a,**k): raise di.dns.resolver.LifetimeTimeout()
    monkeypatch.setattr(di.dns.resolver,'resolve',fail)
    assert di.dns_record('example.com','MX')['status']=='unavailable'

def test_registry_failure_is_unavailable(monkeypatch):
    def fail(*a):raise ValueError('invalid response')
    monkeypatch.setattr(di,'fetch_json',fail)
    assert di.registration('example.com')['status']=='unavailable'
