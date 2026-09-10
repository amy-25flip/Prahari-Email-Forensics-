import domain_evidence


def test_internal_resemblance_needs_no_directory():
    report={'sender':'a@institution.example','subject':'Verify account','urls':[{'domain':'institutoin.example'}]}
    assert domain_evidence.compare(report)
    report['urls']=[{'domain':'mail.institution.example'}]
    assert not domain_evidence.compare(report)


def test_unrelated_delegation_not_a_lookalike():
    assert not domain_evidence.compare({'sender':'a@institution.example','body':'invoice','urls':[{'domain':'payments.example'}]})


def test_fingerprint_order_stable_and_no_empty_collision():
    a={'domain_intelligence':{'dns':{'MX':{'values':['20 b.example.','10 a.example.']}}}}
    b={'domain_intelligence':{'dns':{'MX':{'values':['10 a.example.','20 b.example.']}}}}
    assert domain_evidence.fingerprint(a)['sha256']==domain_evidence.fingerprint(b)['sha256']
    assert domain_evidence.fingerprint({})['sha256'] is None
