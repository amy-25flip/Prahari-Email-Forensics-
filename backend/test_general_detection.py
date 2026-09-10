import general_detection
import origin_assessment
import engine


def test_bec_pattern_without_staff_directory():
    checks=general_detection.language_checks('Urgent',"I am your CEO. Buy gift cards today. Do not call me.")
    assert len(checks)==2


def test_executive_news_does_not_trigger():
    assert not general_detection.language_checks('Company news','The CEO discussed the annual budget and invoice processing.')
    assert not general_detection.language_checks('Hello','I am your CEO. Welcome to the company.')


def test_obfuscated_url_and_redirect():
    reasons=general_detection.url_signals('https://%65xample.com/?next=https%253A%252F%252Fother.example%252Flogin')
    assert 'Percent-encoded authority obscures destination' in reasons
    assert 'Redirect parameter points to another host' in reasons
    assert general_detection.url_signals('http://2130706433/login')


def test_normal_url_not_obfuscated():
    assert not general_detection.url_signals('https://example.com/?next=%2Finbox')
    assert not general_detection.url_signals('https://example.com/path?next=https%3A%2F%2Fexample.com%2Finbox')


def test_excessive_query_fields_do_not_crash():
    result=engine.scan_url('https://example.com/?'+'&'.join('a=1' for _ in range(101)))
    assert 'Query inspection limit reached' in result['reasons']


def test_origin_never_trusts_headers_alone():
    report={'hops':[{'index':1,'ips':['10.0.0.1','8.8.8.8']}],'geo':[]}
    result=origin_assessment.assess(report)
    assert result['earliest_reported_public_node']['ip']=='8.8.8.8'
    assert result['earliest_reliable_node'] is None and result['confidence']=='low'
    conditional=origin_assessment.assess(report,{'client_ip':'1.1.1.1'})
    assert conditional['receiver_ip_in_headers'] is False
    assert conditional['earliest_reliable_node'] is None


def test_no_origin_evidence():
    assert origin_assessment.assess({'hops':[]})['confidence']=='undetermined'
