import engine


def test_html_text_nested_anchor_keeps_outer_link():
    # html.parser is a permissive tokenizer, not a real HTML5 tree
    # constructor -- it does not auto-close an outer <a> when another <a>
    # starts inside it (real browsers do). Confirmed real bug: a single
    # self.current slot meant the inner </a> erased tracking of the outer
    # link before it was ever recorded.
    parser = engine.HTMLText()
    parser.feed('<a href="http://evil.example/verify"><a href="http://benign.example">click</a></a>')
    hrefs = [link[0] for link in parser.links]
    assert 'http://evil.example/verify' in hrefs
    assert 'http://benign.example' in hrefs
    assert len(parser.links) == 2


def test_html_text_sequential_anchors_still_both_recorded():
    parser = engine.HTMLText()
    parser.feed('<a href="http://a.example">a</a><a href="http://b.example">b</a>')
    hrefs = [link[0] for link in parser.links]
    assert hrefs == ['http://a.example', 'http://b.example']


def test_html_text_unclosed_anchor_is_dropped_not_crashed():
    parser = engine.HTMLText()
    parser.feed('<a href="http://a.example">a')
    assert parser.links == []


def test_scan_url_flags_malformed_idna_host_instead_of_dropping_it():
    # A host with an empty DNS label fails .encode('idna') with UnicodeError.
    # This must surface as a flagged, scored URL -- not silently vanish from
    # urls/findings/indicators as if the link never existed.
    result = engine.scan_url('http://accounts.example..com/verify')
    assert result is not None
    assert 'Malformed or invalid host encoding' in result['reasons']
    assert result['score'] > 0


def test_scan_url_missing_host_still_returns_none():
    result = engine.scan_url('http:///just-a-path')
    assert result is None


def test_scan_url_well_formed_host_unaffected():
    result = engine.scan_url('https://example.com/page')
    assert result is not None
    assert 'Malformed or invalid host encoding' not in result['reasons']
