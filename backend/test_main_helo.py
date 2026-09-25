import pytest
import main


@pytest.mark.parametrize('helo', ['[192.0.2.1]', '[IPv6:2001:db8::1]', '[ipv6:2001:db8::1]', 'mx.example.org'])
def test_helo_forms_accepted(helo):
    assert main.SMTPContext(client_ip='203.0.113.5', mail_from='a@b.example', helo=helo)


@pytest.mark.parametrize('helo', ['[not-an-ip]', '[192.0.2.999]', 'bad_host!'])
def test_bad_helo_rejected(helo):
    with pytest.raises(Exception):
        main.SMTPContext(client_ip='203.0.113.5', mail_from='a@b.example', helo=helo)
