"""Real local TLS transport against a mock HEC, not a Splunk server."""
import datetime
import ipaddress
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import siem
from test_selection import client, HEADERS


def test_verified_https_collector(client, tmp_path, monkeypatch):
    report=client.post('/api/samples/account',headers=HEADERS).json()
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
    cert_path,key_path=tmp_path/'test-ca.pem',tmp_path/'test-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    captured=[]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            captured.append({'path':self.path,'authorization':self.headers.get('Authorization'),
                             'body':json.loads(self.rfile.read(int(self.headers['Content-Length'])))})
            payload=b'{"text":"Success","code":0}'
            self.send_response(200)
            self.send_header('Content-Length',str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path,key_path)
    server.socket=tls.wrap_socket(server.socket,server_side=True)
    worker=threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    try:
        monkeypatch.setenv('SIEM_MODE','splunk')
        monkeypatch.setenv('SPLUNK_HEC_URL',f'https://127.0.0.1:{server.server_port}/services/collector/event')
        monkeypatch.setenv('SPLUNK_HEC_TOKEN','test-collector-token')
        monkeypatch.setenv('REQUESTS_CA_BUNDLE',str(cert_path))
        receipt=siem.deliver(report)
        assert receipt['status']=='accepted'
        assert captured[0]['path']=='/services/collector/event'
        assert captured[0]['authorization']=='Splunk test-collector-token'
        assert captured[0]['body']['event']['case_id']==report['id']
        assert report['body'] not in json.dumps(captured)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
