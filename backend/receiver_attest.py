"""Run only within the trusted receiver/log-export environment, not for arbitrary uploads."""
import argparse
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from receiver_evidence import canonical


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--email',required=True,help='Original email recorded by the receiver')
    parser.add_argument('--smtp-record',required=True,help='Receiver log export JSON: client_ip, mail_from, helo')
    parser.add_argument('--receiver',required=True)
    args=parser.parse_args()
    key=os.getenv('RECEIVER_SIGNING_KEY','')
    if len(key.encode())<32: parser.error('Configure RECEIVER_SIGNING_KEY with at least 32 random bytes of secret material')
    raw=Path(args.email).read_bytes()
    if not 0<len(raw)<=1048576:parser.error('Email must be at most 1 MiB')
    record=Path(args.smtp_record)
    if record.stat().st_size>2048:parser.error('SMTP record too large')
    smtp=json.loads(record.read_text(encoding='utf-8-sig'))
    if not isinstance(smtp,dict) or set(smtp)!={'client_ip','mail_from','helo'}:parser.error('Invalid SMTP record fields')
    data={'receiver':args.receiver,'issued_at':int(time.time()),'sha256':hashlib.sha256(raw).hexdigest(),'smtp':smtp}
    data['signature']=hmac.new(key.encode(),canonical(data),hashlib.sha256).hexdigest()
    print(json.dumps(data,separators=(',', ':')))


if __name__=='__main__':main()
