"""Verify receiver attestations bound to original bytes and SMTP context."""
import hashlib
import hmac
import json
import os
import time


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode()


def sign(raw,smtp,receiver,key):
    data={'receiver':receiver,'issued_at':int(time.time()),'sha256':hashlib.sha256(raw).hexdigest(),'smtp':smtp}
    data['signature']=hmac.new(key.encode(),canonical(data),hashlib.sha256).hexdigest()
    return json.dumps(data,separators=(',',':'))


def verify(encoded,raw,keys=None):
    if len(encoded)>8192: raise ValueError('Receiver evidence exceeds size limit')
    try:
        value=json.loads(encoded)
        if not isinstance(value,dict) or set(value)!={'receiver','issued_at','sha256','smtp','signature'}:
            raise ValueError()
        receiver=value['receiver']
        if not isinstance(receiver,str) or not 1<=len(receiver)<=253: raise ValueError()
        issued=value['issued_at']
        if type(issued) is not int or not -60<=time.time()-issued<=300: raise ValueError()
        keys=keys if keys is not None else json.loads(os.getenv('RECEIVER_KEYS_JSON','{}'))
        key=keys.get(receiver) if isinstance(keys,dict) else None
        if not isinstance(key,str) or len(key.encode())<32:
            raise ValueError('Receiver is not configured for authenticated evidence')
        signature=value['signature']
        if not isinstance(signature,str) or len(signature)!=64: raise ValueError()
        unsigned={k:v for k,v in value.items() if k!='signature'}
        expected=hmac.new(key.encode(),canonical(unsigned),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,signature): raise ValueError()
        if value['sha256']!=hashlib.sha256(raw).hexdigest(): raise ValueError()
        return unsigned
    except (ValueError,TypeError,KeyError,AttributeError) as exc:
        raise ValueError('Invalid, expired, unconfigured or mismatched receiver evidence') from exc
