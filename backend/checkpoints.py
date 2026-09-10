"""Compare a separately retained checkpoint with the current session chain."""
import hashlib
import time
import store


def snapshot(sid):
    verification=store.verify(sid)
    if not verification['valid']: raise ValueError('Cannot checkpoint evidence with a failed integrity check')
    with store.connect() as db:
        rows=db.execute('SELECT payload,previous,hash FROM events WHERE session=? ORDER BY seq',(sid,)).fetchall()
    previous='0'*64
    for row in rows:
        expected=hashlib.sha256((previous+row['payload']).encode()).hexdigest()
        if row['previous']!=previous or row['hash']!=expected: raise ValueError('Evidence changed during checkpoint creation')
        previous=row['hash']
    return {'schema':1,'session_fingerprint':hashlib.sha256(sid.encode()).hexdigest(),
            'event_count':len(rows),'head':previous,'created_at':time.time(),
            'scope':'Locally generated checkpoint. Retain separately; not an independent signature or timestamp.'}


def verify(sid, checkpoint):
    if checkpoint['session_fingerprint']!=hashlib.sha256(sid.encode()).hexdigest():
        return {'valid':False,'detail':'Checkpoint belongs to another or expired session.'}
    result=store.verify(sid)
    if not result['valid']: return result
    with store.connect() as db:
        rows=db.execute('SELECT hash FROM events WHERE session=? ORDER BY seq',(sid,)).fetchall()
    count=checkpoint['event_count']
    if len(rows)<count: return {'valid':False,'detail':'The current chain is shorter than the saved checkpoint.'}
    actual=rows[count-1]['hash'] if count else '0'*64
    if actual!=checkpoint['head']: return {'valid':False,'detail':'Saved checkpoint does not match the current chain prefix.'}
    return {'valid':True,'detail':'Current evidence passes local checks and retains the saved chain prefix. This assumes your checkpoint copy was retained securely.'}
