from experiments.settings import CONFIG
"""Observation-level checks of explicitly local lifecycle operations."""
import csv, os, pathlib, copy
from src.core import *
rows=[]
for run in range(CONFIG['lifecycle']['trials']):
    ed=EndDevice(); kms=KMS(); kms.register(ed); app=ApplicationServer(window_size=8)
    joined,_=establish(ed,kms,app)
    old=ed.protect(b'undelivered-old'); old_sid=ed.sid
    first=ed.protect(b'accepted'); assert app.receive(first)[0]
    keys=app.sessions[(ed.did,ed.sid)][0]
    app.install(ed.did,ed.sid,keys)
    preserved=app.receive(first)[1]=='REPLAY'
    pending=ed.join_init(); response,_=kms.process(pending); ed.invalidate()
    try: ed.accept(response); cancelled=False
    except ValueError as e: cancelled=str(e)=='STALE_JOIN'
    joined2,_=establish(ed,kms,app,retire_previous=True)
    retired=app.receive(old)[1]=='UNKNOWN_SESSION'
    fresh=ed.protect(b'fresh'); accepted=app.receive(fresh)[0]
    active=ed.protect(b'active-after-kms-revoke'); kms.revoke(ed.did)
    active_after_revoke=app.receive(active)[0]
    try: kms.process(ed.join_init()); revoked=False
    except ValueError as e: revoked=str(e)=='REVOKED_DEVICE'
    app.revoke_session(ed.did,ed.sid)
    local_revoked=app.receive(ed.protect(b'after-local-revoke'))[1]=='UNKNOWN_SESSION'
    rows.append(dict(run=run,initial_join=joined,fresh_join=joined2,sid_changed=old_sid!=ed.sid,
                     reinstall_preserves_replay=preserved,pending_cancelled=cancelled,
                     old_context_retired_locally=retired,new_message_accepted=accepted,
                     kms_revocation_blocks_join=revoked,active_survives_kms_revocation=active_after_revoke,
                     explicit_as_revocation=local_revoked))
out=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'lifecycle.csv'
with out.open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]); w.writeheader(); w.writerows(rows)
