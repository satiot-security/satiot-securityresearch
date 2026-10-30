from src.core import *

def test_revocation_blocks_join():
    ed=EndDevice(); kms=KMS(); kms.register(ed); kms.revoke(ed.did)
    try: establish(ed,kms,ApplicationServer())
    except ValueError as e: assert str(e)=='REVOKED_DEVICE'
    else: assert False

def test_old_session_rejected_after_rekey_on_new_app():
    ed=EndDevice(); kms=KMS(); kms.register(ed); app=ApplicationServer(); establish(ed,kms,app)
    old=ed.protect(b'x'); old_sid=ed.sid
    ed.invalidate(); app2=ApplicationServer(); establish(ed,kms,app2)
    assert ed.sid != old_sid
    ok,reason,_=app2.receive(old)
    assert not ok and reason=='UNKNOWN_SESSION'
