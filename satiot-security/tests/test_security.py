import copy
from unittest.mock import patch
import pytest
from src.core import *

def setup(window=8,did='ED0001'):
    ed=EndDevice(did); kms=KMS(); kms.register(ed); app=ApplicationServer(window)
    assert establish(ed,kms,app)[0]
    return ed,kms,app

def test_invalidation_cancels_delayed_accept():
    ed,kms,app=setup(); ja,_=kms.process(ed.join_init()); ed.invalidate()
    with pytest.raises(ValueError,match='STALE_JOIN'): ed.accept(ja)
    with pytest.raises(ValueError,match='NO_SESSION'): ed.protect(b'x')

def test_install_is_idempotent_and_conflicting_install_rejected():
    ed,kms,app=setup(); m=ed.protect(b'x'); assert app.receive(m)[0]
    keys=app.sessions[(ed.did,ed.sid)][0]; state=app.sessions[(ed.did,ed.sid)][1]
    app.install(ed.did,ed.sid,keys); assert app.sessions[(ed.did,ed.sid)][1] is state
    assert app.receive(m)[1]=='REPLAY'
    with pytest.raises(ValueError,match='CONFLICTING_SESSION'):
        app.install(ed.did,ed.sid,dict(keys,k_up=b'X'*32))
    assert app.receive(m)[1]=='REPLAY'

def test_local_replacement_retires_undelivered_old_message():
    ed,kms,app=setup(); old=ed.protect(b'old')
    ed.invalidate(); assert establish(ed,kms,app,retire_previous=True)[0]
    assert app.receive(old)[1]=='UNKNOWN_SESSION'; assert app.receive(ed.protect(b'new'))[0]

def test_coexistence_and_distributed_retirement_boundary():
    ed,kms,app=setup(); old=ed.protect(b'old'); ed.invalidate()
    app2=ApplicationServer(); assert establish(ed,kms,app2,retire_previous=True)[0]
    assert app.receive(old)[0]  # Replacement on another AS cannot retire this AS.

def test_kms_revocation_only_blocks_new_join():
    ed,kms,app=setup(); kms.revoke(ed.did)
    assert app.receive(ed.protect(b'active'))[0]
    with pytest.raises(ValueError,match='REVOKED_DEVICE'): kms.process(ed.join_init())
    app.revoke_session(ed.did,ed.sid); assert app.receive(ed.protect(b'local'))[1]=='UNKNOWN_SESSION'

def test_request_replay_is_not_claimed_prevented():
    ed,kms,app=setup(); ji=ed.join_init(); a,_=kms.process(ji); b,_=kms.process(ji)
    assert a.sid!=b.sid  # Limitation: both authenticated requests are processed.

def test_auth_failure_does_not_advance_window():
    ed,kms,app=setup(); legitimate=ed.protect(b'x'); bad=copy.deepcopy(legitimate)
    bad.seq=1000; assert app.receive(bad)[1]=='AUTH_FAILURE'
    rw=app.sessions[(ed.did,ed.sid)][1]; assert rw.highest==-1 and not rw.seen
    assert app.receive(legitimate)[0]

@pytest.mark.parametrize('field,value',[('seq',-1),('seq',2**64),('mtype',256),('sid',-1),('did',''),('tag',b'x'),('ciphertext','bad')])
def test_malformed_rejection(field,value):
    ed,kms,app=setup(); m=ed.protect(b'x'); setattr(m,field,value)
    assert app.receive(m)[1]=='MALFORMED'
    assert app.sessions[(ed.did,ed.sid)][1].highest==-1

def test_counter_exhaustion_requires_fresh_session():
    ed,kms,app=setup(); ed.seq=2**64-1; assert app.receive(ed.protect(b'last'))[0]
    with pytest.raises(ValueError,match='COUNTER_EXHAUSTED'): ed.protect(b'x')
    ed.invalidate(); establish(ed,kms,app,retire_previous=True); assert ed.seq==0

def test_window_lower_boundary():
    rw=ReplayWindow(8); rw.commit(10)
    assert not rw.check(2); assert rw.check(3); rw.commit(3); assert not rw.check(3)

def test_nonce_reuse_is_negative_control():
    ed,kms,app=setup(); a=ed.protect(b'A'*16); assert app.receive(a)[0]; ed.seq=0
    b=ed.protect(b'B'*16)
    assert bytes(x^y for x,y in zip(a.ciphertext,b.ciphertext))==bytes([3]*16)
    assert app.receive(b)[1]=='REPLAY'  # Rejection cannot repair leaked XOR.

def test_safe_recovery_changes_key_and_nonce():
    ed,kms,app=setup(); old_key=ed.keys['k_up']; old_nonce=nonce(ed.keys['nonce_prefix'],0)
    ed.invalidate(); establish(ed,kms,app,retire_previous=True)
    assert old_key!=ed.keys['k_up']; assert old_nonce!=nonce(ed.keys['nonce_prefix'],0)
    assert app.receive(ed.protect(b'after-recovery'))[0]

@pytest.mark.parametrize('offset,expected',[(0,True),(10,True),(11,False),(15,False),(20,False),(30,False)])
def test_contact_completion_boundary(offset,expected):
    ed=EndDevice(); kms=KMS(); kms.register(ed); app=ApplicationServer()
    relay=ContactWindowRelay(30,90,delay_ms=10); relay.advance(offset)
    assert establish(ed,kms,app,relay)[0] is expected

def test_shifted_contact():
    r=ContactWindowRelay(30,90,start_available=False,delay_ms=10)
    assert not r.is_available(); r.advance(90); assert r.is_available()
    assert r.deliver('x')=='x'; r.advance(15); assert r.deliver('x') is None

def test_join_response_wrong_device_and_tamper():
    ed=EndDevice(); kms=KMS(); kms.register(ed); ja,_=kms.process(ed.join_init())
    bad=copy.deepcopy(ja); bad.did='ED0002'
    with pytest.raises(ValueError,match='WRONG_DEVICE'): ed.accept(bad)
    bad=copy.deepcopy(ja); bad.ns=b'X'*16
    with pytest.raises(ValueError,match='INVALID_MAC'): ed.accept(bad)
    ed.accept(ja)
    with pytest.raises(ValueError,match='STALE_JOIN'): ed.accept(ja)

def test_cross_installed_context_substitution():
    a,kms,app=setup(); b=EndDevice('ED0002'); kms.register(b); establish(b,kms,app)
    m=a.protect(b'x'); x=copy.deepcopy(m); x.did=b.did; x.sid=b.sid
    assert app.receive(x)[1]=='AUTH_FAILURE'
    assert app.receive(m)[0]; assert app.receive(b.protect(b'legitimate'))[0]

def test_sid_collision_does_not_reset_context():
    ed,kms,app=setup(); sid=ed.sid
    with patch('src.core.secrets.randbits',return_value=sid):
        with pytest.raises(ValueError,match='SID_EXHAUSTED'): kms.process(ed.join_init())

def test_wire_roundtrip_sizes_and_parser():
    ed,kms,app=setup(); ji=ed.join_init(); ja,_=kms.process(ji); ed.accept(ja)
    m=ed.protect(b'12345678')
    assert (len(ji.wire()),len(ja.wire()),len(m.wire())-8)==(44,64,44)
    for obj,kind in [(ji,'join_init'),(ja,'join_accept'),(m,'protected')]:
        assert decode_wire(obj.wire(),kind)==obj
        for data in [obj.wire()[:-1],obj.wire()+b'x',b'\x02'+obj.wire()[1:]]:
            with pytest.raises(ValueError): decode_wire(data,kind)
    bad=bytearray(m.wire()); bad[24]=1  # Direction byte for 6-byte DID.
    with pytest.raises(ValueError): decode_wire(bytes(bad),'protected')

def test_hkdf_rfc5869_vector():
    actual=hkdf(bytes.fromhex('0b'*22),bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'),bytes.fromhex('000102030405060708090a0b0c'),42)
    assert actual.hex()=='3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'

def test_pending_join_overwritten_response_rejected():
    ed,kms,app=setup(); a,_=kms.process(ed.join_init()); b,_=kms.process(ed.join_init())
    with pytest.raises(ValueError,match='STALE_JOIN'): ed.accept(a)
    ed.accept(b)

def test_dropped_accept_keeps_prior_context_without_installation():
    ed,kms,app=setup(); old_sid=ed.sid; old_keys=ed.keys.copy()
    class DropAccept:
        def deliver(self,obj): return None if isinstance(obj,JoinAccept) else obj
    assert establish(ed,kms,app,DropAccept(),retire_previous=True)[1]=='JOIN_ACCEPT_DROPPED'
    assert ed.sid==old_sid and ed.keys==old_keys and len(app.sessions)==1
    assert app.receive(ed.protect(b'prior-session'))[0]

def test_invalid_join_does_not_issue_session():
    ed=EndDevice(); kms=KMS(); kms.register(ed); ji=ed.join_init(); ji.tag=b'X'*16
    with pytest.raises(ValueError,match='INVALID_MAC'): kms.process(ji)
    assert not kms.issued
    ji=ed.join_init(); ji.epoch+=1
    with pytest.raises(ValueError,match='STALE_EPOCH'): kms.process(ji)
    assert not kms.issued

def test_parser_rejects_invalid_ciphertext_length():
    ed,kms,app=setup(); m=ed.protect(b'hello'); data=bytearray(m.wire())
    data[26:28]=(1).to_bytes(2,'big')
    with pytest.raises(ValueError): decode_wire(bytes(data),'protected')

def test_end_to_end_serialized_exchange_and_plaintext():
    ed=EndDevice(); kms=KMS(); kms.register(ed); app=ApplicationServer()
    ji=decode_wire(ed.join_init().wire(),'join_init'); ja,keys=kms.process(ji)
    ed.accept(decode_wire(ja.wire(),'join_accept')); app.install(ed.did,ed.sid,keys)
    payload=b'serialized P1 roundtrip'
    obj=decode_wire(ed.protect(payload).wire(),'protected')
    assert app.receive(obj)==(True,'ACCEPT',payload)
    assert app.receive(obj)[1]=='REPLAY'

def test_airtime_known_arithmetic():
    assert lora_airtime_ms(21,sf=7)==pytest.approx(56.576)
    assert lora_airtime_ms(21,sf=12)==pytest.approx(1482.752)
