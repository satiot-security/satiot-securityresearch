from src.core import *

def test_replay_window_accepts_reordered_once():
    ed=EndDevice();kms=KMS();kms.register(ed);app=ApplicationServer(window_size=8);establish(ed,kms,app)
    ms=[ed.protect(str(i).encode()) for i in range(4)]
    assert app.receive(ms[0])[0]
    assert app.receive(ms[1])[0]
    assert app.receive(ms[3])[0]
    assert app.receive(ms[2])[0]
    assert not app.receive(ms[2])[0]

def test_strict_rejects_reordered_old_packet():
    ed=EndDevice();kms=KMS();kms.register(ed);app=ApplicationServer(window_size=0);establish(ed,kms,app)
    ms=[ed.protect(str(i).encode()) for i in range(4)]
    assert app.receive(ms[0])[0]
    assert app.receive(ms[3])[0]
    assert app.receive(ms[2])[1]=='REPLAY'

def test_safe_rejoin_changes_session():
    ed=EndDevice();kms=KMS();kms.register(ed);app=ApplicationServer();establish(ed,kms,app); sid=ed.sid
    ed.invalidate(); app2=ApplicationServer();establish(ed,kms,app2)
    assert ed.sid!=sid
