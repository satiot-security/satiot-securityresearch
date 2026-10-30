from experiments.settings import CONFIG
import csv,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from src.core import *
import os
OUT=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'state_rollback.csv'
rows=[]
for mode in CONFIG['rollback']['modes']:
  for run in range(CONFIG['rollback']['trials_per_mode']):
    ed=EndDevice();kms=KMS();kms.register(ed);app=ApplicationServer();establish(ed,kms,app)
    accepted=[]
    for _ in range(5):
      m=ed.protect(b'x'); accepted.append(app.receive(m)[0])
    old_sid=ed.sid; old_key=ed.keys['k_up']; old_nonce=nonce(ed.keys['nonce_prefix'],2)
    if mode=='unsafe_resume':
      ed.seq=CONFIG['rollback']['restored_sequence']  # Deliberate fault injection; outside the operational interface.
      m=ed.protect(b'after-crash');ok,reason,_=app.receive(m)
      new_sid=ed.sid
    else:
      ed.invalidate(); establish(ed,kms,app,retire_previous=True); m=ed.protect(b'after-crash');ok,reason,_=app.receive(m); new_sid=ed.sid
    rows.append(dict(mode=mode,run=run,post_crash_accepted=ok,reason=reason,sid_changed=(old_sid!=new_sid),key_changed=(old_key!=ed.keys['k_up']),key_nonce_reused=(old_key==ed.keys['k_up'] and old_nonce==nonce(ed.keys['nonce_prefix'],m.seq))))
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print(OUT)
