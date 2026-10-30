from experiments.settings import CONFIG
import csv,pathlib,random,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from src.core import *
import os
OUT=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'network_impairments.csv'
conditions=CONFIG['network']['profiles']
rows=[]
for name,delay,jitter,loss in conditions:
  for run in range(CONFIG['network']['trials_per_profile']):
    rng=random.Random(run+CONFIG['network']['seed_offset'])
    ed=EndDevice();kms=KMS();kms.register(ed);app=ApplicationServer()
    # Simulate delivery probabilistically without wall-clock sleeping.
    up_delay=max(0,delay+rng.uniform(-jitter,jitter)); down_delay=max(0,delay+rng.uniform(-jitter,jitter))
    ji=ed.join_init()
    if rng.random()<loss:
      rows.append(dict(condition=name,run=run,delay_ms=delay,jitter_ms=jitter,loss=loss,join_success=False,join_reason='JOIN_INIT_DROPPED',simulated_join_time_ms=round(up_delay,3),uplink_accepted=False,uplink_reason='NO_SESSION'))
      continue
    ja,keys=kms.process(ji)
    if rng.random()<loss:
      rows.append(dict(condition=name,run=run,delay_ms=delay,jitter_ms=jitter,loss=loss,join_success=False,join_reason='JOIN_ACCEPT_DROPPED',simulated_join_time_ms=round(up_delay+down_delay,3),uplink_accepted=False,uplink_reason='NO_SESSION'))
      continue
    ed.accept(ja);app.install(ed.did,ja.sid,keys)
    m=ed.protect(b'x'*32)
    uplink_delay=max(0,delay+rng.uniform(-jitter,jitter))
    if rng.random()<loss:
      accepted=False; reason='DROPPED'
    else:
      accepted,reason,_=app.receive(m)
    rows.append(dict(condition=name,run=run,delay_ms=delay,jitter_ms=jitter,loss=loss,join_success=True,join_reason='ACCEPT',simulated_join_time_ms=round(up_delay+down_delay,3),uplink_accepted=accepted,uplink_reason=reason))
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print(OUT)
