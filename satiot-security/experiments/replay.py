from experiments.settings import CONFIG
import csv,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from src.core import *
import os
OUT=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'replay_window.csv'
order=CONFIG['replay']['delivery_order']
rows=[]
for w in CONFIG['replay']['windows']:
  ed=EndDevice();kms=KMS();kms.register(ed);app=ApplicationServer(window_size=w);establish(ed,kms,app)
  msgs=[ed.protect(f'm{i}'.encode()) for i in range(5)]
  for idx,seq in enumerate(order):
    ok,reason,_=app.receive(msgs[seq]);rows.append(dict(window=w,delivery_index=idx,seq=seq,accepted=ok,reason=reason))
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print(OUT)
