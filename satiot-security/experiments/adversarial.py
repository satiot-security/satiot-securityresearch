from experiments.settings import CONFIG
import csv,pathlib,sys,copy
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from src.core import *
import os
OUT=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'attack_matrix.csv'
rows=[]
attacks=CONFIG['adversarial']['classes']
for attack in attacks:
  for run in range(CONFIG['adversarial']['trials_per_class']):
    ed=EndDevice();kms=KMS();kms.register(ed);app=ApplicationServer();establish(ed,kms,app)
    m=ed.protect(b'payload')
    if attack=='duplicate':
      control=app.receive(m)[0]; ok,reason,_=app.receive(m)
    else:
      x=copy.deepcopy(m)
      if attack=='ciphertext': x.ciphertext=bytes([x.ciphertext[0]^1])+x.ciphertext[1:]
      elif attack=='tag': x.tag=bytes([x.tag[0]^1])+x.tag[1:]
      elif attack=='seq': x.seq+=1
      elif attack=='sid': x.sid^=1
      elif attack=='did': x.did='ED9999'
      elif attack=='mtype': x.mtype^=1
      ok,reason,_=app.receive(x)
      control=app.receive(m)[0]
    rows.append(dict(attack=attack,run=run,accepted=ok,reason=reason,legitimate_control=control))
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print(OUT)
