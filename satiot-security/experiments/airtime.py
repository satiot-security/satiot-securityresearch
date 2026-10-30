from experiments.settings import CONFIG
import csv, pathlib, sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from src.core import lora_airtime_ms, lorawan_packetise
import os
OUT=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'airtime.csv'
payloads=CONFIG['airtime']['payloads']
security_overhead=CONFIG['airtime']['overhead']
# Explicit scenario parameters. Replace max FRMPayload with region/data-rate-specific values in the final dissertation.
max_frm_values=CONFIG['airtime']['capacities']
sfs=CONFIG['airtime']['spreading_factors']
rows=[]
for maxf in max_frm_values:
  for sf in sfs:
    for p in payloads:
      for profile,size in [('P0',p),('P1',p+security_overhead)]:
        packets=lorawan_packetise(size,maxf)
        chunks=[]; rem=size
        for _ in range(packets): chunks.append(min(rem,maxf)); rem-=chunks[-1]
        # Minimum LoRaWAN PHYPayload overhead assumption: 13 B (MHDR+min FHDR+FPort+MIC), no FOpts.
        airtime=sum(lora_airtime_ms(c+CONFIG['airtime']['lower_layer_bytes'],sf=sf,bw_hz=CONFIG['airtime']['bw_hz'],cr=CONFIG['airtime']['cr'],preamble=CONFIG['airtime']['preamble'],explicit_header=CONFIG['airtime']['explicit_header'],crc=CONFIG['airtime']['crc']) for c in chunks)
        rows.append(dict(max_frm_payload=maxf,sf=sf,plaintext_payload=p,profile=profile,app_bytes=size,packets=packets,total_airtime_ms=round(airtime,3)))
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print(OUT)
