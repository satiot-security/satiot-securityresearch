from experiments.settings import CONFIG
"""Analytical sensitivity; no measured reliability or contact deployment claim."""
import csv, os, pathlib, math
from src.core import lora_airtime_ms
rows=[]
for cap in CONFIG['airtime']['capacities']:
    for sf in CONFIG['airtime']['spreading_factors']:
        for metadata in CONFIG['integrated']['fragment_metadata_bytes']:
            for payload in CONFIG['airtime']['payloads']:
                frames=[]
                for size in [44,64,payload+44]:
                    rem=size
                    while rem:
                        chunk=min(rem,cap-metadata); rem-=chunk
                        frames.append(chunk+metadata+CONFIG['airtime']['lower_layer_bytes'])
                airtime=sum(lora_airtime_ms(size,sf=sf) for size in frames)
                for loss in CONFIG['integrated']['frame_loss']:
                    rows.append(dict(capacity=cap,sf=sf,fragment_metadata=metadata,payload=payload,
                                     frames=len(frames),loss=loss,no_retry_completion=(1-loss)**len(frames),
                                     summed_airtime_ms=airtime,serialization_budget_ms=airtime+CONFIG['integrated']['fixed_traversal_budget_ms']))
out=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'integrated.csv'
with out.open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]); w.writeheader(); w.writerows(rows)
