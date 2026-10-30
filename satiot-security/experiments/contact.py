from experiments.settings import CONFIG
"""Deterministic, completion-gated contact scenarios; one observation per case."""
import csv, os, pathlib
from src.core import *
rows=[]
for available,unavailable in CONFIG['contact']['patterns_ms']:
    offsets=sorted(set(CONFIG['contact']['base_offsets_ms']+[available+x for x in CONFIG['contact']['boundary_offsets_from_close_ms']]))
    for offset in offsets:
        ed=EndDevice(); kms=KMS(); kms.register(ed); app=ApplicationServer()
        relay=ContactWindowRelay(available,unavailable,delay_ms=CONFIG['contact']['traversal_ms'],seed=0)
        relay.advance(offset)
        ok,reason=establish(ed,kms,app,relay)
        phase=offset%(available+unavailable)
        predicted=(phase<available and phase+2*CONFIG['contact']['traversal_ms']<=available and phase+CONFIG['contact']['traversal_ms']<available)
        rows.append(dict(available_ms=available,unavailable_ms=unavailable,offset_ms=offset,
                         successful_join=ok,reason=reason,end_ms=relay.virtual_ms,theory=predicted))
out=pathlib.Path(os.environ['SATIOT_RAW_DIR'])/'contact.csv'
with out.open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]); w.writeheader(); w.writerows(rows)
