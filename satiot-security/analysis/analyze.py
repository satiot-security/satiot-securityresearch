"""Typed final-P1 analysis; distributional units are explicit."""
import argparse,csv,json,math,statistics
from collections import defaultdict
from pathlib import Path
from statistics import NormalDist
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from experiments.settings import CONFIG
SCHEMAS={
'attack_matrix':'attack run accepted reason legitimate_control',
'replay_window':'window delivery_index seq accepted reason',
'state_rollback':'mode run post_crash_accepted reason sid_changed key_changed key_nonce_reused',
'lifecycle':'run initial_join fresh_join sid_changed reinstall_preserves_replay pending_cancelled old_context_retired_locally new_message_accepted kms_revocation_blocks_join active_survives_kms_revocation explicit_as_revocation',
'airtime':'max_frm_payload sf plaintext_payload profile app_bytes packets total_airtime_ms',
'network_impairments':'condition run delay_ms jitter_ms loss join_success join_reason simulated_join_time_ms uplink_accepted uplink_reason',
'contact':'available_ms unavailable_ms offset_ms successful_join reason end_ms theory',
'integrated':'capacity sf fragment_metadata payload frames loss no_retry_completion summed_airtime_ms serialization_budget_ms'}
BOOL=set('legitimate_control key_changed key_nonce_reused accepted post_crash_accepted sid_changed initial_join fresh_join reinstall_preserves_replay pending_cancelled old_context_retired_locally new_message_accepted kms_revocation_blocks_join active_survives_kms_revocation explicit_as_revocation join_success uplink_accepted successful_join theory'.split())
TEXT=set('attack reason mode profile condition join_reason uplink_reason'.split())
FLOAT=set('total_airtime_ms loss simulated_join_time_ms end_ms no_retry_completion summed_airtime_ms serialization_budget_ms'.split())
KEYS={'attack_matrix':['attack','run'],'replay_window':['window','delivery_index'],'state_rollback':['mode','run'],'lifecycle':['run'],'airtime':['max_frm_payload','sf','plaintext_payload','profile'],'network_impairments':['condition','run'],'contact':['available_ms','unavailable_ms','offset_ms'],'integrated':['capacity','sf','fragment_metadata','payload','loss']}

def as_bool(s):
    if s=='True': return True
    if s=='False': return False
    raise ValueError(f'Unrecognised Boolean: {s!r}')

def read(raw,name):
    with (raw/(name+'.csv')).open(newline='') as f:
        reader=csv.DictReader(f)
        if reader.fieldnames!=SCHEMAS[name].split(): raise ValueError(f'{name}: schema mismatch')
        rows=[]; seen=set()
        for r in reader:
            if None in r or any(v is None for v in r.values()): raise ValueError(f'{name}: incomplete row')
            row={k:as_bool(v) if k in BOOL else v if k in TEXT else float(v) if k in FLOAT else int(v) for k,v in r.items()}
            if any(isinstance(v,(int,float)) and (not math.isfinite(v) or v<0) for v in row.values()): raise ValueError(f'{name}: nonfinite/negative')
            key=tuple(row[k] for k in KEYS[name])
            if key in seen: raise ValueError(f'{name}: duplicate key {key}')
            seen.add(key); rows.append(row)
    if not rows: raise ValueError(f'{name}: empty data')
    return sorted(rows,key=lambda r:tuple(r[k] for k in KEYS[name]))

def wilson(k,n,confidence=.95):
    if not 0<=k<=n or n<=0 or confidence not in (.90,.95,.99): raise ValueError('Invalid interval input')
    z=NormalDist().inv_cdf((1+confidence)/2); p=k/n; den=1+z*z/n
    centre=(p+z*z/(2*n))/den; half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return max(0,centre-half),min(1,centre+half)

def quantile(xs,q):
    if not xs: return None
    xs=sorted(xs); pos=(len(xs)-1)*q; i=math.floor(pos); f=pos-i
    return xs[i]*(1-f)+xs[min(i+1,len(xs)-1)]*f

def write(out,name,rows):
    with (out/(name+'.csv')).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=rows[0]); w.writeheader(); w.writerows(rows)

def validate(data):
    c=CONFIG
    expected={
'attack_matrix':{(a,i) for a in c['adversarial']['classes'] for i in range(c['adversarial']['trials_per_class'])},
'replay_window':{(w,i) for w in c['replay']['windows'] for i in range(len(c['replay']['delivery_order']))},
'state_rollback':{(m,i) for m in c['rollback']['modes'] for i in range(c['rollback']['trials_per_mode'])},
'lifecycle':{(i,) for i in range(c['lifecycle']['trials'])},
'network_impairments':{(n,i) for n,*_ in c['network']['profiles'] for i in range(c['network']['trials_per_profile'])},
'airtime':{(cap,sf,p,profile) for cap in c['airtime']['capacities'] for sf in c['airtime']['spreading_factors'] for p in c['airtime']['payloads'] for profile in ['P0','P1']},
'contact':{(a,u,o) for a,u in c['contact']['patterns_ms'] for o in set(c['contact']['base_offsets_ms']+[a+x for x in c['contact']['boundary_offsets_from_close_ms']])},
'integrated':{(cap,sf,m,p,loss) for cap in c['airtime']['capacities'] for sf in c['airtime']['spreading_factors'] for m in c['integrated']['fragment_metadata_bytes'] for p in c['airtime']['payloads'] for loss in c['integrated']['frame_loss']}}
    for name,rows in data.items():
        if {tuple(r[k] for k in KEYS[name]) for r in rows}!=expected[name]: raise ValueError(f'{name}: missing/unexpected observations')
    profiles={n:(d,j,p) for n,d,j,p in c['network']['profiles']}
    for r in data['network_impairments']:
        if (r['delay_ms'],r['jitter_ms'],r['loss'])!=profiles[r['condition']]: raise ValueError('Inconsistent network configuration')
        if r['uplink_accepted'] and not r['join_success']: raise ValueError('Uplink without successful join')
        if r['join_success']!=(r['join_reason']=='ACCEPT') or r['uplink_accepted']!=(r['uplink_reason']=='ACCEPT'): raise ValueError('Inconsistent network outcome')
    for name in ('attack_matrix','replay_window'):
        for r in data[name]:
            if r['accepted']!=(r['reason']=='ACCEPT'): raise ValueError(f'{name}: inconsistent outcome')
    for r in data['replay_window']:
        if r['seq']!=c['replay']['delivery_order'][r['delivery_index']]: raise ValueError('Incorrect replay order')
    for r in data['airtime']:
        expected=r['plaintext_payload']+(c['airtime']['overhead'] if r['profile']=='P1' else 0)
        if r['app_bytes']!=expected or r['packets']!=math.ceil(expected/r['max_frm_payload']): raise ValueError('Incorrect packetisation')
    for r in data['integrated']:
        if not math.isclose(r['no_retry_completion'],(1-r['loss'])**r['frames'],rel_tol=1e-12): raise ValueError('Incorrect loss model')

def analyze(raw,out,confidence=.95):
    data={name:read(raw,name) for name in SCHEMAS}; validate(data)
    out.mkdir(parents=True,exist_ok=True); figs=out/'figures'; figs.mkdir(exist_ok=True); tables={}
    groups=defaultdict(list)
    for r in data['attack_matrix']: groups[r['attack']].append(r)
    tables['adversarial_counts']=[dict(attack=a,trials=len(rs),accepted=sum(r['accepted'] for r in rs),rejected=sum(not r['accepted'] for r in rs),legitimate_controls=sum(r['legitimate_control'] for r in rs)) for a,rs in sorted(groups.items())]
    tables['replay_counts']=[]
    for w in CONFIG['replay']['windows']:
        rs=[r for r in data['replay_window'] if r['window']==w]
        legit=[r for r in rs if r['delivery_index']<len(CONFIG['replay']['delivery_order'])-1]
        duplicate=[r for r in rs if r['delivery_index']==len(CONFIG['replay']['delivery_order'])-1]
        tables['replay_counts'].append(dict(window=w,legitimate_deliveries=len(legit),legitimate_accepted=sum(r['accepted'] for r in legit),duplicate_accepted=sum(r['accepted'] for r in duplicate)))
    tables['rollback_counts']=[dict(mode=m,trials=len(rs),accepted=sum(r['post_crash_accepted'] for r in rs),sid_changed=sum(r['sid_changed'] for r in rs),key_changed=sum(r['key_changed'] for r in rs),key_nonce_reused=sum(r['key_nonce_reused'] for r in rs)) for m in CONFIG['rollback']['modes'] for rs in [[r for r in data['state_rollback'] if r['mode']==m]]]
    tables['lifecycle_counts']=[dict(property=k,trials=len(data['lifecycle']),true_count=sum(r[k] for r in data['lifecycle'])) for k in SCHEMAS['lifecycle'].split() if k!='run']
    net=[]
    for name,delay,jitter,loss in CONFIG['network']['profiles']:
        rs=[r for r in data['network_impairments'] if r['condition']==name]; n=len(rs)
        j=sum(r['join_success'] for r in rs); u=sum(r['uplink_accepted'] for r in rs)
        times=[r['simulated_join_time_ms'] for r in rs if r['join_success']]
        jl,jh=wilson(j,n,confidence); ul,uh=wilson(u,n,confidence)
        net.append(dict(condition=name,trials=n,join_success=j,workflow_success=u,join_rate=j/n,join_ci_low=jl,join_ci_high=jh,workflow_rate=u/n,workflow_ci_low=ul,workflow_ci_high=uh,confidence=confidence,join_theory=(1-loss)**2,workflow_theory=(1-loss)**3,workflow_difference_from_ideal=u/n-1,conditional_median_ms=statistics.median(times) if times else None,conditional_q1_ms=quantile(times,.25),conditional_q3_ms=quantile(times,.75),conditional_p95_ms=quantile(times,.95)))
    tables['network_statistics']=net; effects=[]; grouped=defaultdict(dict)
    for r in data['airtime']: grouped[(r['max_frm_payload'],r['sf'],r['plaintext_payload'])][r['profile']]=r
    for (cap,sf,p),rs in sorted(grouped.items()):
        a,b=rs['P0'],rs['P1']; effects.append(dict(capacity=cap,sf=sf,payload=p,p0_packets=a['packets'],p1_packets=b['packets'],packet_increase=b['packets']-a['packets'],p0_airtime_ms=a['total_airtime_ms'],p1_airtime_ms=b['total_airtime_ms'],airtime_difference_ms=b['total_airtime_ms']-a['total_airtime_ms'],airtime_ratio=b['total_airtime_ms']/a['total_airtime_ms']))
    tables['airtime_effects']=effects; tables['contact_cases']=data['contact']; tables['integrated_sensitivity']=data['integrated']
    for name,rows in tables.items(): write(out,name,rows)
    summary=dict(confidence=confidence,observations={k:len(v) for k,v in data.items()},tables=tables,contact_model_disagreements=sum(r['successful_join']!=r['theory'] for r in data['contact']))
    (out/'summary.json').write_text(json.dumps(summary,indent=2,allow_nan=False)+'\n')
    fig,ax=plt.subplots(figsize=(7,4)); xs=list(range(len(net)))
    ax.errorbar(xs,[r['workflow_rate'] for r in net],yerr=[[max(0,r['workflow_rate']-r['workflow_ci_low']) for r in net],[max(0,r['workflow_ci_high']-r['workflow_rate']) for r in net]],fmt='o',label=f'Object simulation: {confidence:.0%} Wilson CI')
    ax.plot(xs,[r['workflow_theory'] for r in net],'x',label='Independent object-loss theory'); ax.set_xticks(xs,[r['condition'] for r in net]); ax.set_ylabel('Complete workflow probability'); ax.set_ylim(.5,1.03); ax.legend(fontsize=8); fig.tight_layout()
    for ext in ('png','pdf'): fig.savefig(figs/f'network.{ext}',dpi=180)
    plt.close(fig); fig,ax=plt.subplots(figsize=(7,4))
    for available,unavailable in CONFIG['contact']['patterns_ms']:
        rs=[r for r in data['contact'] if r['available_ms']==available]
        ax.scatter([r['offset_ms'] for r in rs],[int(r['successful_join']) for r in rs],label=f'{available}/{unavailable} ms',alpha=.75)
    ax.set_xlabel('Attempt offset (ms)'); ax.set_ylabel('Deterministic establishment completion'); ax.set_yticks([0,1]); ax.legend(fontsize=8); fig.tight_layout()
    for ext in ('png','pdf'): fig.savefig(figs/f'contact.{ext}',dpi=180)
    plt.close(fig); fig,ax=plt.subplots(figsize=(7,4))
    for sf in CONFIG['airtime']['spreading_factors']:
        rs=[r for r in effects if r['capacity']==51 and r['sf']==sf]
        ax.plot([r['payload'] for r in rs],[r['airtime_ratio'] for r in rs],'o-',label=f'SF{sf}')
    ax.set_xlabel('Plaintext bytes'); ax.set_ylabel('P1 / P0 modelled airtime'); ax.legend(); fig.tight_layout()
    for ext in ('png','pdf'): fig.savefig(figs/f'airtime.{ext}',dpi=180)
    plt.close(fig)
    (out/'results.md').write_text('''# Focused P1 evidence results

Every raw file in this run is a new execution of the identified source. Supplied observations are excluded from this analysis. Eight drivers span protocol assurance, lifecycle state and communication trade-offs. No host join timing or encryption/decryption timing claim is made.

Attack counts describe seven fixed mutation procedures, not arbitrary attacker probabilities. No confidence intervals are inferred from these repetitions. Replay and contact cases are deterministic, with no inferential intervals. Unsafe rollback is a negative control: rejection does not prevent prior GCM nonce reuse.

Network intervals are Wilson intervals across per-profile seeded Bernoulli object simulations. Profiles jointly change loss and jitter. Seeds overlap across profiles but branch-dependent consumption precludes simple matched delay comparisons. Quantiles use linear interpolation (type 7), conditional on successful joins. Processing, failed-workflow timeouts, airtime, retries and scheduling are excluded. Rate differences from ideal are descriptive effects, not isolated causal estimates.

P0 is an unprotected size baseline. Airtime effects are deterministic, not measured physical or energy costs. Integrated completion probability is analytical independent frame loss without retries. Serialization budget adds summed airtime to three assumed 21-ms traversals; it assumes serial transmission, symmetric radio parameters, no extra waits and no processing. This is no orbital or LoRaWAN feasibility threshold.

Explicit AS retirement is local. Active contexts survive KMS revocation until explicitly removed at the AS. Captured authenticated join requests remain processable. Forward secrecy, durable anti-rollback state and concurrency safety are not claimed.

See CSV tables, summary.json, run_manifest.json and verification/tests.xml for exact observations and provenance.
''')
    print(json.dumps(summary['observations'],sort_keys=True))
if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--raw',type=Path,required=True); ap.add_argument('--out',type=Path,required=True); ap.add_argument('--confidence',type=float,choices=[.90,.95,.99],default=.95); a=ap.parse_args(); analyze(a.raw,a.out,a.confidence)
