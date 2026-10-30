import math
import pytest
from analysis.analyze import as_bool,wilson,quantile
@pytest.mark.parametrize('value',['tru','1','','false'])
def test_boolean_rejects_unknown(value):
    with pytest.raises(ValueError): as_bool(value)
@pytest.mark.parametrize('confidence',[.90,.95,.99])
@pytest.mark.parametrize('k',[0,1,100])
def test_interval_boundary_and_finite(k,confidence):
    low,high=wilson(k,100,confidence)
    assert math.isfinite(low) and math.isfinite(high) and 0<=low<=k/100+1e-15 and k/100-1e-15<=high<=1

def test_type7_quantiles():
    assert quantile([0,10,20,30],.25)==7.5
    assert quantile([30,0,20,10],.95)==pytest.approx(28.5)

from analysis.analyze import read,validate,SCHEMAS
import csv

def put(path,rows):
    with (path/'replay_window.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=SCHEMAS['replay_window'].split()); w.writeheader(); w.writerows(rows)

def test_replay_loading_is_order_independent(tmp_path):
    rows=[dict(window=8,delivery_index=i,seq=s,accepted='True' if i<5 else 'False',reason='ACCEPT' if i<5 else 'REPLAY') for i,s in enumerate([0,1,3,2,4,2])]
    put(tmp_path,rows); a=read(tmp_path,'replay_window')
    put(tmp_path,list(reversed(rows))); assert read(tmp_path,'replay_window')==a

def test_duplicate_trial_identifier_rejected(tmp_path):
    r=dict(window=8,delivery_index=0,seq=0,accepted='True',reason='ACCEPT')
    put(tmp_path,[r,r])
    with pytest.raises(ValueError,match='duplicate key'): read(tmp_path,'replay_window')

def test_malformed_boolean_in_data_rejected(tmp_path):
    put(tmp_path,[dict(window=8,delivery_index=0,seq=0,accepted='tru',reason='REPLAY')])
    with pytest.raises(ValueError,match='Boolean'): read(tmp_path,'replay_window')

def test_missing_observations_rejected():
    with pytest.raises(ValueError,match='missing/unexpected'): validate({k:[] for k in SCHEMAS})

def test_empty_quantile_is_unavailable():
    assert quantile([],.95) is None
