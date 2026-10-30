"""Create one new evidence run; never overwrite an existing run directory."""
import argparse, datetime, hashlib, importlib.metadata, json, os, pathlib, platform, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parent

def identity():
    paths=sorted(p for folder in ('src','experiments','analysis','config','tests') for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    paths += [ROOT/'run.py',ROOT/'requirements.txt',ROOT/'requirements-lock.txt',ROOT/'pytest.ini']
    entries={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
    return entries,hashlib.sha256(json.dumps(entries,sort_keys=True).encode()).hexdigest()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',required=True); args=ap.parse_args()
    out=pathlib.Path(args.out).resolve()
    if out.exists(): raise SystemExit('Output exists: choose a new run directory.')
    out.mkdir(parents=True); (out/'raw').mkdir(); (out/'verification').mkdir()
    files,digest=identity()
    manifest=dict(status='running',started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_sha256=digest,source_files=files,
                  python=sys.version,platform=platform.platform(),machine=platform.machine(),processor=platform.processor(),cpu_count=os.cpu_count(),
                  dependencies={d.metadata['Name']:d.version for d in importlib.metadata.distributions()},
                  configuration=json.loads((ROOT/'config/experiments.json').read_text()),
                  evidence_type='new execution of final P1 source; not historical recovery',commands=[])
    env=dict(os.environ,SATIOT_RAW_DIR=str(out/'raw'),PYTHONPATH=str(ROOT),PYTHONDONTWRITEBYTECODE='1',MPLBACKEND='Agg')
    def execute(command,log):
        manifest['commands'].append(command)
        proc=subprocess.run([sys.executable,*command],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (out/'verification'/log).write_text(proc.stdout)
        if proc.returncode: raise RuntimeError(f'{command}: exit {proc.returncode}; see {log}')
    try:
        execute(['-m','pytest','-q','-p','no:cacheprovider','--junitxml',str(out/'verification/tests.xml')],'tests.txt')
        for module in ('adversarial','replay','rollback','lifecycle','airtime','network','contact','integrated'):
            execute(['-m',f'experiments.{module}'],module+'.txt')
        execute(['-m','analysis.analyze','--raw',str(out/'raw'),'--out',str(out/'derived')],'analysis.txt')
        manifest['status']='completed'
    except Exception as e:
        manifest['status']='failed'; manifest['error']=str(e); raise
    finally:
        manifest['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        manifest['raw_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((out/'raw').glob('*.csv'))}
        (out/'run_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(out)
if __name__=='__main__': main()
