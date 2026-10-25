"""Local read-only modular/standalone smoke evidence; never mutates networking."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--languages',nargs='+',choices=['en','zh-CN','zh-TW'],default=['en','zh-CN','zh-TW'])
    parser.add_argument('--cli-exe',type=Path)
    args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    entries={'module':[sys.executable,'-m','winnetdiff'],'standalone':[sys.executable,str(ROOT/'windows_net_diffdiag.py')]}
    if args.cli_exe:
        binary=args.cli_exe.resolve()
        build_info=json.loads((binary.parent/'BUILD_INFO.json').read_text(encoding='utf-8'))
        if build_info.get('source_sha256') != hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest():
            parser.error('Candidate build metadata does not match the current standalone source.')
        entries['exe']=[str(binary)]
    results=[]
    environment = dict(os.environ, WINNETDIFF_PSEUDONYM_KEY_FILE=str(output/'runtime'/'pseudonym.key'))
    for language in args.languages:
        for mode,entry in entries.items():
            name=mode+'_'+language;target=output/(name+'.json')
            if target.exists():parser.error('Choose a new evidence directory; a previous report exists.')
            command=entry+['--cli','--lang',language,'--no-network','--fake-ip-audit','--json',str(target),
                           '--output-dir',str(output/'runtime')]
            source_before=hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest()
            started=time.perf_counter();run=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=120,env=environment)
            (output/(name+'.log')).write_bytes(run.stdout+run.stderr)
            data=json.loads(target.read_text(encoding='utf-8')) if target.exists() else {}
            row={'mode':mode,'locale':language,'exit_code':run.returncode,'seconds':round(time.perf_counter()-started,3),
                 'source_sha256':source_before,'source_changed_during_run':source_before!=hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest(),
                 'version':data.get('version'),'probe_count':len(data.get('probes',[])),
                 'fake_ip_enabled':data.get('dns_audit',{}).get('enabled'),
                 'core_errors':{key:len(data.get(key,{}).get('errors',[])) for key in ('proxy','route','security')},
                 'counts':{key:len(data.get('route',{}).get(key,[])) for key in ('adapters','routes','bindings')},
                 'dns_server_count':len(data.get('dns_audit',{}).get('dns_servers',[])),
                 'retry_mode':data.get('scan_options',{}).get('retry_mode'),
                 'ownership_components':len(data.get('security',{}).get('ownership',{}).get('components',[])),
                 'ownership_bounded_complete':data.get('security',{}).get('ownership',{}).get('bounded_complete'),
                 'winhttp_config_ok':data.get('proxy',{}).get('winhttp_config',{}).get('ok'),
                 'proxy_network_tested':data.get('proxy_paths',{}).get('network_tested'),
                 'dns_runtime_complete':data.get('dns_audit',{}).get('runtime',{}).get('core_query_complete')}
            results.append(row);print(json.dumps(row),flush=True)
    summary={'source_sha256':hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest(),
             'scope':'Read-only local collectors; loopback checks retained. No remote probes, repair, UAC or security changes.',
             'checks':results,'passed':all(r['exit_code']==0 and r['probe_count']==0 and r['fake_ip_enabled'] and not r['source_changed_during_run'] for r in results)}
    (output/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    return 0 if summary['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
