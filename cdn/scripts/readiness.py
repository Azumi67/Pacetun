#!/usr/bin/env python3
"""Iran/Foreign deployment readiness report"""
import argparse
import json
import stat
import subprocess
import sys
from pathlib import Path

CONF=Path('/etc/pacetun-cdn/tunnel.conf')

def command(*args,timeout=5):
    try:
        return subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):return None

def inspect(role, config=CONF):
    out=[]
    def note(level,key,value):out.append({'level':level,'check':key,'result':value})
    if config.is_symlink() or not config.is_file():
        note('FAIL','config','missing or symlink');return out
    st=config.stat()
    note('PASS' if stat.S_ISREG(st.st_mode) and not st.st_mode & 0o077 else 'WARN','config_permissions','restricted' if not st.st_mode & 0o077 else 'review permissions')
    parsed={}
    for line in config.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1)
            if key.strip() in ('mode','transport','tls_backend','verify_peer'):
                parsed[key.strip()]=value.strip()
    wanted='client' if role=='iran' else 'server'
    note('PASS' if parsed.get('mode')==wanted else 'FAIL','role','matches' if parsed.get('mode')==wanted else 'unexpected; stop')
    note('PASS' if parsed.get('transport')=='websocket' else 'WARN','transport','websocket' if parsed.get('transport')=='websocket' else 'review')
    for service in ('pacetun-cdn', 'pacetun-utls-bridge') if role=='iran' else ('pacetun-cdn',):
        status=command('systemctl','is-active','--quiet',service)
        note('PASS' if status is not None and status.returncode==0 else 'FAIL','service_'+service,'active' if status is not None and status.returncode==0 else 'inactive')
    if role=='iran':
        note('PASS' if parsed.get('tls_backend')=='utls' else 'WARN','tls_backend','uTLS configured' if parsed.get('tls_backend')=='utls' else 'not configured')
        note('FAIL' if parsed.get('verify_peer','1').lower() in ('0','false','off','no') else 'PASS','core_verify_peer','check configuration' if parsed.get('verify_peer','1').lower() in ('0','false','off','no') else 'not disabled in configuration')
    unit=command('systemctl','show','pacetun-cdn','--property=ExecStart','--value')
    note('PASS' if unit is not None and unit.returncode==0 else 'WARN','core_unit','readable' if unit is not None and unit.returncode==0 else 'not readable')
    return out

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--role',choices=('iran','foreign'),required=True)
    a.add_argument('--json',action='store_true')
    x=a.parse_args();results=inspect(x.role)
    if x.json:print(json.dumps({'role':x.role,'checks':results},ensure_ascii=False,indent=2))
    else:
        for entry in results:print(f'{entry["level"]:4s} {entry["check"]:28s} {entry["result"]}')
        print('Read-only checks. Confirm authenticated ONLINE and loaded browsing separately.')
    return int(any(item['level']=='FAIL' for item in results))
if __name__=='__main__':sys.exit(main())
