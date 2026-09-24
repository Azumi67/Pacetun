#!/usr/bin/env python3
import argparse
import importlib.util
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('installer',ROOT/'scripts/install.py')
i=importlib.util.module_from_spec(spec);spec.loader.exec_module(i)
HTTP_UNIT=Path('/etc/systemd/system/pacetun-http-carrier.service')
HTTP_SNIPPET=Path('/etc/nginx/snippets/pacetun-http.conf')
BRIDGE_UNIT=Path('/etc/systemd/system/pacetun-utls-bridge.service')

def setarg(args,key,value):
    for n in range(len(args)-1,0,-1):
        if args[n]==key:
            if n+1>=len(args):raise ValueError('Missing argument in bridge service')
            del args[n:n+2]
        elif args[n].startswith(key+'='):del args[n]
    if value is not None:args.extend([key,str(value)])

def render(cfg,a,existing_bridge=''):
    cfg=dict(cfg);outputs={};role=cfg.get('mode')
    if cfg.get('transport')!='websocket':raise ValueError('Requires existing WebSocket core configuration')
    if a.shaping is not None:
        cfg['traffic_shaping']='1' if a.shaping=='on' else '0'
        if a.shaping=='off':cfg.update(websocket_padding_max_bytes='0',websocket_control_padding_bytes='0')
        if a.shaping=='on':
            cfg.update(websocket_padding_max_bytes='256',websocket_control_padding_bytes='32',padding_budget_pct='5',shaping_startup_ms='1500',shaping_delay_ms='3',shaping_rate_bytes='4096',shaping_burst_bytes='4096')
    if role=='client':
        if cfg.get('tls_backend')!='utls':raise ValueError('Feature helper requires the existing uTLS client service; core shaping itself supports OpenSSL too')
        starts=[line for line in existing_bridge.splitlines() if line.startswith('ExecStart=')]
        if len(starts)!=1:raise ValueError('Expected one ExecStart in existing uTLS service')
        args=shlex.split(starts[0].split('=',1)[1])
        if not args or args[0]!=str(i.BRIDGE):raise ValueError('Unexpected bridge executable')
        args=[s.replace('%%','%') for s in args]
        profile=a.browser_profile
        if profile is None:
            profile='firefox120'
            for n,v in enumerate(args):
                if v=='--fingerprint' and n+1<len(args):profile=args[n+1]
                elif v.startswith('--fingerprint='):profile=v.split('=',1)[1]
        if profile not in ('firefox120','chrome120'):raise ValueError('Unsupported existing browser profile')
        cfg['browser_profile']=profile;setarg(args,'--fingerprint',profile)
        if a.startup_paths is not None:setarg(args,'--startup-paths',a.startup_paths or None)
        if a.carrier:
            setarg(args,'--carrier','http-client' if a.carrier=='http' else 'websocket')
            if a.carrier=='http':
                if a.startup_paths:raise ValueError('Startup requests currently require WebSocket')
                setarg(args,'--startup-paths',None)
                setarg(args,'--http-path',a.http_path);setarg(args,'--http-key',str(a.http_key))
            else:
                setarg(args,'--http-key',None);setarg(args,'--http-path',None)
        #  dry run bridge flags 
        outputs[BRIDGE_UNIT]=(existing_bridge.replace(starts[0],'ExecStart='+' '.join(map(i.unit_quote,args))).encode(),0o644)
        for n,v in enumerate(args):
            if v=='--socket' and n+1<len(args):cfg['tls_adapter_socket']=args[n+1]
            elif v.startswith('--socket='):cfg['tls_adapter_socket']=v.split('=',1)[1]
    elif role=='server' and a.carrier=='http':
        if not a.http_key:raise ValueError('--http-key is required for HTTP mode')
        args=[str(i.BRIDGE),'--carrier','http-server','--http-listen','127.0.0.1:19444','--http-backend',cfg['listen'],'--http-path',a.http_path,'--http-key',str(a.http_key),'--max-sessions','6']
        unit='''[Unit]
Description=PaceTun experimental HTTP request carrier
After=network-online.target pacetun-cdn.service
Wants=network-online.target
[Service]
User=root
ExecStart=COMMAND
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LimitNOFILE=256
MemoryMax=128M
TasksMax=128
[Install]
WantedBy=multi-user.target
'''.replace('COMMAND',' '.join(map(i.unit_quote,args)))
        outputs[HTTP_UNIT]=(unit.encode(),0o644)
        outputs[HTTP_SNIPPET]=(nginx_snippet(a.http_path).encode(),0o644)
    elif role not in ('client','server'):raise ValueError('Unknown role')
    outputs[i.CONFIG]=(('\n'.join(k+'='+v for k,v in cfg.items())+'\n').encode(),0o600)
    return outputs

def nginx_snippet(path):
    return '''# Experimental HTTP carrier
location = PATH {
    proxy_pass http://127.0.0.1:19444;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_request_buffering on;
    proxy_cache off;
    client_max_body_size 64k;
    client_body_timeout 15s;
    proxy_read_timeout 90s;
    proxy_send_timeout 20s;
    access_log off;
}
location ^~ PATH/ {
    proxy_pass http://127.0.0.1:19444;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_request_buffering on;
    proxy_cache off;
    client_max_body_size 64k;
    client_body_timeout 15s;
    proxy_read_timeout 90s;
    proxy_send_timeout 20s;
    access_log off;
}
'''.replace('PATH',path)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--shaping',choices=['on','off']);p.add_argument('--browser-profile',choices=['firefox120','chrome120'])
    p.add_argument('--startup-paths',help='Empty string disables requests; at most two same-origin paths')
    p.add_argument('--carrier',choices=['websocket','http']);p.add_argument('--http-path',default='/assets/transfer/v1');p.add_argument('--http-key',type=Path)
    p.add_argument('--apply',action='store_true');a=p.parse_args()
    if not any((a.shaping,a.browser_profile,a.startup_paths is not None,a.carrier)):p.error('Choose a feature')
    cfg=i.read_config(i.CONFIG)
    if a.carrier=='http':
        if a.http_key is None or not a.http_key.is_absolute():p.error('Supply --http-key with a private absolute path on this server')
        key=a.http_key.read_text().strip()
        if a.http_key.is_symlink() or a.http_key.stat().st_mode&0o077 or len(bytes.fromhex(key))!=32:raise ValueError('HTTP key requires 0600 and 64 hex characters')
    outputs=render(cfg,a,BRIDGE_UNIT.read_text() if cfg.get('mode')=='client' else '')
    if '6.0.0-alpha1' not in i.run(str(i.CORE),'--version').stdout:raise ValueError('Stage version 6.0.0-alpha1 before enabling its features')
    with tempfile.NamedTemporaryFile() as f:
        f.write(outputs[i.CONFIG][0]);f.flush();i.run(str(i.CORE),'--config',f.name,'--check-config')
    for path,(data,_) in outputs.items():
        if path.suffix=='.service':
            start=next(l for l in data.decode().splitlines() if l.startswith('ExecStart='))
            args=[v.replace('%%','%') for v in shlex.split(start.split('=',1)[1])]
            i.run(*args,'--check')
    print('Validated feature changes:')
    for path in outputs:print(' ',path)
    if not a.apply:print('Preview only. Add --apply to save; services will not restart.');return
    i.native();dest=i.backup(list(outputs))
    try:
        for path,(data,mode) in outputs.items():i.atomic_write(path,data,mode)
        i.run('systemctl','daemon-reload')
    except BaseException:i.restore(dest);raise
    print('Saved. Coordinate peer restarts. HTTP server mode also requires including the generated Nginx snippet, nginx -t, and enabling pacetun-http-carrier. See INSTALL.md.')
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,subprocess.SubprocessError) as e:
        print('ERROR:',e)
        if isinstance(e,subprocess.CalledProcessError):print(e.stderr)
        raise SystemExit(1)
