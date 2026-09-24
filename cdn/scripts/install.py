#!/usr/bin/env python3
"""Offline Linux AMD64 installer"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
CONFIG=Path('/etc/pacetun-cdn/tunnel.conf')
CORE=Path('/usr/local/bin/pacetun-cdn')
BRIDGE=Path('/usr/local/bin/pacetun-utls-bridge')
BACKUPS=Path('/var/lib/pacetun-backups')
VERSION='6.0.0-alpha1'
COLOR=sys.stdout.isatty()
def say(s):print(('\033[36m'+s+'\033[0m') if COLOR else s,flush=True)
def run(*args):return subprocess.run(args,check=True,text=True,capture_output=True,timeout=60)
def read_config(path):
    out={}
    for raw in path.read_text().splitlines():
        line=raw.split('#',1)[0].strip()
        if not line:continue
        k,v=line.split('=',1)
        if k.strip() in out:raise ValueError('Duplicate configuration key')
        out[k.strip()]=v.strip()
    return out

def inventory():
    seen=set()
    for line in (ROOT/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split('  ',1);rel=Path(name)
        if len(digest)!=64 or rel.is_absolute() or '..' in rel.parts or name in seen:raise ValueError('Unsafe manifest')
        seen.add(name);p=ROOT/rel
        if p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('Checksum failed: '+name)
    if not {'bin/pacetun-cdn-linux-amd64','bin/pacetun-utls-bridge'}.issubset(seen):raise ValueError('Required binaries missing from manifest')

def atomic_write(path,data,mode):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('Refusing symlink: '+str(path))
    fd,tmp=tempfile.mkstemp(prefix='.pacetun-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.chmod(tmp,mode);os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def backup(paths):
    BACKUPS.mkdir(parents=True,exist_ok=True,mode=0o700)
    dest=BACKUPS/(time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3));dest.mkdir(mode=0o700)
    entries=[]
    for i,p in enumerate(paths):
        if p.is_symlink():raise ValueError('Refusing symlink: '+str(p))
        entry={'path':str(p),'existed':p.exists(),'copy':str(i)}
        if p.exists():
            entry['mode']=p.stat().st_mode&0o777
            shutil.copy2(p,dest/str(i))
        entries.append(entry)
    (dest/'manifest.json').write_text(json.dumps(entries,indent=2));say('Rollback directory: '+str(dest));return dest

def restore(dest):
    dest=Path(dest).resolve()
    if dest.parent!=BACKUPS.resolve() or dest.is_symlink():raise ValueError('Select a backup inside '+str(BACKUPS))
    entries=json.loads((dest/'manifest.json').read_text())
    allowed={str(CORE),str(BRIDGE),str(CONFIG),'/etc/systemd/system/pacetun-cdn.service','/etc/systemd/system/pacetun-utls-bridge.service','/etc/pacetun-cdn/pacetun.psk','/etc/systemd/system/pacetun-http-carrier.service','/etc/nginx/snippets/pacetun-http.conf'}
    for e in entries:
        p=Path(e['path'])
        if str(p) not in allowed:raise ValueError('Unsafe backup target')
        if e['existed']:atomic_write(p,(dest/e['copy']).read_bytes(),e['mode'])
        elif p.exists():
            if p.is_symlink():raise ValueError('Refusing symlink')
            p.unlink()
    run('systemctl','daemon-reload');say('Files restored. Coordinate activation of both peers before restarting.')

def native():
    if os.geteuid()!=0:raise ValueError('Run as root on your VPS')
    if platform.system()!='Linux' or platform.machine() not in ('x86_64','AMD64'):raise ValueError('This package contains Linux AMD64 binaries only')
    if not shutil.which('ip'):raise ValueError('iproute2 is required (ip command missing)')

def preflight():
    inventory()
    out=run(str(ROOT/'bin/pacetun-cdn-linux-amd64'),'--version').stdout
    if VERSION not in out:raise ValueError('Core version mismatch')
    out=run(str(ROOT/'bin/pacetun-utls-bridge'),'-version').stdout
    if VERSION not in out or 'utls1.8.2' not in out:raise ValueError('Bridge version mismatch')
    if CONFIG.exists():
        run(str(ROOT/'bin/pacetun-cdn-linux-amd64'),'--config',str(CONFIG),'--check-config')
        cfg=read_config(CONFIG)
        if cfg.get('transport')!='websocket':raise ValueError('Installer supports WebSocket configurations only')
        say('Existing configuration accepted. Stage this release on BOTH peers before enabling experimental features.')
    say('Package checks passed. SHA-256 checks integrity, not publisher identity.')

def stage():
    if not CONFIG.is_file():raise ValueError('No existing config. Use --setup for a fresh installation.')
    cfg=read_config(CONFIG);items=[CORE,BRIDGE]
    if cfg.get('mode')=='client' and cfg.get('tls_backend')=='utls':
        if not Path('/etc/systemd/system/pacetun-utls-bridge.service').exists():raise ValueError('Existing uTLS service missing; use manual service setup')
    dest=backup(items)
    try:
        atomic_write(CORE,(ROOT/'bin/pacetun-cdn-linux-amd64').read_bytes(),0o755)
        if BRIDGE in items:atomic_write(BRIDGE,(ROOT/'bin/pacetun-utls-bridge').read_bytes(),0o755)
    except BaseException:restore(dest);raise
    say('STAGED. Running processes are unchanged. Stage the other peer, then activate both from independent SSH/console sessions.')

def ask(label,default=None):
    value=input(label+(f' [{default}]' if default is not None else '')+': ').strip()
    if not value and default is not None:return default
    if not value or any(c in value for c in '\n\r\x00'):raise ValueError('A value is required')
    return value

def unit_quote(s):return '"'+s.replace('\\','\\\\').replace('"','\\"').replace('%','%%')+'"'

def setup():
    if CONFIG.exists() or CORE.exists():raise ValueError('Existing installation found; use --stage. Setup never overwrites it.')
    role=ask('Connection role: server (listener) or client (dialer)')
    if role not in ('server','client'):raise ValueError('Role must be server or client')
    sample=ROOT/'config'/('foreign-pool2.conf' if role=='server' else 'iran-pool2.conf')
    cfg=read_config(sample)
    cfg['server_name']=ask('Your CDN hostname (without https://)');cfg['host_header']=cfg['server_name']
    cfg['path']=ask('WebSocket path configured in Nginx (must start with /)')
    cfg['cidr']=ask('Local private tunnel address/CIDR',cfg['cidr']);cfg['peer_cidr']=ask('Peer private tunnel address/CIDR',cfg['peer_cidr'])
    cfg['max_connections']=ask('Pool connections: 1, 2, 3 or 4 (match both peers)','2')
    cfg['resource_profile']=ask('Resource profile: normal or lowmem','lowmem')
    cfg['session_max_age_sec']='3600';cfg['pool_drain_sec']='30';cfg['pool_idle_poll_ms']='100'
    cfg['address_family']=ask('OpenSSL address family: auto, ipv4 or ipv6','auto')
    bridge_unit=None
    if role=='server':cfg['listen']=ask('Local Nginx upstream address:port','127.0.0.1:19443')
    else:
        cfg['server']=ask('CDN destination host:port',cfg['server_name']+':443')
        cfg['tls_backend']=ask('TLS backend: utls or openssl','utls')
        if cfg['tls_backend']=='utls':
            family=ask('uTLS address family: auto, ipv4 or ipv6','auto')
            if family not in ('auto','ipv4','ipv6'):raise ValueError('Invalid address family')
            args=[str(BRIDGE),'--socket','/run/pacetun-utls/bridge.sock','--remote',cfg['server'],'--server-name',cfg['server_name'],'--ca',cfg['tls_ca'],'--family',family,'--max-sessions','6','--fingerprint','firefox120']
            bridge_unit=(ROOT/'systemd/pacetun-utls-bridge.service').read_text()
            bridge_unit='\n'.join('ExecStart='+' '.join(map(unit_quote,args)) if l.startswith('ExecStart=') else l for l in bridge_unit.splitlines())+'\n'
            cfg['tls_adapter_socket']='/run/pacetun-utls/bridge.sock'
    psk_path=Path('/etc/pacetun-cdn/pacetun.psk')
    if role=='server':
        psk=(secrets.token_hex(32)+'\n').encode();say('A random PSK will be generated. Transfer it privately to the client; it will not be printed.')
    else:
        source=Path(ask('Absolute path of the PSK file privately copied from the server'))
        if not source.is_absolute() or not source.is_file():raise ValueError('PSK file missing')
        psk=source.read_bytes()
        if not 32<=len(psk.rstrip())<=4096:raise ValueError('Invalid PSK length')
    cfg['psk_file']=str(psk_path)
    data=('\n'.join(k+'='+v for k,v in cfg.items())+'\n').encode()
    with tempfile.NamedTemporaryFile() as f:
        f.write(data);f.flush();run(str(ROOT/'bin/pacetun-cdn-linux-amd64'),'--config',f.name,'--check-config')
    core_unit=(ROOT/'systemd/pacetun-cdn.service').read_text()
    if bridge_unit:core_unit=core_unit.replace('After=network-online.target','After=network-online.target pacetun-utls-bridge.service\nRequires=pacetun-utls-bridge.service')
    items=[CORE,CONFIG,psk_path,Path('/etc/systemd/system/pacetun-cdn.service')]
    if bridge_unit:items += [BRIDGE,Path('/etc/systemd/system/pacetun-utls-bridge.service')]
    if any(x.exists() for x in items):raise ValueError('A target already exists; refusing to overwrite it')
    dest=backup(items)
    try:
        atomic_write(CONFIG,data,0o600);atomic_write(psk_path,psk,0o600)
        atomic_write(CORE,(ROOT/'bin/pacetun-cdn-linux-amd64').read_bytes(),0o755)
        atomic_write(items[3],core_unit.encode(),0o644)
        if bridge_unit:
            atomic_write(BRIDGE,(ROOT/'bin/pacetun-utls-bridge').read_bytes(),0o755)
            atomic_write(items[-1],bridge_unit.encode(),0o644)
        run('systemctl','daemon-reload');run('systemctl','enable','pacetun-cdn')
        if bridge_unit:run('systemctl','enable','pacetun-utls-bridge')
    except BaseException:restore(dest);raise
    say('SETUP COMPLETE; services have not started. Configure the CDN/Nginx upstream, then activate both peers. PSK: '+str(psk_path))

def activate():
    cfg=read_config(CONFIG)
    run(str(CORE),'--config',str(CONFIG),'--check-config')
    if not Path('/dev/net/tun').exists():raise ValueError('/dev/net/tun is unavailable; this release requires TUN')
    if cfg.get('mode')=='client' and cfg.get('tls_backend')=='utls':run('systemctl','restart','pacetun-utls-bridge')
    if cfg.get('mode')=='server' and Path('/etc/systemd/system/pacetun-http-carrier.service').exists():run('systemctl','restart','pacetun-http-carrier')
    run('systemctl','restart','pacetun-cdn')
    say('Service restarted. Activate the peer too, then verify ONLINE and v2rayN traffic. A service restart alone does not prove connectivity.')

def main():
    ap=argparse.ArgumentParser(description=__doc__);g=ap.add_mutually_exclusive_group(required=True)
    for name in ('check','stage','setup','activate'):g.add_argument('--'+name,action='store_true')
    g.add_argument('--rollback',metavar='BACKUP_DIRECTORY');ap.add_argument('--trusted-key',type=Path)
    a=ap.parse_args()
    if a.trusted_key:run(sys.executable,str(ROOT/'scripts/release-signature.py'),'verify','--public-key',str(a.trusted_key),'--manifest',str(ROOT/'SHA256SUMS'),'--signature',str(ROOT/'SHA256SUMS.sig'))
    if a.check:preflight();return
    native()
    if a.rollback:restore(a.rollback);return
    preflight()
    if a.stage:stage()
    elif a.setup:setup()
    else:activate()
if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print('ERROR:',e,file=sys.stderr)
        if isinstance(e,subprocess.CalledProcessError):print(e.stderr,file=sys.stderr)
        sys.exit(1)
