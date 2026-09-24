#!/usr/bin/env python3
"""PaceTun status; show only allowlisted telemetry"""
import argparse
import re
import subprocess
from pathlib import Path

RTT=re.compile(r'\[HEALTH\] ONLINE \| authenticated round-trip ([\d.]+) ms')
METRIC=re.compile(r'\b([a-z_]+)=([A-Za-z0-9_.-]+)')
SAFE={'session','event','phase','reason','dns_ms','tcp_ms','tls_ms','total_ms','endpoint_attempts','cert_verified','fingerprint','alpn','up_result','down_result'}

def command(*args):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=12,check=False)
        return p.stdout if p.returncode==0 else ''
    except (OSError, subprocess.TimeoutExpired):return ''

def parse(core,bridge):
    core_lines=core.splitlines(); bridge_lines=bridge.splitlines()
    rtts=[float(m.group(1)) for line in core_lines if (m:=RTT.search(line))]
    online=any('[HEALTH] ONLINE' in x or '[ONLINE]' in x for x in core_lines[-100:])
    recent=[dict((k,v) for k,v in METRIC.findall(line) if k in SAFE)
            for line in bridge_lines if 'event=tls_ready' in line or 'event=connect_failed' in line or 'event=closed' in line]
    latest=recent[-1] if recent else {}
    ready=next((x for x in reversed(recent) if x.get('event')=='tls_ready'),{})
    total_closes=sum(x.get('event')=='closed' for x in recent)
    return {'tunnel_online_in_window':online,'last_tunnel_rtt_ms':rtts[-1] if rtts else None,
            'last_verified_tls':ready.get('cert_verified')=='true' if ready else None,
            'last_tls_dns_ms':ready.get('dns_ms'), 'last_tls_tcp_ms':ready.get('tcp_ms'),
            'last_tls_handshake_ms':ready.get('tls_ms'), 'last_tls_total_ms':ready.get('total_ms'),
            'last_bridge_event':latest.get('event','not_observed'),
            'last_bridge_phase':latest.get('phase','not_available'),
            'last_bridge_reason':latest.get('reason','not_available'),
            'closed_sessions_in_window':total_closes}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--since',default='30 minutes ago',help='journalctl time filter')
    ap.add_argument('--core-log',type=Path,help='test/local log file; do not use private config')
    ap.add_argument('--bridge-log',type=Path,help='test/local log file; do not use private config')
    a=ap.parse_args()
    core=a.core_log.read_text(errors='replace') if a.core_log else command('journalctl','-u','pacetun-cdn','--since',a.since,'--no-pager','-n','400')
    bridge=a.bridge_log.read_text(errors='replace') if a.bridge_log else command('journalctl','-u','pacetun-utls-bridge','--since',a.since,'--no-pager','-n','400')
    if not (a.core_log or a.bridge_log):
        for service in ('pacetun-cdn','pacetun-utls-bridge'):
            print(f'{service}_active='+str(bool(command('systemctl','is-active',service).strip()=='active')).lower())
    for k,v in parse(core,bridge).items():print(f'{k}={v if v is not None else "unavailable"}')
    print('Scope: journal excerpt only; TLS ready does not establish websocket upgrade, application traffic or DPI resistance.')
if __name__=='__main__':main()
