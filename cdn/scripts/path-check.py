#!/usr/bin/env python3
"""diagnostics across the private PaceTun IPv6 link"""
from __future__ import annotations

import argparse
import socket
import subprocess
import sys

PEERS={'foreign':'fd87:42::2','iran':'fd87:42::1'}


def run(*argv, timeout=12):
    try:
        return subprocess.run(argv,capture_output=True,text=True,check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired):
        return None


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role',choices=tuple(PEERS),required=True)
    p.add_argument('--tcp-port',type=int,help='optional permitted service port on private peer (1..65535)')
    a=p.parse_args()
    if a.tcp_port is not None and not (1<=a.tcp_port<=65535):p.error('--tcp-port must be 1..65535')
    peer=PEERS[a.role]
    active=run('systemctl','is-active','pacetun-cdn')
    service=bool(active and active.returncode==0 and active.stdout.strip()=='active')
    core=run('/usr/local/bin/pacetun-cdn','--control','/run/pacetun-cdn/control.sock','status')
    state=core.stdout if core and core.returncode==0 else ''
    expected=('[ONLINE]' in state if a.role=='iran' else '[ONLINE]' in state or '[LISTENING]' in state)
    ping=run('ping','-6','-c','3','-W','2',peer,timeout=12)
    reached=bool(ping and ping.returncode==0)
    print(f'role={a.role} service_active={str(service).lower()} authenticated_or_listening={str(expected).lower()}')
    print(f'peer_ipv6_ping={"PASS" if reached else "FAIL"}')
    if a.tcp_port is not None:
        try:
            with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as conn:
                conn.settimeout(3)
                conn.connect((peer,a.tcp_port))
            tcp=True
        except OSError:
            tcp=False
        print(f'private_peer_tcp_port={a.tcp_port} result={"PASS" if tcp else "FAIL"}')
    print('Limit: ping and TCP-open do not prove Xray authentication, CDN stability or successful Internet browsing.')
    return 0 if service and expected and reached and (a.tcp_port is None or tcp) else 1


if __name__=='__main__':sys.exit(main())
