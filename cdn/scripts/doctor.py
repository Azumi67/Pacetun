#!/usr/bin/env python3
"""diagnostics"""
import argparse,ipaddress,json,os,shutil,socket,ssl,subprocess,time
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,default=Path('/etc/pacetun-cdn/tunnel.conf'));a=p.parse_args()
 cfg={}
 for raw in a.config.read_text().splitlines():
  line=raw.split('#',1)[0].strip()
  if '=' in line:k,v=line.split('=',1);cfg[k.strip()]=v.strip()
 out={'tun_device':Path('/dev/net/tun').exists(),'iproute2':bool(shutil.which('ip')),'mode':cfg.get('mode'),'tls_backend':cfg.get('tls_backend','openssl')}
 if cfg.get('mode')=='client':
  endpoint=cfg['server'];host,port=endpoint.rsplit(':',1);host=host.strip('[]');port=int(port)
  start=time.monotonic()
  try:
   addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
   out['dns']={'ok':True,'families':sorted(set('ipv6' if x[0]==socket.AF_INET6 else 'ipv4' for x in addresses)),'ms':round((time.monotonic()-start)*1000,1)}
  except OSError as e:out['dns']={'ok':False,'error':str(e)};addresses=[]
  try:
   ctx=ssl.create_default_context(cafile=cfg.get('tls_ca') or None);ctx.set_alpn_protocols(['http/1.1'])
   with socket.create_connection((host,port),timeout=5) as raw:
    out['tcp']={'ok':True}
    with ctx.wrap_socket(raw,server_hostname=cfg['server_name']) as tls:
     out['tls']={'ok':True,'version':tls.version(),'alpn':tls.selected_alpn_protocol(),'certificate_verified':True}
   out['note']='TLS probe uses Python OpenSSL, not the uTLS fingerprint. Successful TLS is not a WebSocket or inner authentication test.'
  except (OSError,ssl.SSLError) as e:out['tcp_or_tls']={'ok':False,'error':str(e)}
 else:out['note']='Server role: use existing status/path-check scripts and client diagnostics to distinguish origin reachability from tunnel authentication.'
 print(json.dumps(out,indent=2))
if __name__=='__main__':main()
