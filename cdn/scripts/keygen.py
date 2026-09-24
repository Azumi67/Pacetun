#!/usr/bin/env python3
"""Create a new random PSK file"""
import argparse,os,secrets
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('output',type=Path);a=p.parse_args()
fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(32)+'\n');f.flush();os.fsync(f.fileno())
print('Created',a.output,'with mode 0600. Transfer privately; do not paste into logs.')
