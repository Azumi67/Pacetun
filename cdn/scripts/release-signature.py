#!/usr/bin/env python3
"""Ed25519 manifest signatures via OpenSSL"""
import argparse
from pathlib import Path
import subprocess
import sys

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['sign','verify'])
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--signature',type=Path,required=True)
    p.add_argument('--private-key',type=Path);p.add_argument('--public-key',type=Path);a=p.parse_args()
    if a.action=='sign':
        if not a.private_key:p.error('--private-key is required')
        if a.signature.exists():p.error('Refusing to overwrite an existing signature')
        cmd=['openssl','pkeyutl','-sign','-rawin','-inkey',str(a.private_key),'-in',str(a.manifest),'-out',str(a.signature)]
    else:
        if not a.public_key:p.error('--public-key from a trusted channel is required')
        cmd=['openssl','pkeyutl','-verify','-pubin','-rawin','-inkey',str(a.public_key),'-in',str(a.manifest),'-sigfile',str(a.signature)]
    subprocess.run(cmd,check=True,timeout=15)
    print('Signature operation passed. Verify the manifest file hashes before running binaries.')
if __name__=='__main__':
    try:main()
    except (OSError,subprocess.SubprocessError) as e:print('Signature failed:',e,file=sys.stderr);sys.exit(1)
