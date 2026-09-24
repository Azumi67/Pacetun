#!/usr/bin/env python3
"""configuration checker"""
from __future__ import annotations
import argparse
import json
import os
import stat
import sys
from pathlib import Path


def inspect(config: Path) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    def add(level: str, check: str, detail: str):
        results.append(dict(level=level, check=check, detail=detail))
    if not config.is_file() or config.is_symlink():
        add('FAIL', 'configuration', 'Regular configuration file not found (or symlink).')
        return results
    try:
        text = config.read_text(encoding='utf-8')
        cfg: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                cfg[key.strip()] = value.strip()
        role = cfg.get('mode')
        if role not in ('client', 'server'):
            add('FAIL', 'role', 'Unrecognized role.')
        else:
            add('PASS', 'role', 'Iran client' if role == 'client' else 'Foreign server')
        transport = cfg.get('transport')
        if transport == 'websocket':
            add('PASS', 'wire', 'WebSocket configuration selects PTT5 inner transport in this source tree.')
            add('INFO', 'e2ee', 'PTT5 source uses PSK-authenticated ephemeral X25519 and ChaCha20-Poly1305; not independently audited or runtime-verified by this check.')
        else:
            add('WARN', 'wire', 'Not configured for PTT5 WebSocket; do not assume X25519 forward secrecy.')
        if role == 'client':
            if cfg.get('verify_peer', '1').lower() in ('1','true','yes','on'):
                add('PASS', 'certificates', 'Peer certificate verification enabled in core configuration.')
            else:
                add('FAIL', 'certificates', 'Peer certificate verification disabled.')
            if transport == 'websocket' and cfg.get('websocket_tls', '1').lower() in ('1','true','yes','on'):
                add('PASS', 'wss', 'Outer TLS configured for WebSocket transport.')
            else:
                add('WARN', 'wss', 'Outer TLS may be disabled or not applicable.')
            if cfg.get('tls_backend') == 'utls':
                add('PASS', 'utls', 'uTLS sidecar selected; verify running bridge separately.')
            else:
                add('INFO', 'utls', 'uTLS not selected in this configuration; standard TLS may be in use.')
        else:
            listen = cfg.get('listen', '')
            if listen.startswith(('127.0.0.1:', '[::1]:')):
                add('PASS', 'origin', 'Backend listener restricted to loopback.')
            else:
                add('WARN', 'origin', 'Backend listener is not obviously loopback-only; inspect network exposure.')
            add('INFO', 'cdn_origin', 'Origin TLS and CDN settings cannot be verified by this local config check.')
        if cfg.get('strict_file_permissions', '1').lower() in ('1','true','yes','on'):
            add('PASS', 'permissions', 'Strict secret permission checking enabled.')
        else:
            add('WARN', 'permissions', 'Strict secret permission checking disabled.')
        secret = cfg.get('psk_file', '')
        if secret:
            key = Path(secret)
            try:
                if key.is_symlink():
                    add('FAIL', 'psk', 'PSK path is a symlink.')
                else:
                    mode = key.stat().st_mode
                    add('PASS' if stat.S_ISREG(mode) and not (mode & 0o077) else 'FAIL',
                        'psk', 'PSK is a regular file and group/other access is disabled.' if stat.S_ISREG(mode) and not (mode & 0o077) else 'PSK file permissions require review.')
            except OSError:
                add('WARN', 'psk', 'PSK could not be inspected; permissions not confirmed.')
        else:
            add('WARN', 'psk', 'PSK path is unspecified.')
        if cfg.get('websocket_padding_max_bytes', '0') != '0' or cfg.get('timing_jitter_pct', '0') != '0':
            add('INFO', 'traffic_shaping', 'Optional shaping configured; this check cannot establish stealth or performance gains.')
        else:
            add('INFO', 'traffic_shaping', 'No optional packet padding or timing jitter requested; no stealth conclusion follows.')
        add('INFO', 'visibility', 'A CDN terminating TLS can see HTTP/WebSocket metadata and encrypted frame sizes/timing, but not necessarily PTT5 application plaintext.')
        return results
    finally:
        # no print, return
        del text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config', type=Path, default=Path('/etc/pacetun-cdn/tunnel.conf'))
    ap.add_argument('--json', action='store_true', help='structured, secret-free results')
    args = ap.parse_args()
    result = inspect(args.config)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in result:
            print(f'{item["level"]:4s} {item["check"]:16s} {item["detail"]}')
        print('Scope: static checks only. No cryptographic audit, live handshake capture, CDN settings or DPI-resistance claim.')
    return 1 if any(x['level'] == 'FAIL' for x in result) else 0


if __name__ == '__main__':
    sys.exit(main())
