#!/usr/bin/env python3
"""Detailed PaceTun journal"""
from __future__ import annotations
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))')
SECRET = re.compile(
    r'(?i)(?<![\w])((?:psk|password|passwd|secret|private[_-]?key|authorization|'
    r'access[_-]?token|bearer[_-]?token)\s*[:=]\s*)(?:["\']?[^\s|,;"\']+["\']?)'
)
BEARER = re.compile(r'(?i)\bBearer\s+[^\s|,;]+')
STATE = re.compile(r'\b(ONLINE|DEGRADED|RECONNECTING|CONNECTING|LISTENING|WAITING|OFFLINE)\b')
METRICS = re.compile(r'\b(?:RTT(?: p95)?|authenticated round-trip)\s+[0-9]+(?:\.[0-9]+)?\s*ms\b', re.I)
TAGS = re.compile(r'\[(?:ERROR|WARN|WARNING|HEALTH|TRAFFIC|OK|INFO|SESSION|CANDIDATE|CORE|TUN|WS|TLS|PROFILE|STATS|EVENT)\]')
RESET = '\x1b[0m'
PALETTE = {'error': '\x1b[1;31m', 'warn': '\x1b[1;33m', 'ok': '\x1b[1;32m',
           'info': '\x1b[1;36m', 'metric': '\x1b[1;35m', 'subtle': '\x1b[90m'}


def sanitize(raw: str) -> str:
    s = ANSI.sub('', raw).replace('\x1b', '')
    s = ''.join(c if c == '\t' or ord(c) >= 32 and ord(c) != 127 else ' ' for c in s)
    s = SECRET.sub(lambda m: m.group(1) + '[REDACTED]', s)
    return BEARER.sub('Bearer [REDACTED]', s).rstrip('\n')


def enabled(mode: str) -> bool:
    return mode == 'always' or mode == 'auto' and sys.stdout.isatty() and os.getenv('TERM') != 'dumb' and 'NO_COLOR' not in os.environ


def severity(text: str) -> str:
    if re.search(r'\[(?:ERROR)\]|\b(?:event=connect_failed|event=accept_failed)\b', text):
        return 'error'
    if re.search(r'\[(?:WARN|WARNING)\]|\b(?:event=closed|RECONNECTING)\b', text):
        return 'warn'
    if re.search(r'\[(?:HEALTH|OK)\]|\b(?:ONLINE|event=tls_ready)\b', text):
        return 'ok'
    return 'info'


def render(raw: str, color: bool = False) -> str:
    line = sanitize(raw)
    if not color:
        return line
    tone = severity(line)
    line = TAGS.sub(lambda m: PALETTE[tone] + m.group() + RESET, line)
    line = STATE.sub(lambda m: PALETTE['ok' if m.group() == 'ONLINE' else 'warn' if m.group() in ('DEGRADED','RECONNECTING','OFFLINE') else 'info'] + m.group() + RESET, line)
    return METRICS.sub(lambda m: PALETTE['metric'] + m.group() + RESET, line)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--file', type=Path, help='render an exported journal file (offline testing)')
    p.add_argument('--lines', type=int, default=60)
    p.add_argument('--follow', action='store_true')
    p.add_argument('--include-go', action='store_true', help='include the Iran uTLS bridge alongside the core')
    p.add_argument('--color', choices=('auto','always','never'), default='auto')
    a = p.parse_args()
    if not 1 <= a.lines <= 5000:
        p.error('--lines must be 1..5000')
    if a.file and a.follow:
        p.error('--follow and --file are mutually exclusive')
    use_color = enabled(a.color)
    if a.file:
        try:
            entries = a.file.read_text(encoding='utf-8', errors='replace').splitlines()[-a.lines:]
        except OSError:
            print('Cannot read exported journal.', file=sys.stderr)
            return 1
        for line in entries:
            print(render(line, use_color))
        return 0
    cmd = ['journalctl', '-u', 'pacetun-cdn']
    if a.include_go:
        cmd += ['-u', 'pacetun-utls-bridge']
    cmd += ['-n', str(a.lines), '--no-pager', '--output=short-iso']
    if a.follow:
        cmd.append('--follow')
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, encoding='utf-8', errors='replace', bufsize=1) as process:
            assert process.stdout is not None
            for line in process.stdout:
                print(render(line, use_color), flush=a.follow)
            return 0 if process.wait() == 0 else 1
    except KeyboardInterrupt:
        return 0
    except OSError:
        print('journalctl unavailable.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
