#!/usr/bin/env python3
import argparse
import datetime
import os
from pathlib import Path
import shutil
import sys
import tempfile
import urllib.request

BASE=Path(__file__).resolve().parent
BACKUP_ROOT=Path('/root')
DEST={'iran':Path('/var/www/iranian'),'foreign':Path('/var/www/pacetun-cdn')}
EXPECTED={'iran':('روزنهٔ فناوری','Iranian website is working','پیس‌تون'),'foreign':('دفتر فناوری',)}
PHOTO='https://upload.wikimedia.org/wikipedia/commons/b/b3/Wikimedia_Foundation_Servers_2015-63.jpg'

def data(role):
    src=BASE/role
    if not src.is_dir(): raise RuntimeError('Missing package source: '+str(src))
    for p in src.rglob('*'):
        if p.is_symlink() or (not p.is_file() and not p.is_dir()):
            raise RuntimeError('Unexpected file type in package: '+str(p))
    files=[p for p in src.rglob('*') if p.is_file()]
    if not (src/'index.html').is_file() or not any(p.name.endswith('.css') for p in files):
        raise RuntimeError('Incomplete website package')
    return src,files

def guard(role,dest):
    if os.geteuid()!=0: raise RuntimeError('Run as root on the target VPS')
    if dest.is_symlink() or not dest.is_dir() or not (dest/'index.html').is_file():
        raise RuntimeError('Expected existing Nginx website directory is missing; no changes made: '+str(dest))
    title=(dest/'index.html').read_text(encoding='utf-8',errors='replace')
    if not any(mark in title for mark in EXPECTED[role]):
        raise RuntimeError('Existing site does not match expected '+role+' website. Refusing overwrite.')
    for node in [dest,*dest.parents]:
        if node.is_symlink(): raise RuntimeError('Symlink in destination path: '+str(node))

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('role',choices=('iran','foreign'))
    mode=ap.add_mutually_exclusive_group()
    mode.add_argument('--check',action='store_true',help='read-only readiness check')
    mode.add_argument('--install',action='store_true',help='copy static files only, backing up overwritten files')
    ap.add_argument('--photo',action='store_true',help='try downloading the credited Wikimedia photograph for local hosting (internet required)')
    args=ap.parse_args()
    src,files=data(args.role);dest=DEST[args.role];guard(args.role,dest)
    changes=[]
    for p in files:
        rel=p.relative_to(src);target=dest/rel
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise RuntimeError('Unexpected destination file: '+str(target))
        if target.parent.exists() and target.parent.is_symlink():
            raise RuntimeError('Destination folder is symlink: '+str(target.parent))
        if not target.is_file() or p.read_bytes()!=target.read_bytes():changes.append((p,target,rel))
    print(f'Role={args.role} Target={dest} Source_files={len(files)} Files_to_update={len(changes)}')
    if not args.install:
        print('READ ONLY: no files changed. Re-run with --install to deploy.');return
    backup=BACKUP_ROOT/('website-backup-'+args.role+'-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+str(os.getpid()))
    backup.mkdir(mode=0o700)
    written=[]
    try:
        for source,target,rel in changes:
            was=target.exists()
            if was:
                prior=backup/rel;prior.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(target,prior,follow_symlinks=False)
            target.parent.mkdir(parents=True,exist_ok=True)
            if target.parent.is_symlink():raise RuntimeError('Destination parent is symlink: '+str(target.parent))
            fd,tmp=tempfile.mkstemp(prefix='.website-',dir=target.parent)
            try:
                with os.fdopen(fd,'wb') as f:
                    f.write(source.read_bytes());f.flush();os.fsync(f.fileno())
                os.chmod(tmp,0o644);os.replace(tmp,target)
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
            written.append((target,rel,was))
        if args.photo:
            try:
                req=urllib.request.Request(PHOTO,headers={'User-Agent':'PaceTun-Website/1.0 (https://commons.wikimedia.org)'})
                with urllib.request.urlopen(req,timeout=20) as response:
                    ct=response.headers.get('Content-Type','').lower()
                    if 'image/jpeg' not in ct:raise ValueError('Not a JPEG response')
                    payload=response.read(7_000_001)
                if len(payload)>7_000_000 or len(payload)<100_000 or not payload.startswith(b'\xff\xd8'):
                    raise ValueError('Unexpected photograph size or encoding')
                photo=dest/'assets'/'server.jpg'
                if photo.is_symlink():raise ValueError('Photograph destination is symlink')
                if photo.exists():
                    b=backup/'assets'/'server.jpg';b.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(photo,b)
                fd,tmp=tempfile.mkstemp(prefix='.photo-',dir=photo.parent)
                with os.fdopen(fd,'wb') as f:f.write(payload)
                os.chmod(tmp,0o644);os.replace(tmp,photo)
                index=dest/'index.html'
                text=index.read_text(encoding='utf8')
                token='class="real-photo" src="/assets/server.svg"'
                if token not in text:raise ValueError('Expected photo marker not present')
                text=text.replace(token,'class="real-photo" src="/assets/server.jpg"',1)
                fd,tmp=tempfile.mkstemp(prefix='.website-',dir=index.parent)
                with os.fdopen(fd,'w',encoding='utf8') as f:f.write(text)
                os.chmod(tmp,0o644);os.replace(tmp,index)
                text=index.read_text(encoding='utf8')
                old='تصویرسازی آموزشی؛ عکس واقعی پس از دریافت از Wikimedia Commons'
                new='عکس واقعی: Victor Grigas/Wikimedia Foundation، CC BY-SA 3.0'
                if old in text:
                    fd,tmp=tempfile.mkstemp(prefix='.website-',dir=index.parent)
                    with os.fdopen(fd,'w',encoding='utf8') as f:f.write(text.replace(old,new,1))
                    os.chmod(tmp,0o644);os.replace(tmp,index)
                print('PHOTO: locally downloaded with attribution from Wikimedia Commons')
            except Exception as ex:
                print('PHOTO NOT DOWNLOADED; original local SVG remains: '+str(ex))
        print(f'INSTALLED {len(written)} static files. Existing files backed up at {backup}.')
        print('Nginx, certificates, PaceTun, foreign/Iran roles and PSK were NOT modified.')
    except Exception:
        for target,rel,was in reversed(written):
            if was:shutil.copy2(backup/rel,target)
            elif target.exists():target.unlink()
        print('ERROR: website changes rolled back. Backup: '+str(backup),file=sys.stderr)
        raise
if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError) as exc:
        print('ERROR: '+str(exc),file=sys.stderr);sys.exit(1)
