#!/usr/bin/env python3
from pathlib import Path
import importlib.util
import tempfile
import hashlib
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_gate',ROOT/'scripts/release-gate.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    (root/'payload').write_bytes(b'original')
    digest=hashlib.sha256(b'original').hexdigest()
    (root/'SHA256SUMS').write_text(f'{digest}  payload\n')
    assert not m.manifest_errors(root)
    (root/'payload').write_bytes(b'changed');assert m.manifest_errors(root)
    (root/'payload').write_bytes(b'original')
    (root/'unlisted').write_text('x');assert m.manifest_errors(root)
    (root/'unlisted').unlink()
    (root/'SHA256SUMS').write_text(f'{digest}  ../escape\n');assert m.manifest_errors(root)
    (root/'SHA256SUMS').write_text(f'{digest}  payload\n{digest}  payload\n');assert m.manifest_errors(root)
assert m.elf_amd64(ROOT/'bin/pacetun-cdn-linux-amd64')
print('Release-gate test PASS: integrity, inventory, path and architecture checks')
