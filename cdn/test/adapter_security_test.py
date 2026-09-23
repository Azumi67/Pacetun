"""offline sign trust and random PSK creation without login into a VPS."""
import subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class SecurityTools(unittest.TestCase):
 def test_signature_rejects_modified_manifest(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);key=d/'key';pub=d/'pub';manifest=d/'SHA256SUMS';sig=d/'sig'
   subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,capture_output=True)
   subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(pub)],check=True,capture_output=True)
   manifest.write_text('test manifest\n')
   common=['python3',str(ROOT/'scripts/release-signature.py')]
   subprocess.run(common+['sign','--private-key',str(key),'--manifest',str(manifest),'--signature',str(sig)],check=True,capture_output=True)
   verify=common+['verify','--public-key',str(pub),'--manifest',str(manifest),'--signature',str(sig)]
   self.assertEqual(subprocess.run(verify,capture_output=True).returncode,0)
   manifest.write_text('tampered\n');self.assertNotEqual(subprocess.run(verify,capture_output=True).returncode,0)
 def test_keygen_no_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'psk';cmd=['python3',str(ROOT/'scripts/keygen.py'),str(p)]
   r=subprocess.run(cmd,capture_output=True,text=True);self.assertEqual(r.returncode,0)
   secret=p.read_text().strip();self.assertEqual(len(bytes.fromhex(secret)),32)
   self.assertNotIn(secret,r.stdout);self.assertEqual(p.stat().st_mode&0o777,0o600)
   self.assertNotEqual(subprocess.run(cmd,capture_output=True).returncode,0);self.assertEqual(secret,p.read_text().strip())
if __name__=='__main__':unittest.main()
