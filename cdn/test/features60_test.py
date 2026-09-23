import importlib.util, unittest
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('features',Path(__file__).resolve().parents[1]/'scripts/features60.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FeatureTests(unittest.TestCase):
 def args(self,**kw):
  d=dict(shaping='on',browser_profile=None,startup_paths=None,carrier=None,http_path='/assets/transfer/v1',http_key=Path('/etc/pacetun-cdn/http.key'));d.update(kw);return SimpleNamespace(**d)
 def test_client_preserves_routing_and_family(self):
  cfg=dict(mode='client',transport='websocket',tls_backend='utls',server='[::1]:443',cidr='fd87:42::2/126',path='/assets/live/v6')
  unit='[Service]\nExecStart=/usr/local/bin/pacetun-utls-bridge --remote example.test:443 --server-name example.test --fingerprint firefox120 --family ipv6 --socket /run/pacetun-utls/bridge.sock\n'
  out=m.render(cfg,self.args(carrier='http'),unit)
  text=out[m.BRIDGE_UNIT][0].decode();self.assertIn('"--family" "ipv6"',text);self.assertIn('"--carrier" "http-client"',text)
  core=out[m.i.CONFIG][0].decode();self.assertIn('cidr=fd87:42::2/126',core);self.assertIn('path=/assets/live/v6',core);self.assertIn('traffic_shaping=1',core)
  out=m.render(cfg,self.args(carrier='websocket'),text);self.assertNotIn('--http-key',out[m.BRIDGE_UNIT][0].decode())
 def test_server_generates_additive_snippet(self):
  out=m.render(dict(mode='server',transport='websocket',listen='127.0.0.1:19443'),self.args(carrier='http'))
  text=out[m.HTTP_SNIPPET][0].decode();self.assertIn('proxy_buffering off',text);self.assertNotIn('listen ',text)
  self.assertIn('"--http-backend" "127.0.0.1:19443"',out[m.HTTP_UNIT][0].decode())
 def test_conflicting_startup_http_rejected(self):
  with self.assertRaises(ValueError):m.render(dict(mode='client',transport='websocket',tls_backend='utls'),self.args(carrier='http',startup_paths='/'),'ExecStart=/usr/local/bin/pacetun-utls-bridge\n')
if __name__=='__main__':unittest.main()
