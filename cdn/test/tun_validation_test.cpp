#include "pacetun/tun.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

void reject(const std::string& name, const std::string& local,
            const std::string& peer, int mtu) {
  bool failed = false;
  try { pacetun::validate_tun_inputs(name, local, peer, mtu); }
  catch (const std::runtime_error&) { failed = true; }
  if (!failed) throw std::runtime_error("unsafe TUN settings accepted");
}
int main() {
  pacetun::validate_tun_inputs("pcdn0", "10.87.42.1/30", "10.87.42.2/30", 1200);
  pacetun::validate_tun_inputs("pcdn6", "fd87:34::1/126", "fd87:34::2/126", 1280);
  reject("this-is-too-long0", "10.87.42.1/30", "10.87.42.2/30", 1200);
  reject("../other", "10.87.42.1/30", "10.87.42.2/30", 1200);
  reject("pcdn0", "10.87.42.1/99", "10.87.42.2/30", 1200);
  reject("pcdn0", "10.87.42.1/30", "fd87:34::2/126", 1200);
  reject("pcdn0", "10.87.42.1/30", "10.87.42.1/30", 1200);
  reject("pcdn0", "10.87.42.1/30", "10.87.42.2/30", 100);
  reject("pcdn6", "fd87:42::1/126", "fd87:42::2/126", 1200);
  reject("pcdn0", "10.87.42.1/abc", "10.87.42.2/30", 1200);
  std::cout << "TUN preflight validation passed (IPv4, IPv6, unsafe values rejected)\n";
}
