#include "pacetun/tun.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <cerrno>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace pacetun {
namespace {
std::string ip_only(const std::string& cidr){auto p=cidr.find('/');return p==std::string::npos?cidr:cidr.substr(0,p);} 
void safe_token(const std::string& s){if(s.empty())throw std::runtime_error("empty network token");for(unsigned char c:s)if(!(std::isalnum(c)||c=='.'||c==':'||c=='/'||c=='_'||c=='-'))throw std::runtime_error("unsafe network token: "+s);} 
int validate_cidr(const std::string& value) {
  const auto slash = value.find('/');
  if (slash == std::string::npos || slash == 0 || slash + 1 == value.size() || value.find('/', slash + 1) != std::string::npos)
    throw std::runtime_error("TUN address must be an IP address with prefix length: " + value);
  const auto address = value.substr(0, slash);
  const auto prefix = value.substr(slash + 1);
  if (prefix.empty() || !std::all_of(prefix.begin(), prefix.end(), [](unsigned char c){return std::isdigit(c) != 0;}))
    throw std::runtime_error("invalid TUN address prefix: " + value);
  unsigned long bits = 0;
  try { bits = std::stoul(prefix); } catch (...) { throw std::runtime_error("invalid TUN address prefix: " + value); }
  unsigned char storage[16]{};
  const int family = address.find(':') == std::string::npos ? AF_INET : AF_INET6;
  if (inet_pton(family, address.c_str(), storage) != 1 || bits > (family == AF_INET ? 32UL : 128UL))
    throw std::runtime_error("invalid TUN IP address or prefix: " + value);
  return family;
}
void run_ip(std::vector<std::string> args){
  std::vector<char*> argv;argv.reserve(args.size()+2);argv.push_back(const_cast<char*>("ip"));
  for(auto&arg:args)argv.push_back(arg.data());
  argv.push_back(nullptr);
  const pid_t pid=fork();
  if(pid<0)throw std::runtime_error("fork for ip failed: "+std::string(std::strerror(errno)));
  if(pid==0){execvp("ip",argv.data());_exit(127);}
  int status=0;pid_t w;do{w=waitpid(pid,&status,0);}while(w<0&&errno==EINTR);
  if(w<0)throw std::runtime_error("waitpid for ip failed: "+std::string(std::strerror(errno)));
  if(!WIFEXITED(status)||WEXITSTATUS(status)!=0){
    std::string cmd="ip";for(const auto&a:args)cmd+=" "+a;
    throw std::runtime_error("command failed: "+cmd);
  }
}
}
void validate_tun_inputs(const std::string& dev, const std::string& cidr,
                         const std::string& peer_cidr, int mtu) {
  safe_token(dev);
  if (dev.size() >= IFNAMSIZ || dev.front() == '-' || dev.find('/') != std::string::npos ||
      dev.find(':') != std::string::npos || dev.find('.') == 0)
    throw std::runtime_error("TUN interface name must be 1-15 safe characters");
  safe_token(cidr);
  safe_token(peer_cidr);
  if (mtu < 576 || mtu > 9000) throw std::runtime_error("TUN MTU must be 576-9000");
  const int family = validate_cidr(cidr);
  if (family != validate_cidr(peer_cidr))
    throw std::runtime_error("TUN and peer addresses must use the same IP family");
  if (family == AF_INET6 && mtu < 1280)
    throw std::runtime_error("IPv6 TUN MTU must be at least 1280");
  if (ip_only(cidr) == ip_only(peer_cidr))
    throw std::runtime_error("TUN and peer IP addresses must differ");
}
TunDevice::TunDevice(const std::string& dev,const std::string& cidr,const std::string& peer_cidr,int mtu){
  validate_tun_inputs(dev,cidr,peer_cidr,mtu);
  fd_=::open("/dev/net/tun",O_RDWR|O_CLOEXEC|O_NONBLOCK); if(fd_<0) throw std::runtime_error("open /dev/net/tun failed: "+std::string(std::strerror(errno)));
  ifreq ifr{}; ifr.ifr_flags=IFF_TUN|IFF_NO_PI; std::snprintf(ifr.ifr_name,IFNAMSIZ,"%s",dev.c_str());
  if(ioctl(fd_,TUNSETIFF,&ifr)<0){auto e=std::string(std::strerror(errno));::close(fd_);fd_=-1;throw std::runtime_error("TUNSETIFF failed: "+e);} name_=ifr.ifr_name;
  try {
    run_ip({"link","set","dev",name_,"mtu",std::to_string(mtu)});
    run_ip({"addr","flush","dev",name_,"scope","global"});
    run_ip({"addr","add",ip_only(cidr),"peer",ip_only(peer_cidr),"dev",name_});
    run_ip({"link","set","dev",name_,"up"});
    if (validate_cidr(cidr) == AF_INET6) {
      run_ip({"-6","route","replace",ip_only(peer_cidr)+"/128","dev",name_,"src",ip_only(cidr)});
    }
  } catch (...) {
    ::close(fd_);
    fd_ = -1;
    throw;
  }
}
std::ptrdiff_t TunDevice::read_packet(std::span<unsigned char> packet) {
  return ::read(fd_, packet.data(), packet.size());
}
std::ptrdiff_t TunDevice::write_packet(std::span<const unsigned char> packet) {
  return ::write(fd_, packet.data(), packet.size());
}
TunDevice::~TunDevice(){if(fd_>=0)::close(fd_);} 
}
