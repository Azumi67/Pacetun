#include "pacetun/config.hpp"
#include "pacetun/runtime.hpp"
#include "pacetun/logging.hpp"
#include "pacetun/tun.hpp"
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
  try {
    if (argc==2 && std::string(argv[1])=="--platform") {
      std::cout << "os=linux backend=linux-tun windows=unsupported macos=unsupported freebsd=unsupported socks5=not-implemented release=6.0.0-alpha1\n";
      return 0;
    }
    if (argc==3 && std::string(argv[1])=="--explain") {
      const auto e=pacetun::explain_problem(argv[2]);
      std::cout<<"Code: "<<argv[2]<<"\nMeaning: "<<e.meaning<<"\nNext step: "<<e.next_step<<"\n";
      return 0;
    }
    if (argc==2 && std::string(argv[1])=="diagnose")
      return pacetun::control_command("/run/pacetun-cdn/control.sock", "diagnose");
    std::string path, control, command;
    bool check=false, print=false;
    for (int i=1;i<argc;i++) {
      const std::string a=argv[i];
      if (a=="--config" && i+1<argc) path=argv[++i];
      else if (a=="--check-config") check=true;
      else if (a=="--print-effective-config") print=true;
      else if (a=="--control" && i+2<argc) {
        control=argv[++i];command=argv[++i];
      } else if(a=="--version") {
        std::cout<<"pacetun-cdn 6.0.0-alpha1-linux\n";return 0;
      } else if(a=="--help"||a=="-h") {
        std::cout<<"pacetun-cdn 6.0.0-alpha1-linux\n"
          "Usage:\n"
          "  pacetun-cdn --config FILE [--check-config|--print-effective-config]\n"
          "  pacetun-cdn --platform\n"
          "  pacetun-cdn diagnose\n"
          "  pacetun-cdn --explain ERROR_CODE\n"
          "  pacetun-cdn --control SOCKET {overview|status|stats|health|events|diagnose|reconnect|stop}\n";
        return 0;
      } else throw std::runtime_error("unknown argument: "+a);
    }
    if (!control.empty())return pacetun::control_command(control,command);
    if (path.empty())throw std::runtime_error("--config FILE is required");
    auto c=pacetun::load_config(path);
    pacetun::validate_tun_inputs(c.dev,c.cidr,c.peer_cidr,c.mtu);
    if (check){std::cout<<"configuration OK\n";return 0;}
    if (print){std::cout<<pacetun::effective_config(c);return 0;}
    return pacetun::run(c);
  }catch(const std::exception& e){
    std::cerr<<"fatal: "<<e.what()<<"\n";return 1;
  }
}
