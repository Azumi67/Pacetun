#include "../src/runtime.cpp"
#include <sys/wait.h>
#include <cassert>
namespace pacetun {
int test_tun_fd=-1;
TunDevice::TunDevice(const std::string& name,const std::string&,const std::string&,int):fd_(test_tun_fd),name_(name){}
TunDevice::~TunDevice(){if(fd_>=0)close(fd_);}
std::ptrdiff_t TunDevice::read_packet(std::span<unsigned char> b){return ::read(fd_,b.data(),b.size());}
std::ptrdiff_t TunDevice::write_packet(std::span<const unsigned char> b){return ::write(fd_,b.data(),b.size());}
}
using namespace pacetun;
int main(){
 int ct[2],st[2],report[2];assert(socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK,0,ct)==0);
 assert(socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK,0,st)==0);assert(pipe(report)==0);
 int listener=listen_tcp(std::getenv("PACETUN_TEST_LISTEN")?std::getenv("PACETUN_TEST_LISTEN"):"127.0.0.1:0",16);sockaddr_in addr{};socklen_t n=sizeof(addr);
 assert(getsockname(listener,reinterpret_cast<sockaddr*>(&addr),&n)==0);
 char keypath[]="/tmp/pacetun-pool-test-XXXXXX";int keyfd=mkstemp(keypath);assert(keyfd>=0);
 std::vector<unsigned char> key(32,0x5a);assert(write(keyfd,key.data(),key.size())==32);close(keyfd);
 Config cfg;cfg.transport="websocket";cfg.max_connections=2;cfg.websocket_tls=false;
 cfg.server="127.0.0.1:"+std::to_string(ntohs(addr.sin_port));cfg.server_name=cfg.host_header="example.test";
 if(auto target=std::getenv("PACETUN_TEST_ADAPTER_TCP"))cfg.server=target;
 cfg.path="/ws";cfg.psk_file=keypath;cfg.pool_drain_sec=1;cfg.latency_renew_cooldown_sec=1;
 cfg.session_max_age_sec=2;cfg.connect_timeout_sec=2;cfg.websocket_upgrade_timeout_sec=2;
 cfg.traffic_shaping=true;cfg.shaping_rate_bytes=256;cfg.shaping_burst_bytes=64;cfg.browser_profile="firefox120";
 cfg.websocket_padding_max_bytes=32;cfg.websocket_control_padding_bytes=16;cfg.padding_budget_pct=5;
 cfg.websocket_ping_sec=1;cfg.websocket_pong_timeout_sec=4;cfg.rtt_probe_sec=5;cfg.stats_interval_sec=60;
 pid_t server=fork();assert(server>=0);
 if(server==0){
  close(ct[0]);close(ct[1]);close(st[0]);close(report[0]);close(report[1]);test_tun_fd=st[1];
  signal(SIGTERM,on_signal);cfg.mode="server";
  try{TunDevice tun("test","","",1280);Stats stats;
   AdmissionServer admission(listener,cfg.host_header,cfg.path,{key},2000,2,8,2);
   pool_tunnel_loop(tun,cfg,stats,&admission,nullptr);
  }catch(const std::exception& e){std::cerr<<e.what()<<"\n";_exit(2);} _exit(0);
 }
 pid_t client=fork();assert(client>=0);
 if(client==0){
  close(listener);close(st[0]);close(st[1]);close(ct[0]);close(report[0]);test_tun_fd=ct[1];
  signal(SIGTERM,on_signal);cfg.mode="client";Stats stats;
  try{TunDevice tun("test","","",1280);pool_tunnel_loop(tun,cfg,stats,nullptr,nullptr);}
  catch(const std::exception& e){std::cerr<<e.what()<<"\n";_exit(2);}
  std::uint64_t result[3]={stats.session_renewals.load(),stats.tun_out_pkts.load(),stats.padding_extra_tx.load()};
  (void)write(report[1],result,sizeof(result));_exit(0);
 }
 close(listener);close(ct[1]);close(st[1]);close(report[1]);
 unsigned received=0;auto start=Clock::now();
 std::vector<unsigned char> packet(44,0);packet[0]=0x45;packet[3]=44;packet[9]=6;packet[12]=10;packet[16]=10;packet[19]=2;
 unsigned serial=0;
 while(Clock::now()-start<std::chrono::seconds(8)){
  packet[15]=static_cast<unsigned char>(serial++);packet[20]=packet[15];
  (void)write(ct[0],packet.data(),packet.size());
  pollfd polls[2]={{st[0],POLLIN,0},{ct[0],POLLIN,0}};(void)poll(polls,2,10);
  unsigned char buf[2048];ssize_t len;
  while((len=read(st[0],buf,sizeof(buf)))>0){assert(len==44&&buf[0]==0x45);(void)write(st[0],buf,static_cast<size_t>(len));}
  while((len=read(ct[0],buf,sizeof(buf)))>0){assert(len==44&&buf[0]==0x45);++received;}
 }
 kill(client,SIGTERM);int cs=0;waitpid(client,&cs,0);kill(server,SIGTERM);int ss=0;waitpid(server,&ss,0);
 std::uint64_t result[3]{};assert(read(report[0],result,sizeof(result))==sizeof(result));
 close(report[0]);close(ct[0]);close(st[0]);unlink(keypath);
 assert(WIFEXITED(cs)&&WEXITSTATUS(cs)==0&&WIFEXITED(ss)&&WEXITSTATUS(ss)==0);
 assert(result[2]<=64+256*10);
 assert(received>100&&result[0]>=1&&result[1]>100&&result[2]>0);
 std::cout<<"PTT8 production loops: "<<received<<" echoed packets, "<<result[0]<<" verified replacements, "<<result[2]<<" padding bytes; PASS\n";
}
