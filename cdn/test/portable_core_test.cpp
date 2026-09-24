#include "../src/runtime.cpp"
#include <cassert>
namespace pacetun {
int tun_peer=-1;
TunDevice::TunDevice(const std::string& name,const std::string&,const std::string&,int):name_(name){int f[2];if(socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK,0,f))throw std::runtime_error("socketpair");fd_=f[0];tun_peer=f[1];}
TunDevice::~TunDevice(){close(fd_);close(tun_peer);}
std::ptrdiff_t TunDevice::read_packet(std::span<unsigned char> packet){return ::read(fd_,packet.data(),packet.size());}
std::ptrdiff_t TunDevice::write_packet(std::span<const unsigned char> packet){return ::write(fd_,packet.data(),packet.size());}
class SimulatedCarrier:public Carrier {
 int f[2];CarrierCounters c;RecordDecoderV5 decoder{Key32{},65536};uint64_t seq=1;
 std::vector<std::vector<unsigned char>> incoming;Clock::time_point last=Clock::now();bool replies;
 public:
 explicit SimulatedCarrier(bool answer):replies(answer){if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,f))throw std::runtime_error("socketpair");}
 ~SimulatedCarrier(){close(f[0]);close(f[1]);}
 std::string_view name()const override{return "simulated";}
 int native_fd()const override{return f[0];}
 void send(std::span<const unsigned char> p)override{
  ++c.tx_messages;c.tx_payload_bytes+=p.size();std::string error;
  if(!decoder.feed(p,[&](uint8_t flags,uint64_t,std::span<const unsigned char> b){
   if(flags==RECORD_PING){auto payload=std::vector<unsigned char>(b.begin(),b.end());if(!replies)payload.back()^=1;incoming.push_back(encode_record_v5(Key32{},seq++,payload,RECORD_PONG));}
  },error))throw std::runtime_error(error);
 }
 std::vector<std::vector<unsigned char>> read(int)override{
  if(Clock::now()-last>std::chrono::milliseconds(50)){
    incoming.push_back(encode_record_v5(Key32{},seq++,{},RECORD_KEEPALIVE));last=Clock::now();
  }
  auto out=std::move(incoming);incoming.clear();c.rx_frames+=out.size();return out;
 }
 size_t flush(size_t)override{return 0;}
 bool tx_pending()const override{return false;}
 short tx_poll_events()const override{return 0;}
 short rx_poll_events()const override{return POLLIN;}
 size_t tx_pending_bytes()const override{return 0;}
 bool tx_stalled(int)const override{return false;}
 void send_ping(std::span<const unsigned char>)override{}
 std::vector<std::vector<unsigned char>> take_pongs()override{return {};}
 CarrierCounters counters()const override{return c;}
};
void runtime_case(bool replies){
 Config cfg;cfg.rtt_probe_sec=5;cfg.idle_probe_sec=5;cfg.timing_jitter_pct=0;cfg.websocket_poll_ms=1;
 cfg.reply_degraded_sec=1;cfg.reply_renew_sec=1;cfg.reply_timeout_sec=2;cfg.websocket_ping_sec=0;
 TunDevice tun("test","","",1200);SimulatedCarrier carrier(replies);Stats st;Key32 key{};g_stop=false;g_state=3;g_phase=7;
 auto start=Clock::now();bool timed_out=false,saw_degraded=false;
 try{carrier_tunnel_loop(carrier,tun,cfg,st,key,key,[&]{
  saw_degraded|=st.degraded.load();
  if(Clock::now()-start>std::chrono::milliseconds(7500))g_stop=true;
 });}catch(const std::exception& e){timed_out=std::string(e.what())=="authenticated probe reply timeout";if(!timed_out)throw;}
 if(replies){if(timed_out||saw_degraded||st.rtt_sample_us.load()==0)throw std::runtime_error("healthy peer watchdog regression");}
 else{if(!timed_out||!saw_degraded||st.rtt_sample_us.load()!=0||st.reply_timeouts!=1)throw std::runtime_error("silent peer not detected");}
 g_state=2;auto status=status_text(st,cfg,start,true);if(status.find("rtt_ms=-1")==std::string::npos)throw std::runtime_error("stale RTT exposed while connecting");auto human=overview_text(st,cfg);if(human.find("Tunnel round-trip: unavailable") == std::string::npos) throw std::runtime_error("stale RTT exposed in human overview");g_stop=false;
}
}
int main(){
  const auto require_code=[](int phase,const std::string& detail,const std::string& expected){
    if(std::string(pacetun::failure_code(phase,detail))!=expected)
      throw std::runtime_error("incorrect failure classification for "+detail);
  };
  require_code(5,"WebSocket upgrade rejected: HTTP/1.1 504 Gateway Time-out","HTTP_504_TIMEOUT");
  require_code(5,"WebSocket upgrade rejected: HTTP/1.1 502 Bad Gateway","HTTP_502_GATEWAY");
  require_code(3,"DNS resolution failed for test.invalid: not known","DNS_RESOLUTION_FAILED");
  require_code(3,"TCP connect failed to test.invalid:443: Connection timed out","TCP_CONNECT_TIMEOUT");
  require_code(4,"TLS handshake timeout","TLS_HANDSHAKE_TIMEOUT");
  require_code(4,"TLS connect failed: certificate verify failed","TLS_CERTIFICATE_FAILED");
  pacetun::runtime_case(false);pacetun::runtime_case(true);std::cout<<"production runtime: missing replies, mismatched PONG, healthy replies and stale status PASS\n";}
