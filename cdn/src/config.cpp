#include "pacetun/config.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace pacetun { namespace {
std::string trim(std::string s){auto n=[](unsigned char c){return !std::isspace(c);};s.erase(s.begin(),std::find_if(s.begin(),s.end(),n));s.erase(std::find_if(s.rbegin(),s.rend(),n).base(),s.end());return s;}
bool bval(const std::string&v){if(v=="1"||v=="true"||v=="yes"||v=="on")return true;if(v=="0"||v=="false"||v=="no"||v=="off")return false;throw std::runtime_error("invalid boolean: "+v);}
int ival(const std::unordered_map<std::string,std::string>&m,const char*k,int d){auto i=m.find(k);return i==m.end()?d:std::stoi(i->second);} 
std::size_t zval(const std::unordered_map<std::string,std::string>&m,const char*k,std::size_t d){auto i=m.find(k);return i==m.end()?d:static_cast<std::size_t>(std::stoull(i->second));}
std::string sval(const std::unordered_map<std::string,std::string>&m,const char*k,const std::string&d={}){auto i=m.find(k);return i==m.end()?d:i->second;}
void range(const char*n,long long v,long long lo,long long hi){if(v<lo||v>hi)throw std::runtime_error(std::string(n)+" out of range");}
void validate_http_field(const char*name,const std::string&s,std::size_t max_len,bool allow_empty=false){
  if(s.empty()){if(allow_empty)return;throw std::runtime_error(std::string(name)+" is required");}
  if(s.size()>max_len)throw std::runtime_error(std::string(name)+" is too long");
  for(char ch:s){
    const auto c=static_cast<unsigned char>(ch);
    if(c<=0x20||c==0x7f)throw std::runtime_error(std::string(name)+" contains whitespace/control characters");
  }
}
void validate_endpoint(const char*name,const std::string&s){
  if(s.empty())throw std::runtime_error(std::string(name)+" is empty");
  std::string host,port;
  if(s.front()=='['){
    const auto rb=s.find(']');
    if(rb==std::string::npos||rb==1||rb+1>=s.size()||s[rb+1]!=':'||rb+2>=s.size())throw std::runtime_error(std::string(name)+" must use [ipv6]:port");
    host=s.substr(1,rb-1);port=s.substr(rb+2);
  }else{
    const auto first=s.find(':'),last=s.rfind(':');
    if(first==std::string::npos||first==0||first!=last||first+1>=s.size())throw std::runtime_error(std::string(name)+" must use host:port (IPv6 requires brackets)");
    host=s.substr(0,first);port=s.substr(first+1);
  }
  if(host.empty()||port.empty()||!std::all_of(port.begin(),port.end(),[](unsigned char c){return std::isdigit(c)!=0;}))throw std::runtime_error(std::string(name)+" has invalid host/port");
  unsigned long value=0;try{value=std::stoul(port);}catch(...){throw std::runtime_error(std::string(name)+" has invalid port");}
  if(value<1||value>65535)throw std::runtime_error(std::string(name)+" port out of range");
}

void apply_profile(Config& c,const std::string& p){
  if(p=="balanced"){
    c.queue_packets=4096;c.queue_bytes=8*1024*1024;c.queue_delay_ms=500;c.batch_packets=8;c.batch_bytes=16384;c.queue_target_delay_ms=40;
    c.sndbuf=4*1024*1024;c.rcvbuf=4*1024*1024;c.keepalive_sec=10;c.rtt_probe_sec=5;c.websocket_poll_ms=5;
  }else if(p=="lightning"){
    c.queue_packets=2048;c.queue_bytes=4*1024*1024;c.queue_delay_ms=25;c.batch_packets=1;c.batch_bytes=4096;c.queue_target_delay_ms=10;
    c.sndbuf=2*1024*1024;c.rcvbuf=2*1024*1024;c.keepalive_sec=5;c.rtt_probe_sec=3;c.websocket_poll_ms=1;
  }else if(p=="bulk"){
    c.queue_packets=8192;c.queue_bytes=16*1024*1024;c.queue_delay_ms=1000;c.batch_packets=32;c.batch_bytes=65536;c.queue_target_delay_ms=100;
    c.sndbuf=8*1024*1024;c.rcvbuf=8*1024*1024;c.keepalive_sec=15;c.rtt_probe_sec=10;c.websocket_poll_ms=15;
  }else if(p=="ultra"){
    c.queue_packets=16384;c.queue_bytes=32*1024*1024;c.queue_delay_ms=750;c.batch_packets=64;c.batch_bytes=131072;c.queue_target_delay_ms=60;
    c.sndbuf=16*1024*1024;c.rcvbuf=16*1024*1024;c.keepalive_sec=10;c.rtt_probe_sec=5;c.websocket_poll_ms=2;
  }
}
void apply_resource_cap(Config& c,const std::string& r){
  if(r!="lowmem")return;
  c.max_record_buffer_bytes=std::min<std::size_t>(c.max_record_buffer_bytes,131072);
  c.queue_packets=std::min<std::size_t>(c.queue_packets,512);
  c.queue_bytes=std::min<std::size_t>(c.queue_bytes,1024*1024);
  c.queue_delay_ms=std::min(c.queue_delay_ms,250);
  c.batch_packets=std::min(c.batch_packets,4);
  c.batch_bytes=std::min<std::size_t>(c.batch_bytes,8192);
  c.sndbuf=std::min(c.sndbuf,524288);c.rcvbuf=std::min(c.rcvbuf,524288);
  c.stats_interval_sec=std::max(c.stats_interval_sec,10);
}
}

Config load_config(const std::string&path){
  std::ifstream in(path);if(!in)throw std::runtime_error("cannot open config: "+path);
  std::unordered_map<std::string,std::string>m;std::string line;int no=0;
  while(std::getline(in,line)){++no;auto h=line.find('#');if(h!=std::string::npos)line.resize(h);line=trim(line);if(line.empty())continue;auto e=line.find('=');if(e==std::string::npos)throw std::runtime_error("config line "+std::to_string(no)+": expected key=value");auto k=trim(line.substr(0,e)),v=trim(line.substr(e+1));if(k.empty())throw std::runtime_error("config line "+std::to_string(no)+": empty key");if(!m.emplace(k,v).second)throw std::runtime_error("duplicate config key: "+k);}
  Config c;
  c.browser_profile=sval(m,"browser_profile",c.browser_profile);
  if(auto i=m.find("traffic_shaping");i!=m.end())c.traffic_shaping=bval(i->second);
  c.shaping_startup_ms=ival(m,"shaping_startup_ms",c.shaping_startup_ms);
  c.shaping_delay_ms=ival(m,"shaping_delay_ms",c.shaping_delay_ms);
  c.shaping_rate_bytes=ival(m,"shaping_rate_bytes",c.shaping_rate_bytes);
  c.shaping_burst_bytes=ival(m,"shaping_burst_bytes",c.shaping_burst_bytes);
  c.websocket_control_padding_bytes=ival(m,"websocket_control_padding_bytes",0);
  c.padding_budget_pct=ival(m,"padding_budget_pct",10);
  c.latency_renew_ms=ival(m,"latency_renew_ms",600);
  c.latency_renew_samples=ival(m,"latency_renew_samples",3);
  c.latency_renew_cooldown_sec=ival(m,"latency_renew_cooldown_sec",180);
  c.idle_probe_sec=ival(m,"idle_probe_sec",20);
  c.reply_degraded_sec=ival(m,"reply_degraded_sec",10);
  c.reply_renew_sec=ival(m,"reply_renew_sec",30);
  c.reply_timeout_sec=ival(m,"reply_timeout_sec",60);
  c.candidate_max_rtt_ms=ival(m,"candidate_max_rtt_ms",1500);
  c.timing_jitter_pct=ival(m,"timing_jitter_pct",15);
  c.log_format=sval(m,"log_format","human");
  c.websocket_padding_max_bytes=ival(m,"websocket_padding_max_bytes",0);
  c.max_connections=ival(m,"max_connections",c.max_connections);
  c.pool_drain_sec=ival(m,"pool_drain_sec",c.pool_drain_sec);
  c.pool_idle_poll_ms=ival(m,"pool_idle_poll_ms",c.pool_idle_poll_ms);
  c.address_family=sval(m,"address_family",c.address_family);
  if(auto i=m.find("flow_scheduler");i!=m.end())c.flow_scheduler=bval(i->second);
  c.profile=sval(m,"profile",c.profile);c.resource_profile=sval(m,"resource_profile",c.resource_profile);apply_profile(c,c.profile);
  c.mode=sval(m,"mode");c.transport=sval(m,"transport",c.transport);c.listen=sval(m,"listen");c.server=sval(m,"server");c.server_name=sval(m,"server_name");c.path=sval(m,"path",c.path);c.host_header=sval(m,"host_header",c.host_header);c.tls_backend=sval(m,"tls_backend",c.tls_backend);c.tls_adapter_socket=sval(m,"tls_adapter_socket",c.tls_adapter_socket);if(auto i=m.find("edge_dns_rotation");i!=m.end())c.edge_dns_rotation=bval(i->second);if(auto i=m.find("websocket_tls");i!=m.end())c.websocket_tls=bval(i->second);c.websocket_ping_sec=ival(m,"websocket_ping_sec",c.websocket_ping_sec);c.websocket_pong_timeout_sec=ival(m,"websocket_pong_timeout_sec",c.websocket_pong_timeout_sec);c.websocket_poll_ms=ival(m,"websocket_poll_ms",c.websocket_poll_ms);c.websocket_upgrade_timeout_sec=ival(m,"websocket_upgrade_timeout_sec",c.websocket_upgrade_timeout_sec);c.websocket_io_timeout_sec=ival(m,"websocket_io_timeout_sec",c.websocket_io_timeout_sec);c.listen_backlog=ival(m,"listen_backlog",c.listen_backlog);c.session_max_age_sec=ival(m,"session_max_age_sec",c.session_max_age_sec);c.dev=sval(m,"dev",c.dev);c.cidr=sval(m,"cidr");c.peer_cidr=sval(m,"peer_cidr");c.mtu=ival(m,"mtu",c.mtu);c.tls_cert=sval(m,"tls_cert");c.tls_key=sval(m,"tls_key");c.tls_ca=sval(m,"tls_ca");if(auto i=m.find("verify_peer");i!=m.end())c.verify_peer=bval(i->second);c.psk_file=sval(m,"psk_file");c.psk_previous_file=sval(m,"psk_previous_file");
  c.max_record_buffer_bytes=zval(m,"max_record_buffer_bytes",c.max_record_buffer_bytes);if(auto i=m.find("control_mode");i!=m.end())c.control_mode=std::stoi(i->second,nullptr,8);c.queue_packets=zval(m,"queue_packets",c.queue_packets);c.queue_bytes=zval(m,"queue_bytes",c.queue_bytes);c.queue_delay_ms=ival(m,"queue_delay_ms",c.queue_delay_ms);c.batch_packets=ival(m,"batch_packets",c.batch_packets);c.batch_bytes=zval(m,"batch_bytes",c.batch_bytes);if(auto i=m.find("adaptive_batching");i!=m.end())c.adaptive_batching=bval(i->second);c.adaptive_batch_min_packets=ival(m,"adaptive_batch_min_packets",c.adaptive_batch_min_packets);c.adaptive_batch_max_packets=ival(m,"adaptive_batch_max_packets",c.adaptive_batch_max_packets);c.queue_target_delay_ms=ival(m,"queue_target_delay_ms",c.queue_target_delay_ms);c.connect_timeout_sec=ival(m,"connect_timeout_sec",c.connect_timeout_sec);c.idle_timeout_sec=ival(m,"idle_timeout_sec",c.idle_timeout_sec);c.keepalive_sec=ival(m,"keepalive_sec",c.keepalive_sec);c.rtt_probe_sec=ival(m,"rtt_probe_sec",c.rtt_probe_sec);c.reconnect_initial_ms=ival(m,"reconnect_initial_ms",c.reconnect_initial_ms);c.reconnect_max_ms=ival(m,"reconnect_max_ms",c.reconnect_max_ms);c.reconnect_jitter_pct=ival(m,"reconnect_jitter_pct",c.reconnect_jitter_pct);c.tcp_keepidle_sec=ival(m,"tcp_keepidle_sec",c.tcp_keepidle_sec);c.tcp_keepintvl_sec=ival(m,"tcp_keepintvl_sec",c.tcp_keepintvl_sec);c.tcp_keepcnt=ival(m,"tcp_keepcnt",c.tcp_keepcnt);c.tcp_user_timeout_ms=ival(m,"tcp_user_timeout_ms",c.tcp_user_timeout_ms);c.sndbuf=ival(m,"sndbuf",c.sndbuf);c.rcvbuf=ival(m,"rcvbuf",c.rcvbuf);c.stats_interval_sec=ival(m,"stats_interval_sec",c.stats_interval_sec);c.control_socket=sval(m,"control_socket");if(auto i=m.find("strict_file_permissions");i!=m.end())c.strict_file_permissions=bval(i->second);
  apply_resource_cap(c,c.resource_profile);
  static const std::vector<std::string>known={"browser_profile","traffic_shaping","shaping_startup_ms","shaping_delay_ms","shaping_rate_bytes","shaping_burst_bytes","pool_drain_sec","pool_idle_poll_ms","address_family","reply_degraded_sec","reply_renew_sec","reply_timeout_sec","candidate_max_rtt_ms","latency_renew_ms","latency_renew_samples","latency_renew_cooldown_sec","idle_probe_sec","websocket_control_padding_bytes","padding_budget_pct","timing_jitter_pct","log_format","websocket_padding_max_bytes","flow_scheduler","max_connections","mode","transport","listen","server","server_name","path","host_header","edge_dns_rotation","tls_backend","tls_adapter_socket","websocket_tls","websocket_ping_sec","websocket_pong_timeout_sec","websocket_poll_ms","websocket_upgrade_timeout_sec","websocket_io_timeout_sec","listen_backlog","session_max_age_sec","dev","cidr","peer_cidr","mtu","tls_cert","tls_key","tls_ca","verify_peer","psk_file","psk_previous_file","profile","resource_profile","max_record_buffer_bytes","control_mode","queue_packets","queue_bytes","queue_delay_ms","batch_packets","batch_bytes","adaptive_batching","adaptive_batch_min_packets","adaptive_batch_max_packets","queue_target_delay_ms","connect_timeout_sec","idle_timeout_sec","keepalive_sec","rtt_probe_sec","reconnect_initial_ms","reconnect_max_ms","reconnect_jitter_pct","tcp_keepidle_sec","tcp_keepintvl_sec","tcp_keepcnt","tcp_user_timeout_ms","sndbuf","rcvbuf","stats_interval_sec","control_socket","strict_file_permissions"};
  for (const auto& [key, value] : m) {
    (void)value;
    if (std::find(known.begin(), known.end(), key) == known.end()) {
      throw std::runtime_error("unknown config key: " + key);
    }
  }
  validate_config(c);
  return c;
}

void validate_config(const Config& c) {
  range("max_connections",c.max_connections,1,4);
  range("pool_drain_sec",c.pool_drain_sec,1,120);
  range("pool_idle_poll_ms",c.pool_idle_poll_ms,1,250);
  if(c.address_family!="auto" && c.address_family!="ipv4" && c.address_family!="ipv6")throw std::runtime_error("address_family must be auto, ipv4 or ipv6");
  if(c.max_connections>1 && c.transport!="websocket") throw std::runtime_error("max_connections requires websocket");
  if(c.max_connections>2 && c.resource_profile=="lowmem") throw std::runtime_error("lowmem limits max_connections to 2");
  range("websocket_control_padding_bytes",c.websocket_control_padding_bytes,0,1024);
  if(c.browser_profile!="none" && c.browser_profile!="firefox120" && c.browser_profile!="chrome120")throw std::runtime_error("invalid browser_profile");
  range("shaping_startup_ms",c.shaping_startup_ms,0,10000);
  range("shaping_delay_ms",c.shaping_delay_ms,0,10);
  range("shaping_rate_bytes",c.shaping_rate_bytes,0,65536);
  range("shaping_burst_bytes",c.shaping_burst_bytes,0,65536);
  if(c.traffic_shaping && (c.transport!="websocket" || c.websocket_padding_max_bytes==0 || c.websocket_control_padding_bytes==0))
    throw std::runtime_error("traffic_shaping requires websocket transport and nonzero data/control padding limits");
  range("padding_budget_pct",c.padding_budget_pct,0,50);
  range("latency_renew_ms",c.latency_renew_ms,0,60000);
  range("latency_renew_samples",c.latency_renew_samples,2,20);
  range("latency_renew_cooldown_sec",c.latency_renew_cooldown_sec,60,3600);
  range("idle_probe_sec",c.idle_probe_sec,0,300);
  range("reply_degraded_sec",c.reply_degraded_sec,2,60);
  range("reply_renew_sec",c.reply_renew_sec,5,120);
  range("reply_timeout_sec",c.reply_timeout_sec,10,300);
  range("candidate_max_rtt_ms",c.candidate_max_rtt_ms,100,5000);
  if(c.reply_degraded_sec>=c.reply_renew_sec || c.reply_renew_sec>=c.reply_timeout_sec)throw std::runtime_error("reply deadlines must increase: degraded < renew < timeout");
  range("timing_jitter_pct",c.timing_jitter_pct,0,30);
  if(c.log_format!="human"&&c.log_format!="legacy")throw std::runtime_error("log_format must be human or legacy");
  if(c.websocket_control_padding_bytes&&c.transport!="websocket")throw std::runtime_error("control padding requires websocket");
  if(c.websocket_control_padding_bytes&&c.batch_bytes<static_cast<size_t>(std::max(c.mtu+c.websocket_padding_max_bytes,8+c.websocket_control_padding_bytes)+35))throw std::runtime_error("batch_bytes too small for padded envelope");
  range("websocket_padding_max_bytes",c.websocket_padding_max_bytes,0,1024);
  if(c.websocket_padding_max_bytes && c.transport!="websocket") throw std::runtime_error("padding requires websocket transport");
  if (c.transport != "tls" && c.transport != "websocket") {
    throw std::runtime_error("transport must be tls or websocket");
  }
  if (c.mode != "server" && c.mode != "client") {
    throw std::runtime_error("mode must be server or client");
  }
  if (c.mode == "server" && c.listen.empty()) {
    throw std::runtime_error("listen is required in server mode");
  }
  if (c.mode == "client" && (c.server.empty() || c.server_name.empty())) {
    throw std::runtime_error("server and server_name are required in client mode");
  }
  if (c.mode == "server" && c.server_name.empty()) {
    throw std::runtime_error("server_name is required in server mode");
  }
  validate_http_field("server_name",c.server_name,255);
  validate_http_field("host_header",c.host_header,255,true);
  if(c.mode=="server")validate_endpoint("listen",c.listen);
  else validate_endpoint("server",c.server);
  if (c.path.empty() || c.path.front() != '/') {
    throw std::runtime_error("path must start with /");
  }
  validate_http_field("path",c.path,2048);
  if (c.dev.empty() || c.dev.size() > 15) {
    throw std::runtime_error("dev must contain 1..15 characters");
  }
  if (c.cidr.empty() || c.peer_cidr.empty()) {
    throw std::runtime_error("cidr and peer_cidr are required");
  }
  if (c.mode == "server" && c.transport == "tls" && (c.tls_cert.empty() || c.tls_key.empty())) {
    throw std::runtime_error("tls_cert and tls_key are required in server mode");
  }
  if(c.tls_backend!="openssl" && c.tls_backend!="utls") throw std::runtime_error("tls_backend must be openssl or utls");
  if(c.tls_backend=="utls") {
    if(c.mode!="client" || c.transport!="websocket" || !c.websocket_tls || !c.verify_peer)
      throw std::runtime_error("uTLS adapter requires authenticated HTTPS WebSocket client");
    if(c.edge_dns_rotation) throw std::runtime_error("disable edge_dns_rotation with uTLS: adapter performs DNS resolution");
    if(c.tls_adapter_socket.empty() || c.tls_adapter_socket.front()!='/' || c.tls_adapter_socket.size()>=100 ||
       c.tls_adapter_socket.find("..")!=std::string::npos)
      throw std::runtime_error("tls_adapter_socket must be a short absolute path without ..");
  }
  if(c.edge_dns_rotation && (c.mode!="client" || c.transport!="websocket")) throw std::runtime_error("edge_dns_rotation requires websocket client");
  if(c.mode=="client" && c.transport=="websocket" && (!c.websocket_tls||!c.verify_peer)) throw std::runtime_error("WSS requires websocket_tls=1 and verify_peer=1");
  const bool client_uses_tls = c.mode == "client" && (c.transport != "websocket" || c.websocket_tls);
  if (client_uses_tls && c.verify_peer && c.tls_ca.empty()) {
    throw std::runtime_error("tls_ca is required when verify_peer=1");
  }
  if (c.psk_file.empty()) {
    throw std::runtime_error("psk_file is required");
  }
  if (c.profile != "balanced" && c.profile != "lightning" &&
      c.profile != "bulk" && c.profile != "ultra") {
    throw std::runtime_error("profile must be balanced, lightning, bulk, or ultra");
  }
  if (c.resource_profile != "normal" && c.resource_profile != "lowmem") {
    throw std::runtime_error("resource_profile must be normal or lowmem");
  }

  range("mtu", c.mtu, 576, 9000);
  range("websocket_ping_sec", c.websocket_ping_sec, 0, 300);
  range("websocket_pong_timeout_sec", c.websocket_pong_timeout_sec, 0, 120);
  range("websocket_poll_ms", c.websocket_poll_ms, 1, 100);
  range("websocket_upgrade_timeout_sec", c.websocket_upgrade_timeout_sec, 1, 120);
  range("websocket_io_timeout_sec", c.websocket_io_timeout_sec, 1, 300);
  range("listen_backlog", c.listen_backlog, 16, 4096);
  range("session_max_age_sec", c.session_max_age_sec, 0, 604800);














  range("max_record_buffer_bytes", c.max_record_buffer_bytes, 65536, 16777216);
  range("control_mode", c.control_mode, 0, 0777);
  range("queue_packets", c.queue_packets, 16, 1000000);
  range("queue_bytes", c.queue_bytes, 65536, 1LL << 31);
  range("queue_delay_ms", c.queue_delay_ms, 10, 60000);
  range("batch_packets", c.batch_packets, 1, 256);
  range("batch_bytes", c.batch_bytes, 1024, 4 * 1024 * 1024);
  if (c.transport == "websocket" && c.batch_bytes < static_cast<std::size_t>(c.mtu + 32 + (c.websocket_padding_max_bytes ? 2+c.websocket_padding_max_bytes : 0))) {
    throw std::runtime_error("batch_bytes must be at least mtu + 32 (plus 2 + websocket_padding_max_bytes when padding is enabled) for PTT5 WebSocket records");
  }
  range("adaptive_batch_min_packets", c.adaptive_batch_min_packets, 1, 256);
  range("adaptive_batch_max_packets", c.adaptive_batch_max_packets, c.adaptive_batch_min_packets, 256);
  range("queue_target_delay_ms", c.queue_target_delay_ms, 1, 60000);
  if(c.transport=="websocket"&&c.adaptive_batching&&c.queue_target_delay_ms>c.queue_delay_ms)
    throw std::runtime_error("queue_target_delay_ms must not exceed queue_delay_ms for adaptive WebSocket batching");
  range("connect_timeout_sec", c.connect_timeout_sec, 1, 300);
  range("idle_timeout_sec", c.idle_timeout_sec, 5, 3600);
  range("keepalive_sec", c.keepalive_sec, 0, 300);
  range("rtt_probe_sec", c.rtt_probe_sec, 0, 300);
  range("reconnect_initial_ms", c.reconnect_initial_ms, 100, 60000);
  range("reconnect_max_ms", c.reconnect_max_ms, c.reconnect_initial_ms, 600000);
  range("reconnect_jitter_pct", c.reconnect_jitter_pct, 0, 50);
  range("tcp_keepidle_sec", c.tcp_keepidle_sec, 1, 3600);
  range("tcp_keepintvl_sec", c.tcp_keepintvl_sec, 1, 300);
  range("tcp_keepcnt", c.tcp_keepcnt, 1, 20);
  range("tcp_user_timeout_ms", c.tcp_user_timeout_ms, 1000, 600000);
  range("sndbuf", c.sndbuf, 65536, 1LL << 30);
  range("rcvbuf", c.rcvbuf, 65536, 1LL << 30);
  range("stats_interval_sec", c.stats_interval_sec, 1, 300);
  if (c.control_socket.empty()) {
    throw std::runtime_error("control_socket is required");
  }
  if (c.control_socket.size() >= 100) {
    throw std::runtime_error("control_socket path is too long");
  }
}

std::string effective_config(const Config&c){std::ostringstream o;o<<"browser_profile="<<c.browser_profile<<"\n";o<<"traffic_shaping="<<c.traffic_shaping<<"\nshaping_startup_ms="<<c.shaping_startup_ms<<"\nshaping_delay_ms="<<c.shaping_delay_ms<<"\nshaping_rate_bytes="<<c.shaping_rate_bytes<<"\nshaping_burst_bytes="<<c.shaping_burst_bytes<<"\n";o<<"pool_drain_sec="<<c.pool_drain_sec<<"\npool_idle_poll_ms="<<c.pool_idle_poll_ms<<"\naddress_family="<<c.address_family<<"\n";o<<"reply_degraded_sec="<<c.reply_degraded_sec<<"\nreply_renew_sec="<<c.reply_renew_sec<<"\nreply_timeout_sec="<<c.reply_timeout_sec<<"\ncandidate_max_rtt_ms="<<c.candidate_max_rtt_ms<<'\n';o<<"latency_renew_ms="<<c.latency_renew_ms<<'\n';o<<"latency_renew_samples="<<c.latency_renew_samples<<'\n';o<<"latency_renew_cooldown_sec="<<c.latency_renew_cooldown_sec<<'\n';o<<"idle_probe_sec="<<c.idle_probe_sec<<'\n';o<<"websocket_control_padding_bytes="<<c.websocket_control_padding_bytes<<"\npadding_budget_pct="<<c.padding_budget_pct<<"\ntiming_jitter_pct="<<c.timing_jitter_pct<<"\nlog_format="<<c.log_format<<'\n';o<<"websocket_padding_max_bytes="<<c.websocket_padding_max_bytes<<'\n';o<<"flow_scheduler="<<(c.flow_scheduler?1:0)<<'\n';o<<"mode="<<c.mode<<'\n'<<"transport="<<c.transport<<'\n';if(c.mode=="server")o<<"listen="<<c.listen<<'\n';else o<<"server="<<c.server<<"\nserver_name="<<c.server_name<<'\n';o<<"path="<<c.path<<"\nhost_header="<<c.host_header<<"\ntls_backend="<<c.tls_backend<<"\ntls_adapter_socket="<<c.tls_adapter_socket<<"\nmax_connections="<<c.max_connections<<"\nedge_dns_rotation="<<(c.edge_dns_rotation?1:0)<<"\nwebsocket_tls="<<(c.websocket_tls?1:0)<<"\nwebsocket_ping_sec="<<c.websocket_ping_sec<<"\nwebsocket_pong_timeout_sec="<<c.websocket_pong_timeout_sec<<"\nwebsocket_poll_ms="<<c.websocket_poll_ms<<"\nwebsocket_upgrade_timeout_sec="<<c.websocket_upgrade_timeout_sec<<"\nwebsocket_io_timeout_sec="<<c.websocket_io_timeout_sec<<"\nlisten_backlog="<<c.listen_backlog<<"\nsession_max_age_sec="<<c.session_max_age_sec<<"\ndev="<<c.dev<<"\ncidr="<<c.cidr<<"\npeer_cidr="<<c.peer_cidr<<"\nmtu="<<c.mtu<<'\n';if(c.mode=="server")o<<"tls_cert="<<c.tls_cert<<"\ntls_key="<<c.tls_key<<'\n';else o<<"tls_ca="<<c.tls_ca<<"\nverify_peer="<<(c.verify_peer?1:0)<<'\n';o<<"psk_file="<<c.psk_file<<"\npsk_previous_file="<<c.psk_previous_file<<"\nprofile="<<c.profile<<"\nresource_profile="<<c.resource_profile<<"\nmax_record_buffer_bytes="<<c.max_record_buffer_bytes<<"\ncontrol_mode="<<std::oct<<c.control_mode<<std::dec<<"\nqueue_packets="<<c.queue_packets<<"\nqueue_bytes="<<c.queue_bytes<<"\nqueue_delay_ms="<<c.queue_delay_ms<<"\nbatch_packets="<<c.batch_packets<<"\nbatch_bytes="<<c.batch_bytes<<"\nadaptive_batching="<<(c.adaptive_batching?1:0)<<"\nadaptive_batch_min_packets="<<c.adaptive_batch_min_packets<<"\nadaptive_batch_max_packets="<<c.adaptive_batch_max_packets<<"\nqueue_target_delay_ms="<<c.queue_target_delay_ms<<"\nconnect_timeout_sec="<<c.connect_timeout_sec<<"\nidle_timeout_sec="<<c.idle_timeout_sec<<"\nkeepalive_sec="<<c.keepalive_sec<<"\nrtt_probe_sec="<<c.rtt_probe_sec<<"\nreconnect_initial_ms="<<c.reconnect_initial_ms<<"\nreconnect_max_ms="<<c.reconnect_max_ms<<"\nreconnect_jitter_pct="<<c.reconnect_jitter_pct<<"\ntcp_keepidle_sec="<<c.tcp_keepidle_sec<<"\ntcp_keepintvl_sec="<<c.tcp_keepintvl_sec<<"\ntcp_keepcnt="<<c.tcp_keepcnt<<"\ntcp_user_timeout_ms="<<c.tcp_user_timeout_ms<<"\nsndbuf="<<c.sndbuf<<"\nrcvbuf="<<c.rcvbuf<<"\nstats_interval_sec="<<c.stats_interval_sec<<"\ncontrol_socket="<<c.control_socket<<'\n';return o.str();}
}
