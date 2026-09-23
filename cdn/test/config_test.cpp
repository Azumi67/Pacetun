#include "pacetun/config.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
std::filesystem::path write_cfg(const std::string& name,const std::string& extra,
                                const std::string& transport="websocket",
                                const std::string& listen="127.0.0.1:9443"){
  auto p=std::filesystem::temp_directory_path()/name;
  std::ofstream o(p);
  o<<"mode=server\ntransport="<<transport<<"\nlisten="<<listen
   <<"\nserver_name=example.test\npath=/ws\n"
   <<"dev=pttest0\ncidr=10.34.0.1/30\npeer_cidr=10.34.0.2/30\n"
   <<"psk_file=/tmp/nonexistent-test-psk\ncontrol_socket=/tmp/pacetun-config-test.sock\n"
   <<extra;
  return p;
}
void must_load(const std::filesystem::path&p){
  (void)pacetun::load_config(p.string());
  std::filesystem::remove(p);
}
void must_reject(const std::filesystem::path&p,const std::string&needle){
  bool rejected=false;
  try{(void)pacetun::load_config(p.string());}
  catch(const std::exception&e){rejected=std::string(e.what()).find(needle)!=std::string::npos;}
  std::filesystem::remove(p);
  if(!rejected)throw std::runtime_error("expected config rejection containing: "+needle);
}
std::filesystem::path write_client_cfg(const std::string& name,bool ws_tls,bool verify_peer){
  auto p=std::filesystem::temp_directory_path()/name;
  std::ofstream o(p);
  o<<"mode=client\n"
   <<"transport=websocket\n"
   <<"websocket_tls="<<(ws_tls?1:0)<<"\n"
   <<"server=example.test:"<<(ws_tls?443:80)<<"\n"
   <<"server_name=example.test\n"
   <<"host_header=example.test\n"
   <<"path=/ws\n"
   <<"dev=pttest0\n"
   <<"cidr=10.34.0.2/30\n"
   <<"peer_cidr=10.34.0.1/30\n"
   <<"verify_peer="<<(verify_peer?1:0)<<"\n";
  if(ws_tls&&verify_peer)o<<"tls_ca=/etc/ssl/certs/ca-certificates.crt\n";
  o<<"psk_file=/tmp/nonexistent-test-psk\n"
   <<"control_socket=/tmp/pacetun-config-test.sock\n";
  return p;
}
}

int main(){
  try{
    must_reject(write_cfg("bad-reply-order.conf","reply_degraded_sec=30\nreply_renew_sec=20\n"),"reply deadlines must increase");
    must_reject(write_cfg("bad-candidate.conf","candidate_max_rtt_ms=0\n"),"candidate_max_rtt_ms out of range");
    must_load(write_cfg("pacetun-lightning.conf","profile=lightning\n"));
    must_load(write_cfg("flow-on.conf","flow_scheduler=1\n"));
    must_load(write_cfg("pool-two.conf","max_connections=2\n"));
    must_reject(write_cfg("pool-zero.conf","max_connections=0\n"),"max_connections out of range");
    must_reject(write_cfg("pool-five.conf","max_connections=5\n"),"max_connections out of range");
    must_reject(write_cfg("pool-tls.conf","max_connections=2\n","tls"),"max_connections requires websocket");
    must_reject(write_cfg("pool-memory.conf","max_connections=3\nresource_profile=lowmem\n"),"lowmem limits max_connections");
    must_load(write_cfg("pool-padding.conf","max_connections=2\nwebsocket_padding_max_bytes=8\n"));
    must_load(write_cfg("pool-control-padding.conf","max_connections=2\nwebsocket_control_padding_bytes=8\n"));
    must_reject(write_cfg("flow-bad.conf","flow_scheduler=maybe\n"),"invalid boolean");
    must_load(write_cfg("pacetun-ultra.conf","profile=ultra\n"));
    must_load(write_cfg("pacetun-ipv6.conf","","websocket","[::1]:9443"));
    must_reject(write_cfg("pacetun-bad-ipv6.conf","","websocket","::1:9443"),"IPv6 requires brackets");
    must_reject(write_cfg("pacetun-bad-port.conf","","websocket","127.0.0.1:70000"),"port out of range");
    must_reject(write_cfg("pacetun-small-batch.conf","mtu=1280\nbatch_bytes=1024\n"),"batch_bytes must be at least mtu + 32");
    must_reject(write_cfg("pacetun-target.conf","queue_delay_ms=25\nqueue_target_delay_ms=40\n"),"queue_target_delay_ms must not exceed");
    must_reject(write_cfg("pacetun-small-backlog.conf","listen_backlog=8\n"),"listen_backlog out of range");
    {
      auto p=std::filesystem::temp_directory_path()/"pacetun-v41-bad-path.conf";
      std::ofstream o(p);
      o<<"mode=server\ntransport=websocket\nlisten=127.0.0.1:9443\nserver_name=example.test\npath=/ok bad\n"
       <<"dev=pttest0\ncidr=10.34.0.1/30\npeer_cidr=10.34.0.2/30\n"
       <<"psk_file=/tmp/nonexistent-test-psk\ncontrol_socket=/tmp/pacetun-config-test.sock\n";
      o.close();
      must_reject(p,"path contains whitespace/control characters");
    }

    auto h2=write_cfg("pacetun-h2-compat.conf","queue_delay_ms=20\n","http2");
    must_reject(h2,"transport must be tls or websocket");
    must_reject(write_cfg("pacetun-unknown.conf","not_a_real_option=1\n"),"unknown config key");
    must_reject(write_client_cfg("pacetun-ws80-client.conf",false,false),"WSS requires");
    must_reject(write_client_cfg("pacetun-ws80-bad-verify.conf",false,true),"WSS requires");
    must_load(write_client_cfg("pacetun-wss-client.conf",true,true));
    must_reject(write_cfg("rotation-server.conf","edge_dns_rotation=1\n"),"edge_dns_rotation requires websocket client");
    {
      auto path=write_client_cfg("rotation-client.conf",true,true);
      std::ofstream out(path,std::ios::app);out<<"edge_dns_rotation=1\n";out.close();
      auto rotation=pacetun::load_config(path.string());
      std::filesystem::remove(path);
      if(!rotation.edge_dns_rotation)throw std::runtime_error("client DNS rotation not loaded");
    }


    must_reject(write_cfg("pool-disabled.conf","ws_domains=example.test,backup.example.test\n"),"unknown config key");
    must_reject(write_cfg("h2-config-disabled.conf","http_upload_parallel=2\n"),"unknown config key");
    must_reject(write_cfg("utls-server.conf","tls_backend=utls\n"),"uTLS adapter requires");
    {
      auto path=write_client_cfg("utls-client.conf",true,true);
      std::ofstream out(path,std::ios::app);out<<"tls_backend=utls\n";out.close();
      auto got=pacetun::load_config(path.string());
      std::filesystem::remove(path);
      if(got.tls_backend!="utls")throw std::runtime_error("uTLS selection not loaded");
    }
    {
      auto path=write_client_cfg("utls-rotation-invalid.conf",true,true);
      std::ofstream out(path,std::ios::app);out<<"tls_backend=utls\nedge_dns_rotation=1\n";out.close();
      must_reject(path,"disable edge_dns_rotation");
    }
    {
      auto path=write_client_cfg("utls-socket-invalid.conf",true,true);
      std::ofstream out(path,std::ios::app);out<<"tls_backend=utls\ntls_adapter_socket=relative.sock\n";out.close();
      must_reject(path,"tls_adapter_socket must be");
    }
    must_reject(write_client_cfg("wss-noverify.conf",true,false),"WSS requires");

    std::cout<<"PaceTun config self-test OK\n";
    return 0;
  }catch(const std::exception&e){
    std::cerr<<"config self-test failed: "<<e.what()<<"\n";
    return 1;
  }
}
