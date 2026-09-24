#include "pacetun/websocket.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
using Clock=std::chrono::steady_clock;

void set_nonblock(int fd){
  const int f=fcntl(fd,F_GETFL,0);
  if(f<0||fcntl(fd,F_SETFL,f|O_NONBLOCK)<0)throw std::runtime_error("fcntl failed");
}

void pump_tx(pacetun::WsSession&ws,int timeout_ms=2000){
  const auto deadline=Clock::now()+std::chrono::milliseconds(timeout_ms);
  while(pacetun::websocket_tx_pending(ws)){
    pacetun::websocket_flush(ws,64*1024);
    if(!pacetun::websocket_tx_pending(ws))break;
    if(Clock::now()>=deadline)throw std::runtime_error("TX pump timeout");
    pollfd p{ws.fd,static_cast<short>(POLLIN|POLLOUT),0};
    poll(&p,1,10);
  }
}

std::vector<unsigned char> raw_frame(uint8_t opcode,bool fin,std::span<const unsigned char>payload,bool masked){
  if(payload.size()>125)throw std::runtime_error("raw test helper supports <=125 byte payloads");
  std::vector<unsigned char>f;
  f.push_back(static_cast<unsigned char>((fin?0x80:0)|opcode));
  f.push_back(static_cast<unsigned char>((masked?0x80:0)|payload.size()));
  const std::array<unsigned char,4>mk{0x11,0x22,0x33,0x44};
  if(masked)f.insert(f.end(),mk.begin(),mk.end());
  for(std::size_t i=0;i<payload.size();++i)f.push_back(static_cast<unsigned char>(payload[i]^(masked?mk[i%4]:0)));
  return f;
}

void write_all_fd(int fd,std::span<const unsigned char>d){
  std::size_t off=0;
  while(off<d.size()){
    auto n=send(fd,d.data()+off,d.size()-off,MSG_NOSIGNAL);
    if(n>0){off+=static_cast<std::size_t>(n);continue;}
    if(n<0&&errno==EINTR)continue;
    throw std::runtime_error("raw write failed");
  }
}

std::string test_header(const std::string&s,const std::string&name){
  const std::string needle="\r\n"+name+":";
  auto p=s.find(needle);if(p==std::string::npos)return{};p+=needle.size();
  while(p<s.size()&&(s[p]==' '||s[p]=='\t'))++p;
  auto e=s.find("\r\n",p);return s.substr(p,e-p);
}
std::string test_ws_accept(const std::string&key){
  const std::string in=key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::array<unsigned char,SHA_DIGEST_LENGTH>d{};
  if(!SHA1(reinterpret_cast<const unsigned char*>(in.data()),in.size(),d.data()))throw std::runtime_error("SHA1 failed");
  std::string out(4*((d.size()+2)/3),'\0');
  const int n=EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),d.data(),static_cast<int>(d.size()));
  if(n<0)throw std::runtime_error("base64 failed");
  out.resize(static_cast<std::size_t>(n));return out;
}
std::string read_http_headers_fd(int fd){
  std::string s;char b[2048];
  while(s.find("\r\n\r\n")==std::string::npos){auto n=recv(fd,b,sizeof(b),0);if(n>0){s.append(b,static_cast<std::size_t>(n));if(s.size()>32768)throw std::runtime_error("test headers too large");continue;}if(n<0&&errno==EINTR)continue;throw std::runtime_error("test header read failed");}
  return s;
}

void test_ptt5_crypto(){
  std::vector<unsigned char>psk(32);
  for(std::size_t i=0;i<psk.size();++i)psk[i]=static_cast<unsigned char>(0xa0+i);
  bool malformed_hex_rejected=false;
  try{(void)pacetun::key32_from_hex(std::string(62,'0')+"0g");}
  catch(const std::exception&){malformed_hex_rejected=true;}
  if(!malformed_hex_rejected)throw std::runtime_error("malformed PTT5 key hex accepted");

  auto client=pacetun::generate_x25519_keypair();
  auto server=pacetun::generate_x25519_keypair();
  auto cs=pacetun::x25519_shared_secret(client.private_key,server.public_key);
  auto sc=pacetun::x25519_shared_secret(server.private_key,client.public_key);
  if(cs!=sc)throw std::runtime_error("X25519 shared secret mismatch");
  auto cn=pacetun::random_nonce_hex(),sn=pacetun::random_nonce_hex();
  auto ck=pacetun::derive_session_keys_v5(psk,cs,sn,cn,client.public_key,server.public_key);
  auto sk=pacetun::derive_session_keys_v5(psk,sc,sn,cn,client.public_key,server.public_key);
  if(ck.client_tx!=sk.client_tx||ck.server_tx!=sk.server_tx||ck.auth!=sk.auth)throw std::runtime_error("PTT5 KDF mismatch");

  const std::array<unsigned char,20>payload{0x45,0,0,20,0,0,0,0,64,1,0,0,10,0,0,1,10,0,0,2};
  auto record=pacetun::encode_record_v5(ck.client_tx,1,payload);
  pacetun::RecordDecoderV5 dec(sk.client_tx,65536);
  bool delivered=false;std::string error;
  if(!dec.feed(record,[&](uint8_t flags,uint64_t seq,std::span<const unsigned char>p){
    if(flags!=0||seq!=1||!std::equal(p.begin(),p.end(),payload.begin(),payload.end()))throw std::runtime_error("PTT5 decoded payload mismatch");
    delivered=true;
  },error)||!delivered)throw std::runtime_error("PTT5 decode failed: "+error);
  std::string replay_error;
  if(dec.feed(record,[](uint8_t,uint64_t,std::span<const unsigned char>){},replay_error))throw std::runtime_error("replayed PTT5 record accepted");
  if(replay_error.find("replay")==std::string::npos)throw std::runtime_error("replay returned wrong error");

  auto tampered=pacetun::encode_record_v5(ck.client_tx,2,payload);
  tampered.back()^=0x01;
  pacetun::RecordDecoderV5 bad(sk.client_tx,65536);std::string bad_error;
  if(bad.feed(tampered,[](uint8_t,uint64_t,std::span<const unsigned char>){},bad_error))throw std::runtime_error("tampered PTT5 record accepted");
  if(bad_error.find("authentication")==std::string::npos)throw std::runtime_error("tampered PTT5 record returned wrong error");

  const std::array<unsigned char,8>control{0,1,2,3,4,5,6,7};
  bool mixed_rejected=false;
  try{(void)pacetun::encode_record_v5(ck.client_tx,3,control,pacetun::RECORD_PING|pacetun::RECORD_PONG);}
  catch(const std::exception&){mixed_rejected=true;}
  if(!mixed_rejected)throw std::runtime_error("ambiguous PTT5 control flags accepted");
}

void test_upgrade_binary_and_ping(){
  int fds[2] = {-1,-1};
  if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)!=0)throw std::runtime_error("socketpair failed");
  std::vector<unsigned char>psk(32);
  for(std::size_t i=0;i<psk.size();++i)psk[i]=static_cast<unsigned char>(i+1);
  std::vector<std::vector<unsigned char>>psks{psk};
  std::exception_ptr server_error;
  pacetun::WsHandshakeResult server_hs,client_hs;

  std::thread server([&]{
    try{
      pacetun::WsSession ws;ws.fd=fds[0];ws.client=false;ws.io_timeout_ms=2000;
      server_hs=pacetun::websocket_server_upgrade(ws,"example.test","/ws",psks,2000);
      if(server_hs.psk_index!=0)throw std::runtime_error("wrong PSK index");
      std::vector<std::vector<unsigned char>>msgs;
      for(int i=0;i<100&&msgs.empty();++i){
        auto got=pacetun::websocket_read_messages(ws,20);
        msgs.insert(msgs.end(),std::make_move_iterator(got.begin()),std::make_move_iterator(got.end()));
        pump_tx(ws);
      }
      if(msgs.size()!=1||std::string(msgs[0].begin(),msgs[0].end())!="hello")throw std::runtime_error("server payload mismatch");
      const std::array<unsigned char,5>reply{'w','o','r','l','d'};
      pacetun::websocket_send_binary(ws,reply);
      pump_tx(ws);
      pacetun::websocket_close(ws);
    }catch(...){server_error=std::current_exception();}
  });

  int rc=0;
  try{
    pacetun::WsSession ws;ws.fd=fds[1];ws.client=true;ws.io_timeout_ms=2000;
    client_hs=pacetun::websocket_client_upgrade(ws,"example.test","/ws",psk,2000);
    const std::array<unsigned char,8>ping{0,1,2,3,4,5,6,7};
    pacetun::websocket_send_ping(ws,ping);
    const std::array<unsigned char,5>msg{'h','e','l','l','o'};
    pacetun::websocket_send_binary(ws,msg);
    pump_tx(ws);

    std::vector<std::vector<unsigned char>>replies;
    std::vector<std::vector<unsigned char>>pongs;
    for(int i=0;i<100&&(replies.empty()||pongs.empty());++i){
      auto got=pacetun::websocket_read_messages(ws,20);
      replies.insert(replies.end(),std::make_move_iterator(got.begin()),std::make_move_iterator(got.end()));
      auto pg=pacetun::websocket_take_pongs(ws);
      pongs.insert(pongs.end(),std::make_move_iterator(pg.begin()),std::make_move_iterator(pg.end()));
    }
    if(replies.size()!=1||std::string(replies[0].begin(),replies[0].end())!="world")throw std::runtime_error("client payload mismatch");
    if(pongs.size()!=1||!std::equal(pongs[0].begin(),pongs[0].end(),ping.begin(),ping.end()))throw std::runtime_error("PONG correlation mismatch");
    pacetun::websocket_close(ws);
  }catch(const std::exception&e){std::cerr<<"upgrade/binary/ping test failed: "<<e.what()<<"\n";rc=1;}
  server.join();
  if(server_error){try{std::rethrow_exception(server_error);}catch(const std::exception&e){std::cerr<<"server test failed: "<<e.what()<<"\n";}rc=1;}
  if(!rc&&(client_hs.keys.client_tx!=server_hs.keys.client_tx||client_hs.keys.server_tx!=server_hs.keys.server_tx)){
    std::cerr<<"PTT5 handshake key agreement mismatch\n";rc=1;
  }
  if(!client_hs.peer_padding || !server_hs.peer_padding) throw std::runtime_error("padding capability missing");
  if(rc)throw std::runtime_error("upgrade/binary/ping test failed");
}

void test_client_rejects_bad_server_proof(){
  int fds[2]={-1,-1};
  if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)!=0)throw std::runtime_error("socketpair failed");
  std::vector<unsigned char>psk(32,0x55);bool client_rejected=false;std::exception_ptr server_error;
  std::thread server([&]{
    try{
      const auto req=read_http_headers_fd(fds[0]);
      const auto key=test_header(req,"Sec-WebSocket-Key");
      if(req.find("X-PaceTun-")!=std::string::npos||req.find("Authorization:")!=std::string::npos||
         req.find("Sec-WebSocket-Protocol:")!=std::string::npos||req.find("User-Agent:")!=std::string::npos)
        throw std::runtime_error("identifying metadata leaked into HTTP request");
      const std::string resp="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+test_ws_accept(key)+"\r\n\r\n";
      write_all_fd(fds[0],{reinterpret_cast<const unsigned char*>(resp.data()),resp.size()});
      pacetun::WsSession server_ws;server_ws.fd=fds[0];server_ws.client=false;
      auto hello=pacetun::websocket_read_messages(server_ws,1000);
      if(hello.size()!=1||hello.front().size()!=199)throw std::runtime_error("post-upgrade client hello missing");
      const auto server_key=pacetun::generate_x25519_keypair();
      const std::string forged="PTT6-S:"+std::string(64,'a')+pacetun::key32_hex(server_key.public_key)+std::string(64,'0');
      pacetun::websocket_send_binary(server_ws,{reinterpret_cast<const unsigned char*>(forged.data()),forged.size()});
      pump_tx(server_ws);
    }catch(...){server_error=std::current_exception();}
    close(fds[0]);
  });
  pacetun::WsSession ws;ws.fd=fds[1];ws.client=true;ws.io_timeout_ms=1000;
  try{(void)pacetun::websocket_client_upgrade(ws,"example.test","/ws",psk,1000);}
  catch(const std::exception&e){client_rejected=std::string(e.what()).find("server authentication failed")!=std::string::npos;}
  pacetun::websocket_close(ws);server.join();
  if(server_error)std::rethrow_exception(server_error);
  if(!client_rejected)throw std::runtime_error("forged PTT5 server proof was accepted or returned wrong error");
}

void test_handshake_rejects_wrong_psk(){
  int fds[2]={-1,-1};
  if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)!=0)throw std::runtime_error("socketpair failed");
  std::vector<unsigned char>server_psk(32,0x31),client_psk(32,0x42);
  std::vector<std::vector<unsigned char>>psks{server_psk};
  bool server_rejected=false,client_rejected=false;
  std::thread server([&]{
    pacetun::WsSession ws;ws.fd=fds[0];ws.client=false;ws.io_timeout_ms=1000;
    try{(void)pacetun::websocket_server_upgrade(ws,"example.test","/ws",psks,1000);}
    catch(...){server_rejected=true;}
    pacetun::websocket_close(ws);
  });
  pacetun::WsSession ws;ws.fd=fds[1];ws.client=true;ws.io_timeout_ms=1000;
  try{(void)pacetun::websocket_client_upgrade(ws,"example.test","/ws",client_psk,1000);}
  catch(...){client_rejected=true;}
  pacetun::websocket_close(ws);server.join();
  if(!server_rejected||!client_rejected)throw std::runtime_error("wrong-PSK handshake was not rejected by both peers");
}

void test_fragment_reassembly(){
  int fds[2]={-1,-1};
  if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)!=0)throw std::runtime_error("socketpair failed");
  pacetun::WsSession server;server.fd=fds[0];server.client=false;
  const std::array<unsigned char,3>a{'a','b','c'};
  const std::array<unsigned char,3>b{'d','e','f'};
  auto f1=raw_frame(2,false,a,true);
  auto f2=raw_frame(0,true,b,true);
  write_all_fd(fds[1],f1);write_all_fd(fds[1],f2);
  std::vector<std::vector<unsigned char>>msgs;
  for(int i=0;i<20&&msgs.empty();++i){auto got=pacetun::websocket_read_messages(server,20);msgs.insert(msgs.end(),std::make_move_iterator(got.begin()),std::make_move_iterator(got.end()));}
  if(msgs.size()!=1||std::string(msgs[0].begin(),msgs[0].end())!="abcdef")throw std::runtime_error("fragment reassembly mismatch");
  close(fds[0]);close(fds[1]);
}

void test_rejects_oversize_frame(){
  int fds[2]={-1,-1};
  if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)!=0)throw std::runtime_error("socketpair failed");
  pacetun::WsSession server;server.fd=fds[0];server.client=false;
  const uint64_t declared=(16ULL*1024ULL*1024ULL)+1ULL;
  std::vector<unsigned char> hdr{0x82,0xff}; // FIN+binary, masked, 64-bit length
  for(int i=7;i>=0;--i)hdr.push_back(static_cast<unsigned char>((declared>>(8*i))&0xff));
  hdr.insert(hdr.end(),{0x11,0x22,0x33,0x44});
  write_all_fd(fds[1],hdr);
  bool rejected=false;
  try{(void)pacetun::websocket_read_messages(server,100);}
  catch(const std::exception&e){rejected=std::string(e.what()).find("frame too large")!=std::string::npos;}
  close(fds[0]);close(fds[1]);
  if(!rejected)throw std::runtime_error("oversize WebSocket frame was not rejected");
}

void test_nonblocking_partial_tx(){
  int fds[2]={-1,-1};
  if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)!=0)throw std::runtime_error("socketpair failed");
  int small=4096;setsockopt(fds[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small));
  set_nonblock(fds[0]);set_nonblock(fds[1]);
  pacetun::WsSession client;client.fd=fds[0];client.client=true;
  pacetun::WsSession server;server.fd=fds[1];server.client=false;server.authenticated=true;
  std::vector<unsigned char>payload(1024*1024);
  for(std::size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i&0xff);
  pacetun::websocket_send_binary(client,payload);
  const auto start=Clock::now();
  pacetun::websocket_flush(client,256*1024);
  const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count();
  if(elapsed>250)throw std::runtime_error("nonblocking flush took too long");
  if(!pacetun::websocket_tx_pending(client))throw std::runtime_error("partial TX test did not create backpressure");

  std::vector<std::vector<unsigned char>>msgs;
  const auto deadline=Clock::now()+std::chrono::seconds(5);
  while((pacetun::websocket_tx_pending(client)||msgs.empty())&&Clock::now()<deadline){
    pacetun::websocket_flush(client,64*1024);
    auto got=pacetun::websocket_read_messages(server,0);
    msgs.insert(msgs.end(),std::make_move_iterator(got.begin()),std::make_move_iterator(got.end()));
    if(msgs.empty())std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  if(pacetun::websocket_tx_pending(client))throw std::runtime_error("partial TX did not drain");
  if(msgs.size()!=1||msgs[0]!=payload)throw std::runtime_error("partial TX payload mismatch");
  if(client.tx_binary_frames!=1||client.tx_binary_payload_bytes!=payload.size())throw std::runtime_error("TX completion accounting mismatch");
  close(fds[0]);close(fds[1]);
}

void test_close_diagnostics(){
  const auto check=[](std::span<const unsigned char> payload, bool valid,
                      std::string expected, uint16_t code=0){
    int fds[2]={-1,-1};
    if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)!=0)throw std::runtime_error("socketpair failed");
    pacetun::WsSession client;client.fd=fds[0];client.client=true;client.authenticated=true;
    auto frame=raw_frame(8,true,payload,false);
    write_all_fd(fds[1],frame);
    bool threw=false;std::string diagnostic;
    try{(void)pacetun::websocket_read_messages(client,100);}
    catch(const std::exception&e){threw=true;diagnostic=e.what();}
    if(!threw || diagnostic.find(expected)==std::string::npos)
      throw std::runtime_error("close-frame result mismatch: "+diagnostic);
    if(valid){
      if(!client.close_received || (code!=0 && (!client.close_has_code || client.close_code!=code)))
        throw std::runtime_error("close code not retained");
      const auto after=pacetun::websocket_close_summary(client);
      if(after.find(expected)==std::string::npos || after.find("secret")!=std::string::npos)
        throw std::runtime_error("peer close summary leaked reason or lost code");
    }else if(client.close_received)throw std::runtime_error("invalid peer close accepted");
    client.upgraded=false;pacetun::websocket_close(client);close(fds[1]);
  };
  const std::array<unsigned char,8> normal{0x03,0xe8,'s','e','c','r','e','t'};
  const std::array<unsigned char,2> bad{0x03,0xed}; // 1005 must never be on wire
  const std::array<unsigned char,1> short_close{0x03};
  check(normal,true,"code=1000 category=normal reason_bytes=6",1000);
  check(bad,false,"invalid WebSocket close status");
  check(short_close,false,"invalid WebSocket close payload");
  check(std::span<const unsigned char>{},true,"code=none category=unspecified");
}
}

int main(){
  try{
    test_ptt5_crypto();
    test_upgrade_binary_and_ping();
    test_client_rejects_bad_server_proof();
    test_handshake_rejects_wrong_psk();
    test_fragment_reassembly();
    test_nonblocking_partial_tx();
    test_rejects_oversize_frame();
    test_close_diagnostics();
    std::cout<<"PaceTun 5.0.2 post-upgrade-auth self-test OK (PTT5 X25519/AEAD, upgrade, ping/pong, fragmentation, bounded RX, nonblocking TX)\n";
    return 0;
  }catch(const std::exception&e){std::cerr<<"self-test failed: "<<e.what()<<"\n";return 1;}
}
