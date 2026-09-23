#include "pacetun/admission.hpp"
#include "pacetun/traffic.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <future>
#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
using namespace pacetun;
void need(bool b,const char*why){if(!b)throw std::runtime_error(why);}
int dial(uint16_t port){int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=htons(port);need(connect(fd,(sockaddr*)&a,sizeof(a))==0,"connect");timeval t{2,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));return fd;}
void crypto(){Key32 key{};std::string error;
 for(uint8_t flag:{uint8_t(0),RECORD_KEEPALIVE,RECORD_PING,RECORD_PONG}){
  std::vector<unsigned char> payload(flag==0?1200:flag==RECORD_KEEPALIVE?0:8,42);
  RecordDecoderV5 decoder(key,65536);
  for(int seq=1;seq<=100;++seq){auto r=encode_envelope_record_v5(key,seq,payload,flag,64);int calls=0;auto cb=[&](uint8_t f,uint64_t q,std::span<const unsigned char>b){need(f==flag&&q==static_cast<uint64_t>(seq)&&std::vector<unsigned char>(b.begin(),b.end())==payload,"envelope recovery");++calls;};
   need(decoder.feed(std::span(r.data(),5),cb,error)&&decoder.feed(std::span(r.data()+5,r.size()-5),cb,error)&&calls==1,"fragmented envelope");
  }
 }
 std::vector<unsigned char> invalid{RECORD_PING,0,0};auto r=encode_record_v5(key,1,invalid,RECORD_ENVELOPE);RecordDecoderV5 d(key,65536);bool called=false;auto cb=[&](uint8_t,uint64_t,std::span<const unsigned char>){called=true;};need(!d.feed(r,cb,error)&&!called,"authenticated malformed control accepted");
 r=encode_envelope_record_v5(key,1,{},RECORD_KEEPALIVE,64);r.back()^=1;RecordDecoderV5 bad(key,65536);need(!bad.feed(r,cb,error),"tampered control accepted");
 PaddingBudget budget(10,0);uint64_t bytes=0,extra=0;
 for(int i=0;i<1000;++i){size_t n=(i%2)?84:1200;int allowance=budget.data_allowance(n,128);int used=allowance>=3?allowance:0;budget.spend_data(used);bytes+=n;extra+=used;need(extra<=bytes/10,"data budget exceeded");}
 PaddingBudget idle(10,0);uint64_t control=0;
 for(uint64_t now=0;now<=1000000;now+=1000){int a=idle.control_allowance(64,now);idle.spend_control(a);control+=a;}
 need(control<=192,"control rate budget exceeded");
 std::mt19937 rng(42);int lo=999999,hi=0;for(int i=0;i<100;++i){int x=traffic_interval_ms(15,15,rng);need(x>=12750&&x<=17250,"jitter bounds");lo=std::min(lo,x);hi=std::max(hi,x);}need(hi>lo,"jitter constant");
}
void admission(){
 int listener=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);need(bind(listener,(sockaddr*)&a,sizeof(a))==0&&listen(listener,32)==0,"listen");socklen_t len=sizeof(a);getsockname(listener,(sockaddr*)&a,&len);uint16_t port=ntohs(a.sin_port);
 std::vector<unsigned char> key(32,7);AdmissionServer server(listener,"example.test","/ws",{key},750,4,8);
 int slow[3];for(auto&fd:slow){fd=dial(port);const char part[]="GET /ws HTTP/1.1\r\n";send(fd,part,sizeof(part)-1,MSG_NOSIGNAL);}
 WsSession client;client.fd=dial(port);client.client=true;
 auto h=websocket_client_upgrade(client,"example.test","/ws",key,1500);need(h.peer_envelope&&h.confirmed&&h.peer_trial&&h.trial_max_rtt_us>=0,"missing measured trial");
 auto active=server.take(1500);need(active!=nullptr,"slow peers blocked legitimate handshake");
 int probe=dial(port);std::string request="GET /missing HTTP/1.1\r\nHost: example.test\r\n\r\n";send(probe,request.data(),request.size(),MSG_NOSIGNAL);char buf[2048];auto n=recv(probe,buf,sizeof(buf),0);need(n>0&&std::string(buf,n).starts_with("HTTP/1.1 404"),"probe not handled during active tunnel");close(probe);
 for(auto fd:slow)close(fd);
 int replay=dial(port);
 std::string request2="GET /ws HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
 send(replay,request2.data(),request2.size(),MSG_NOSIGNAL);
 n=recv(replay,buf,sizeof(buf),0);need(n>0&&std::string(buf,n).starts_with("HTTP/1.1 101"),"valid RFC6455 upgrade rejected");
 WsSession impostor;impostor.fd=replay;impostor.client=true;std::vector<unsigned char> forged(32,0);
 websocket_send_binary(impostor,forged);while(websocket_tx_pending(impostor))websocket_flush(impostor);
 need(!server.take(1000),"unconfirmed peer admitted as replacement");websocket_close(impostor);
 int pair[2];need(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0,"relay pair");
 auto relay=std::async(std::launch::async,[&,a=pair[1]]{
  int b=dial(port);char bytes[65536];bool stop=false;
  while(!stop){pollfd p[2]={{a,POLLIN,0},{b,POLLIN,0}};if(poll(p,2,2000)<=0)break;
   for(int i=0;i<2;++i){if(p[i].revents&(POLLERR|POLLHUP|POLLNVAL)){stop=true;break;}
    if(p[i].revents&POLLIN){auto n=recv(p[i].fd,bytes,sizeof(bytes),0);if(n<=0){stop=true;break;}
      if(i==1)std::this_thread::sleep_for(std::chrono::milliseconds(20));
      size_t off=0;while(off<size_t(n)){auto k=send(i==0?b:a,bytes+off,n-off,MSG_NOSIGNAL);if(k<=0){stop=true;break;}off+=k;}
    }
   }
  }close(a);close(b);
 });
 WsSession slow_candidate;slow_candidate.fd=pair[0];slow_candidate.client=true;
 bool rejected=false;
 try{websocket_client_upgrade(slow_candidate,"example.test","/ws",key,1500,1,true);}
 catch(const std::exception& e){rejected=std::string(e.what()).find("candidate rejected")!=std::string::npos;}
 websocket_close(slow_candidate);relay.get();need(rejected,"slow candidate not rejected");
 need(!server.take(100),"rejected candidate displaced live tunnel");
 WsSession second;second.fd=dial(port);second.client=true;websocket_client_upgrade(second,"example.test","/ws",key,1500);auto standby=server.take(1500);need(standby&&standby->handshake.confirmed,"confirmed standby unavailable");standby.reset();websocket_close(second);
 std::vector<unsigned char> packet{1,2,3};websocket_send_binary(active->ws,packet);while(websocket_tx_pending(active->ws))websocket_flush(active->ws);auto got=websocket_read_messages(client,1000);need(got.size()==1&&got[0]==packet,"active session interrupted by probes");
 active.reset();websocket_close(client);
 WsSession reconnect;reconnect.fd=dial(port);reconnect.client=true;websocket_client_upgrade(reconnect,"example.test","/ws",key,1500);auto next=server.take(1500);need(next!=nullptr,"reconnect slot not released");next.reset();websocket_close(reconnect);
}
void pooled_admission(){
 int listener=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 need(bind(listener,(sockaddr*)&a,sizeof(a))==0&&listen(listener,32)==0,"pool listen");
 socklen_t len=sizeof(a);getsockname(listener,(sockaddr*)&a,&len);const uint16_t port=ntohs(a.sin_port);
 std::vector<unsigned char> key(32,0x5a);AdmissionServer server(listener,"example.test","/ws",{key},1700,4,8,2);
 WsSession left;left.fd=dial(port);left.client=true;
 auto a_hs=websocket_client_upgrade(left,"example.test","/ws",key,1700,0,false,2);
 need(a_hs.confirmed&&a_hs.pool_connections==2&&a_hs.peer_trial,"PTT7 first lane handshake");
 auto a_peer=server.take(1700);need(a_peer&&a_peer->handshake.confirmed&&a_peer->handshake.pool_connections==2,"PTT7 first lane admission");
 WsSession right;right.fd=dial(port);right.client=true;
 auto b_hs=websocket_client_upgrade(right,"example.test","/ws",key,1700,0,false,2);
 auto b_peer=server.take(1700);need(b_peer&&b_peer->handshake.confirmed&&b_peer->handshake.pool_connections==2,"PTT7 second lane admission");
 need(a_hs.keys.client_tx!=b_hs.keys.client_tx,"pool lanes reused encryption keys");
 std::vector<unsigned char> p(40,0);p[0]=0x45;p[3]=40;p[9]=6;p[12]=10;p[16]=10;
 auto ra=encode_record_v5(a_hs.keys.client_tx,1,p),rb=encode_record_v5(b_hs.keys.client_tx,1,p);
 RecordDecoderV5 da(a_peer->handshake.keys.client_tx,65536),db(b_peer->handshake.keys.client_tx,65536);
 std::string err;int accepted=0;auto cb=[&](uint8_t f,uint64_t seq,std::span<const unsigned char>data){need(f==0&&seq==1&&std::equal(p.begin(),p.end(),data.begin(),data.end()),"PTT7 lane payload");++accepted;};
 need(da.feed(ra,cb,err)&&db.feed(rb,cb,err)&&accepted==2,"PTT7 independent sequence spaces");
 RecordDecoderV5 cross(b_peer->handshake.keys.client_tx,65536);need(!cross.feed(ra,cb,err),"cross-lane encrypted replay accepted");
 WsSession wrong;wrong.fd=dial(port);wrong.client=true;bool mismatched=false;
 try{(void)websocket_client_upgrade(wrong,"example.test","/ws",key,1200,0,false,3);}
 catch(const std::exception&){mismatched=true;}
 need(mismatched,"PTT7 mismatched pool count accepted");websocket_close(wrong);
 need(!server.take(100),"misconfigured pool peer admitted");
 WsSession replacement;replacement.fd=dial(port);replacement.client=true;
 (void)websocket_client_upgrade(replacement,"example.test","/ws",key,1700,0,false,2);
 auto replaced=server.take(1700);need(replaced&&replaced->handshake.confirmed,"pool did not refill after lane loss");
 a_peer.reset();websocket_close(left);
 replaced.reset();b_peer.reset();websocket_close(right);websocket_close(replacement);
}
void policy_test(){LatencyRenewal p;need(!p.observe(1000000,800000,1000000,true,600,3,180),"first spike");need(!p.observe(1000000,800000,2000000,true,600,3,180),"stale reused sample");need(!p.observe(2000000,800000,2000000,true,600,3,180),"second spike");need(p.observe(3000000,800000,3000000,true,600,3,180),"third spike no renewal");for(uint64_t i=4;i<100;++i)need(!p.observe(i*1000000,800000,i*1000000,true,600,3,180),"cooldown failed");need(!p.observe(200000000,800000,200000000,false,600,3,180),"idle renewal");need(!p.observe(201000000,800000,201000000,true,600,3,180),"idle reset failed");need(!p.observe(202000000,100000,202000000,true,600,3,180),"low reset failed");}
void watchdog_test(){
 ReplyWatchdog w;need(!w.pending(),"initial pending");w.sent(1000);w.sent(2000);
 need(w.age_us(5000)==4000,"outstanding deadline overwritten");
 need(!w.reply(2000,5000)&&w.pending(),"unrelated pong cleared watchdog");
 need(w.reply(1000,5000)&&!w.pending(),"matching pong rejected");
 need(!w.reply(1000,6000),"duplicate pong accepted");
 RecoveryBackoff b;need(b.ready(0),"initial backoff");b.started(0);need(!b.ready(29999999),"minimum cooldown");
 b.failed(1000000);need(b.remaining_sec(1000000)==30,"first failure backoff");
 b.failed(31000000);need(b.remaining_sec(31000000)==60,"second failure backoff");
 for(int i=0;i<10;++i)b.failed(100000000);need(b.remaining_sec(100000000)==300,"backoff cap");
 b.succeeded(200000000);need(b.remaining_sec(200000000)==30,"success reset");
}
int main(){crypto();admission();pooled_admission();policy_test();watchdog_test();std::cout<<"5.5 PTT7 two-lane admission, key isolation, refill and legacy tests PASS\n";}
