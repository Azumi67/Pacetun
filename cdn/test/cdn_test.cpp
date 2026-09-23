#include "pacetun/record.hpp"
#include "pacetun/websocket.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>
using namespace pacetun;
void need(bool ok){if(!ok)throw std::runtime_error("CDN test failed");}
int main(){
 Key32 k{};std::vector<unsigned char> packet(1200,0x41);packet[0]=0x45;
 for(int n: {0,1,128,1024}){
  RecordDecoderV5 d(k,65536);int delivered=0;std::string error;
  for(int i=1;i<100;++i){
   auto r=encode_padded_record_v5(k,i,packet,n);
   need(r.size()>=packet.size()+32 && r.size()<=packet.size()+34+n);
   auto cb=[&](uint8_t f,uint64_t,std::span<const unsigned char> b){need(f==0 && std::vector<unsigned char>(b.begin(),b.end())==packet);++delivered;};
   need(d.feed(std::span(r.data(),7),cb,error));need(d.feed(std::span(r.data()+7,r.size()-7),cb,error));
  }
  need(delivered==99);
 }
 auto r=encode_padded_record_v5(k,1,packet,128);r.back()^=1;
 RecordDecoderV5 corrupt(k,65536);std::string err;bool called=false;auto cb=[&](uint8_t,uint64_t,std::span<const unsigned char>){called=true;};need(!corrupt.feed(r,cb,err)&&!called);
 r=encode_padded_record_v5(k,1,packet,128);RecordDecoderV5 replay(k,65536);need(replay.feed(r,cb,err));need(!replay.feed(r,cb,err));
 std::vector<unsigned char> bad(24);bad[0]=0xff;bad[1]=0xff;r=encode_record_v5(k,1,bad,RECORD_PADDED);RecordDecoderV5 malformed(k,65536);called=false;need(!malformed.feed(r,cb,err)&&!called);
 bool rejects=false;try{encode_padded_record_v5(k,1,packet,1025);}catch(...){rejects=true;}need(rejects);
 int fd[2];need(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);WsSession ws;ws.fd=fd[0];websocket_http_fallback(ws);char b[2048];auto count=read(fd[1],b,sizeof(b));need(count>0 && std::string(b,count).starts_with("HTTP/1.1 404"));close(fd[1]);websocket_close(ws);
 std::cout<<"CDN padding, corruption, replay, malformed-length and HTTP fallback tests PASS\n";
}
