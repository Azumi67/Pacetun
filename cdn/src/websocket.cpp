#include <openssl/hmac.h>
#include "pacetun/websocket.hpp"
#include "pacetun/record.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <limits>
#include <sstream>
#include <string_view>
#include <stdexcept>
#include <utility>

namespace pacetun { namespace {
using Clock = std::chrono::steady_clock;
constexpr std::size_t kMaxWsMessageBytes = 16 * 1024 * 1024;
constexpr std::size_t kMaxWsTxBytes = kMaxWsMessageBytes + 64 * 1024;
constexpr std::size_t kMaxWsRxBufferedBytes = 2 * kMaxWsMessageBytes + 64 * 1024;
constexpr std::size_t kMaxRememberedPongs = 16;

struct EphemeralKeyGuard {
  X25519KeyPair value;
  explicit EphemeralKeyGuard(X25519KeyPair v):value(std::move(v)){}
  ~EphemeralKeyGuard(){OPENSSL_cleanse(value.private_key.data(),value.private_key.size());}
};
struct Secret32Guard {
  Key32 value;
  explicit Secret32Guard(Key32 v):value(std::move(v)){}
  ~Secret32Guard(){OPENSSL_cleanse(value.data(),value.size());}
};

uint64_t mono_ms() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
      Clock::now().time_since_epoch()).count());
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
  return s;
}
std::string trim(std::string s) {
  auto not_space=[](unsigned char c){return !std::isspace(c);};
  s.erase(s.begin(),std::find_if(s.begin(),s.end(),not_space));
  s.erase(std::find_if(s.rbegin(),s.rend(),not_space).base(),s.end());
  return s;
}
std::string b64(std::span<const unsigned char> in) {
  std::string o(4*((in.size()+2)/3),'\0');
  int n=EVP_EncodeBlock(reinterpret_cast<unsigned char*>(o.data()),in.data(),static_cast<int>(in.size()));
  if(n<0) throw std::runtime_error("base64 encoding failed");
  o.resize(static_cast<std::size_t>(n));
  return o;
}
std::string ws_accept(const std::string& key) {
  std::string s=key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::array<unsigned char,SHA_DIGEST_LENGTH>d{};
  if(!SHA1(reinterpret_cast<const unsigned char*>(s.data()),s.size(),d.data()))
    throw std::runtime_error("SHA1 failed");
  return b64(d);
}
std::string rand_key() {
  std::array<unsigned char,16>b{};
  if(RAND_bytes(b.data(),static_cast<int>(b.size()))!=1)throw std::runtime_error("RAND_bytes failed");
  return b64(b);
}
bool valid_ws_key(const std::string& key) {
  if(key.size()!=24) return false;
  std::array<unsigned char,32> out{};
  const int n=EVP_DecodeBlock(out.data(),reinterpret_cast<const unsigned char*>(key.data()),static_cast<int>(key.size()));
  if(n<0) return false;
  int padding=0;
  if(!key.empty()&&key.back()=='=') ++padding;
  if(key.size()>1&&key[key.size()-2]=='=') ++padding;
  return n-padding==16;
}
std::string hdr(const std::string&s,const std::string&name) {
  std::string low=lower(s),needle="\r\n"+lower(name)+":";
  auto p=low.find(needle);
  if(p==std::string::npos)return{};
  p+=needle.size();
  while(p<s.size()&&(s[p]==' '||s[p]=='\t'))++p;
  auto e=s.find("\r\n",p);
  if(e==std::string::npos)e=s.size();
  return trim(s.substr(p,e-p));
}
bool header_token(const std::string& value,const std::string& token) {
  const std::string wanted=lower(token);
  std::size_t start=0;
  while(start<=value.size()) {
    auto comma=value.find(',',start);
    auto part=trim(value.substr(start,comma==std::string::npos?std::string::npos:comma-start));
    if(lower(part)==wanted)return true;
    if(comma==std::string::npos)break;
    start=comma+1;
  }
  return false;
}
bool host_matches(const std::string& got,const std::string& expected) {
  const auto g=lower(trim(got)), e=lower(trim(expected));
  return g==e || g==e+":443" || g==e+":80";
}

ssize_t io_read(WsSession&w,unsigned char*b,size_t n) {
  if(w.ssl) {
    size_t got=0;int rc=SSL_read_ex(w.ssl,b,n,&got);
    if(rc==1){w.rx_wait=0;return static_cast<ssize_t>(got);}
    int e=SSL_get_error(w.ssl,rc);
    if(e==SSL_ERROR_WANT_READ){w.rx_wait=1;errno=EAGAIN;return-1;}
    if(e==SSL_ERROR_WANT_WRITE){w.rx_wait=2;errno=EAGAIN;return-1;}
    if(e==SSL_ERROR_ZERO_RETURN)return 0;
    return-2;
  }
  const auto rc=recv(w.fd,b,n,MSG_DONTWAIT);
  if(rc>=0)w.rx_wait=0;else if(errno==EAGAIN||errno==EWOULDBLOCK)w.rx_wait=1;
  return rc;
}
ssize_t io_write(WsSession&w,const unsigned char*b,size_t n) {
  if(w.ssl) {
    size_t got=0;int rc=SSL_write_ex(w.ssl,b,n,&got);
    if(rc==1){w.tx_wait=0;return static_cast<ssize_t>(got);}
    int e=SSL_get_error(w.ssl,rc);
    if(e==SSL_ERROR_WANT_READ){w.tx_wait=1;errno=EAGAIN;return-1;}
    if(e==SSL_ERROR_WANT_WRITE){w.tx_wait=2;errno=EAGAIN;return-1;}
    if(e==SSL_ERROR_ZERO_RETURN)return 0;
    return-2;
  }
  const auto rc=send(w.fd,b,n,MSG_NOSIGNAL|MSG_DONTWAIT);
  if(rc>=0)w.tx_wait=0;
  else if(errno==EAGAIN||errno==EWOULDBLOCK)w.tx_wait=2;
  return rc;
}
void wait_io(WsSession&w,short events,Clock::time_point deadline,const char* what) {
  while(true) {
    const auto remain=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
    if(remain<=0)throw std::runtime_error(std::string("WebSocket ")+what+" timeout");
    pollfd p{w.fd,static_cast<short>(events|POLLERR|POLLHUP),0};
    const int rc=poll(&p,1,static_cast<int>(std::min<long long>(remain,250)));
    if(rc>0) {
      if(p.revents&POLLNVAL)throw std::runtime_error(std::string("WebSocket ")+what+" socket invalid");
      if(p.revents&events)return;
      if(p.revents&(POLLERR|POLLHUP))throw std::runtime_error(std::string("WebSocket ")+what+" socket closed");
      continue;
    }
    if(rc<0&&errno!=EINTR)throw std::runtime_error(std::string("WebSocket ")+what+" poll failed");
  }
}
void write_all_until(WsSession&w,std::span<const unsigned char>d,Clock::time_point deadline,const char* what) {
  size_t off=0;
  while(off<d.size()) {
    auto n=io_write(w,d.data()+off,d.size()-off);
    if(n>0){off+=static_cast<size_t>(n);continue;}
    if(n==-1&&(errno==EAGAIN||errno==EWOULDBLOCK)){wait_io(w,w.tx_wait==1?POLLIN:POLLOUT,deadline,what);continue;}
    throw std::runtime_error(std::string("WebSocket ")+what+" write failed");
  }
}
std::string read_headers(WsSession&w,int timeout_ms) {
  const auto deadline=Clock::now()+std::chrono::milliseconds(std::max(100,timeout_ms));
  std::string s;
  unsigned char b[2048];
  while(true) {
    auto end=s.find("\r\n\r\n");
    if(end!=std::string::npos) {
      end+=4;
      if(end<s.size())w.rx.insert(w.rx.end(),s.begin()+static_cast<std::ptrdiff_t>(end),s.end());
      s.resize(end);
      return s;
    }
    if(s.size()>32768)throw std::runtime_error("WebSocket headers too large");
    auto n=io_read(w,b,sizeof(b));
    if(n>0){s.append(reinterpret_cast<char*>(b),static_cast<size_t>(n));continue;}
    if(n==-1&&(errno==EAGAIN||errno==EWOULDBLOCK)){wait_io(w,w.rx_wait==2?POLLOUT:POLLIN,deadline,"upgrade");continue;}
    throw std::runtime_error("WebSocket header read failed");
  }
}

std::vector<unsigned char> make_frame(const WsSession&w,uint8_t opcode,std::span<const unsigned char>p) {
  const bool control=(opcode&0x8)!=0;
  if(control&&p.size()>125)throw std::runtime_error("WebSocket control payload too large");
  if(!control&&p.size()>kMaxWsMessageBytes)throw std::runtime_error("WebSocket payload too large");
  std::vector<unsigned char>f;
  f.reserve(14+p.size());
  f.push_back(static_cast<unsigned char>(0x80|opcode));
  const bool mask=w.client;
  const uint64_t n=p.size();
  const uint8_t mbit=mask?0x80:0;
  if(n<126)f.push_back(static_cast<unsigned char>(mbit|n));
  else if(n<=65535){f.push_back(static_cast<unsigned char>(mbit|126));f.push_back(static_cast<unsigned char>(n>>8));f.push_back(static_cast<unsigned char>(n));}
  else{f.push_back(static_cast<unsigned char>(mbit|127));for(int i=7;i>=0;--i)f.push_back(static_cast<unsigned char>(n>>(8*i)));}
  std::array<unsigned char,4>mk{};
  if(mask){
    if(RAND_bytes(mk.data(),static_cast<int>(mk.size()))!=1)throw std::runtime_error("RAND_bytes failed");
    f.insert(f.end(),mk.begin(),mk.end());
  }
  const size_t start=f.size();
  f.insert(f.end(),p.begin(),p.end());
  if(mask)for(size_t i=0;i<p.size();++i)f[start+i]^=mk[i%4];
  return f;
}

void queue_frame(WsSession&w,uint8_t opcode,std::span<const unsigned char>p) {
  auto data=make_frame(w,opcode,p);
  if(data.size()>kMaxWsTxBytes || w.tx_queued_bytes>kMaxWsTxBytes-data.size())
    throw std::runtime_error("WebSocket TX queue limit exceeded");
  const bool was_empty=w.tx.empty();
  w.tx_queued_bytes+=data.size();
  w.tx.push_back(WsTxFrame{std::move(data),0,p.size(),opcode});
  if(was_empty)w.tx_last_progress_ms=mono_ms();
}

void account_completed_frame(WsSession&w,const WsTxFrame&f) {
  if(f.opcode==2){++w.tx_binary_frames;w.tx_binary_payload_bytes+=f.payload_bytes;}
  else if(f.opcode==9)++w.tx_ping_frames;
  else if(f.opcode==10)++w.tx_pong_frames;
}

void best_effort_close_frame(WsSession&w) {
  if(!w.upgraded||w.fd<0)return;
  try {
    w.tx.clear();w.tx_queued_bytes=0;w.tx_last_progress_ms=0;
    auto f=make_frame(w,8,{});
    const auto deadline=Clock::now()+std::chrono::milliseconds(std::min(std::max(100,w.io_timeout_ms),1000));
    write_all_until(w,f,deadline,"close");
  } catch(...) {}
}
}

namespace {
std::vector<unsigned char> confirmation_mac(const SessionKeys& keys,bool client) {
  const std::string label=client?"PTT5 client key confirmation v1":"PTT5 server key confirmation v1";
  std::vector<unsigned char> out(32);unsigned n=0;
  if(!HMAC(EVP_sha256(),keys.auth.data(),keys.auth.size(),reinterpret_cast<const unsigned char*>(label.data()),label.size(),out.data(),&n)||n!=32)throw std::runtime_error("confirmation MAC failed");
  return out;
}
std::vector<unsigned char> trial_message(const SessionKeys& keys,uint8_t type,
                                         std::span<const unsigned char> nonce) {
  std::vector<unsigned char> out{type};out.insert(out.end(),nonce.begin(),nonce.end());
  std::string label="PTT5 candidate trial v1";
  std::vector<unsigned char> input(label.begin(),label.end());input.insert(input.end(),out.begin(),out.end());
  unsigned n=0;unsigned char mac[32];
  if(!HMAC(EVP_sha256(),keys.auth.data(),keys.auth.size(),input.data(),input.size(),mac,&n)||n!=32)
    throw std::runtime_error("trial MAC failed");
  out.insert(out.end(),mac,mac+32);return out;
}
void trial_session(WsSession& w,WsHandshakeResult& hs,int timeout,int max_rtt_ms) {
  const auto deadline=Clock::now()+std::chrono::milliseconds(std::max(100,timeout));
  auto send=[&](const std::vector<unsigned char>& msg){
    websocket_send_binary(w,msg);
    while(websocket_tx_pending(w)){
      websocket_flush(w);
      if(Clock::now()>=deadline)throw std::runtime_error("candidate trial send timeout");
      if(websocket_tx_pending(w)){pollfd p{w.fd,websocket_tx_poll_events(w),0};poll(&p,1,5);}
    }
  };
  auto receive=[&](){
    while(Clock::now()<deadline){
      auto messages=websocket_read_messages(w,5);if(messages.empty())continue;
      auto first=std::move(messages.front());
      for(size_t i=1;i<messages.size();++i)w.prefetched_messages.push_back(std::move(messages[i]));
      return first;
    }
    throw std::runtime_error("candidate trial receive timeout");
  };
  std::array<unsigned char,32> nonce{};
  for(uint8_t i=0;i<3;++i){
    const uint8_t request=0x40+i,response=0x50+i;
    if(w.client){
      if(RAND_bytes(nonce.data(),nonce.size())!=1)throw std::runtime_error("trial randomness failed");
      const auto start=Clock::now();send(trial_message(hs.keys,request,nonce));
      const auto got=receive(),want=trial_message(hs.keys,response,nonce);
      if(got.size()!=want.size()||CRYPTO_memcmp(got.data(),want.data(),want.size()))throw std::runtime_error("candidate trial authentication failed");
      const auto us=std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-start).count();
      hs.trial_max_rtt_us=std::max(hs.trial_max_rtt_us,static_cast<int64_t>(us));
      if(max_rtt_ms>0&&us>int64_t(max_rtt_ms)*1000)throw std::runtime_error("candidate rejected: authenticated trial RTT exceeds "+std::to_string(max_rtt_ms)+" ms");
    }else{
      const auto got=receive();if(got.size()!=65)throw std::runtime_error("invalid trial request");
      std::copy_n(got.begin()+1,32,nonce.begin());
      const auto want=trial_message(hs.keys,request,nonce);
      if(CRYPTO_memcmp(got.data(),want.data(),want.size()))throw std::runtime_error("candidate trial authentication failed");
      send(trial_message(hs.keys,response,nonce));
    }
  }
  const auto commit=trial_message(hs.keys,0x60,nonce),ack=trial_message(hs.keys,0x61,nonce);
  if(w.client){
    send(commit);auto got=receive();
    if(got.size()!=ack.size()||CRYPTO_memcmp(got.data(),ack.data(),ack.size()))throw std::runtime_error("candidate commit acknowledgement failed");
  }else{
    auto got=receive();
    if(got.size()!=commit.size()||CRYPTO_memcmp(got.data(),commit.data(),commit.size()))throw std::runtime_error("candidate commit failed");
    send(ack);
  }
}
void confirm_session(WsSession& w,WsHandshakeResult& hs,int timeout) {
  auto deadline=Clock::now()+std::chrono::milliseconds(std::max(100,timeout));
  auto send=[&]{websocket_send_binary(w,confirmation_mac(hs.keys,w.client));while(websocket_tx_pending(w)){websocket_flush(w);if(Clock::now()>=deadline)throw std::runtime_error("key confirmation timeout");if(websocket_tx_pending(w)){pollfd p{w.fd,websocket_tx_poll_events(w),0};poll(&p,1,10);}}};
  auto receive=[&]{
    while(Clock::now()<deadline){auto messages=websocket_read_messages(w,10);if(messages.empty())continue;
      auto wanted=confirmation_mac(hs.keys,!w.client);
      if(messages[0].size()!=wanted.size()||CRYPTO_memcmp(messages[0].data(),wanted.data(),wanted.size())!=0)throw std::runtime_error("key confirmation failed");
      for(size_t i=1;i<messages.size();++i)w.prefetched_messages.push_back(std::move(messages[i]));
      return;
    }throw std::runtime_error("key confirmation timeout");
  };
  if(w.client){send();receive();}else{receive();send();}
}
}
namespace {
constexpr std::string_view kClientHello = "PTT6-C:";
constexpr std::string_view kPoolClientHello = "PTT8-C:";
constexpr std::string_view kPoolServerHello = "PTT8-S:";
constexpr std::string_view kServerHello = "PTT6-S:";
constexpr std::size_t kClientHelloSize = 7 + 64 + 64 + 64;
constexpr std::size_t kServerHelloSize = 7 + 64 + 64 + 64;
void send_handshake(WsSession& w,const std::string& data,Clock::time_point deadline) {
  if(data.size()>1024)throw std::runtime_error("oversized handshake");
  websocket_send_binary(w,{reinterpret_cast<const unsigned char*>(data.data()),data.size()});
  while(websocket_tx_pending(w)) {
    websocket_flush(w);
    if(Clock::now()>=deadline)throw std::runtime_error("post-upgrade authentication timeout");
    if(websocket_tx_pending(w))wait_io(w,websocket_tx_poll_events(w),deadline,"authentication send");
  }
}
std::string receive_handshake(WsSession& w,Clock::time_point deadline) {
  while(Clock::now()<deadline) {
    const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
    const auto messages=websocket_read_messages(w,static_cast<int>(std::clamp<long long>(left,1,100)));
    if(messages.empty())continue;
    if(messages.size()!=1||messages.front().size()>1024)throw std::runtime_error("invalid post-upgrade negotiation frame count or size");
    return std::string(messages.front().begin(),messages.front().end());
  }
  throw std::runtime_error("post-upgrade authentication timeout");
}
}
WsHandshakeResult websocket_client_upgrade(WsSession&w,const std::string&host,const std::string&path,
                                           std::span<const unsigned char>psk,int timeout_ms,int candidate_max_rtt_ms,bool require_trial,int pool_connections) {
  if(pool_connections<1||pool_connections>4)throw std::runtime_error("invalid pool handshake size");
  if(w.ssl)SSL_set_mode(w.ssl,SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  WsHandshakeResult result;
  EphemeralKeyGuard eph(generate_x25519_keypair());
  result.client_nonce=random_nonce_hex();
  const auto client_public_hex=key32_hex(eph.value.public_key);
  const auto key=rand_key();
  std::string browser_headers;
  if(w.browser_profile!="none") {
    const std::string ua=w.browser_profile=="chrome120"
      ? "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      : "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0";
    browser_headers="User-Agent: "+ua+"\r\nOrigin: https://"+host+"\r\nSec-Fetch-Dest: websocket\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n";
  }
  const std::string req="GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "+key+"\r\nSec-WebSocket-Version: 13\r\n"+browser_headers+"\r\n";
  const auto deadline=Clock::now()+std::chrono::milliseconds(std::max(100,timeout_ms));
  write_all_until(w,{reinterpret_cast<const unsigned char*>(req.data()),req.size()},deadline,"upgrade");
  const auto remain=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
  if(remain<=0)throw std::runtime_error("WebSocket upgrade timeout");
  const auto r=read_headers(w,static_cast<int>(remain));
  if(r.rfind("HTTP/1.1 101 ",0)!=0 && r.rfind("HTTP/1.1 101\r\n",0)!=0)
    throw std::runtime_error("WebSocket upgrade rejected: "+r.substr(0,r.find("\r\n")));
  if(lower(hdr(r,"Upgrade"))!="websocket"||!header_token(hdr(r,"Connection"),"upgrade")||
     hdr(r,"Sec-WebSocket-Accept")!=ws_accept(key)||!hdr(r,"Sec-WebSocket-Protocol").empty())
    throw std::runtime_error("invalid RFC6455 upgrade response");
  w.upgraded=true;
  const bool pooled=pool_connections>1;
  const std::string bind=pooled?("pool-v2:"+std::to_string(pool_connections)):"";
  const auto token=websocket_client_auth_token_v5(psk,host,path,result.client_nonce,client_public_hex+bind);
  result.pool_connections=pool_connections;
  send_handshake(w,std::string(pooled?kPoolClientHello:kClientHello)+result.client_nonce+client_public_hex+token,deadline);
  const auto response=receive_handshake(w,deadline);
  const auto server_prefix=pooled?kPoolServerHello:kServerHello;
  if(response.size()!=kServerHelloSize||response.compare(0,server_prefix.size(),server_prefix)!=0)
    throw std::runtime_error("invalid authenticated server negotiation");
  result.server_nonce=response.substr(server_prefix.size(),64);
  const auto server_public_hex=response.substr(server_prefix.size()+64,64);
  const auto proof=response.substr(server_prefix.size()+128,64);
  Key32 server_public{};
  try{server_public=key32_from_hex(server_public_hex);}catch(...){throw std::runtime_error("invalid server public key");}
  const auto want=websocket_server_proof_v5(psk,host,path,result.client_nonce,result.server_nonce,client_public_hex,server_public_hex+bind);
  if(proof.size()!=want.size()||CRYPTO_memcmp(proof.data(),want.data(),want.size())!=0)
    throw std::runtime_error("server authentication failed");
  Secret32Guard shared(x25519_shared_secret(eph.value.private_key,server_public));
  result.keys=derive_session_keys_v5(psk,shared.value,result.server_nonce,result.client_nonce,eph.value.public_key,server_public);
  result.confirmed=result.peer_trial=result.peer_envelope=result.peer_padding=true;
  confirm_session(w,result,timeout_ms);
  if(result.peer_trial)trial_session(w,result,timeout_ms,candidate_max_rtt_ms);
  if(require_trial&&!result.peer_trial)throw std::runtime_error("replacement requires trial-v1");
  w.authenticated=true;
  return result;
}

WsHandshakeResult websocket_server_upgrade(WsSession&w,const std::string&host,const std::string&path,
                                           const std::vector<std::vector<unsigned char>>&psks,int timeout_ms,int pool_connections) {
  if(pool_connections<1||pool_connections>4)throw std::runtime_error("invalid server pool handshake size");
  if(w.ssl)SSL_set_mode(w.ssl,SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  WsHandshakeResult result;
  const auto deadline=Clock::now()+std::chrono::milliseconds(std::max(100,timeout_ms));
  const auto r=read_headers(w,timeout_ms);
  const auto e=r.find("\r\n");
  if(e==std::string::npos||r.substr(0,e)!="GET "+path+" HTTP/1.1")throw std::runtime_error("invalid WebSocket path or method");
  const auto key=hdr(r,"Sec-WebSocket-Key");
  if(lower(hdr(r,"Upgrade"))!="websocket"||!header_token(hdr(r,"Connection"),"upgrade")||
     hdr(r,"Sec-WebSocket-Version")!="13"||!valid_ws_key(key)||!hdr(r,"Sec-WebSocket-Protocol").empty())
    throw std::runtime_error("invalid RFC6455 request");
  if(!host_matches(hdr(r,"Host"),host))throw std::runtime_error("invalid WebSocket Host");
  const auto resp="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+ws_accept(key)+"\r\n\r\n";
  write_all_until(w,{reinterpret_cast<const unsigned char*>(resp.data()),resp.size()},deadline,"upgrade");
  w.upgraded=true;
  const auto hello=receive_handshake(w,deadline);
  const bool pooled=pool_connections>1;
  const auto client_prefix=pooled?kPoolClientHello:kClientHello;
  const std::string bind=pooled?("pool-v2:"+std::to_string(pool_connections)):"";
  if(hello.size()!=kClientHelloSize||hello.compare(0,client_prefix.size(),client_prefix)!=0)
    throw std::runtime_error("invalid post-upgrade client negotiation");
  result.client_nonce=hello.substr(client_prefix.size(),64);
  const auto client_public_hex=hello.substr(client_prefix.size()+64,64);
  const auto auth=hello.substr(client_prefix.size()+128,64);
  Key32 client_public{};
  try{client_public=key32_from_hex(client_public_hex);}catch(...){throw std::runtime_error("invalid client public key");}
  std::size_t idx=psks.size();
  for(std::size_t i=0;i<psks.size();++i){
    const auto want=websocket_client_auth_token_v5(psks[i],host,path,result.client_nonce,client_public_hex+bind);
    if(auth.size()==want.size()&&CRYPTO_memcmp(auth.data(),want.data(),want.size())==0){idx=i;break;}
  }
  if(idx==psks.size())throw std::runtime_error("post-upgrade client authentication failed");
  result.psk_index=idx;
  EphemeralKeyGuard eph(generate_x25519_keypair());
  result.server_nonce=random_nonce_hex();
  const auto server_public_hex=key32_hex(eph.value.public_key);
  const auto proof=websocket_server_proof_v5(psks[idx],host,path,result.client_nonce,result.server_nonce,client_public_hex,server_public_hex+bind);
  Secret32Guard shared(x25519_shared_secret(eph.value.private_key,client_public));
  result.keys=derive_session_keys_v5(psks[idx],shared.value,result.server_nonce,result.client_nonce,client_public,eph.value.public_key);
  result.pool_connections=pool_connections;
  send_handshake(w,std::string(pooled?kPoolServerHello:kServerHello)+result.server_nonce+server_public_hex+proof,deadline);
  result.confirmed=result.peer_trial=result.peer_envelope=result.peer_padding=true;
  confirm_session(w,result,timeout_ms);
  trial_session(w,result,timeout_ms,0);
  w.authenticated=true;
  return result;
}

namespace {
bool valid_close_status(uint16_t code) {
  return (code>=1000 && code<=1014 && code!=1004 && code!=1005 && code!=1006) ||
         (code>=3000 && code<=4999);
}
const char* close_category(uint16_t code) {
  switch(code){
    case 1000:return "normal";
    case 1001:return "going_away";
    case 1002:return "protocol_error";
    case 1003:return "unsupported_data";
    case 1007:return "invalid_payload";
    case 1008:return "policy_violation";
    case 1009:return "message_too_big";
    case 1010:return "extension_required";
    case 1011:return "server_error";
    case 1012:return "service_restart";
    case 1013:return "try_again_later";
    case 1014:return "bad_gateway";
    default:return code>=3000&&code<=3999?"registered":"private";
  }
}
} 
std::string websocket_close_summary(const WsSession&w) {
  if(!w.close_received)return "WebSocket peer close not received";
  if(!w.close_has_code)return "WebSocket peer close received code=none category=unspecified reason_bytes=0";
  return "WebSocket peer close received code="+std::to_string(w.close_code)+
      " category="+close_category(w.close_code)+
      " reason_bytes="+std::to_string(w.close_reason_bytes);
}
void websocket_send_binary(WsSession&w,std::span<const unsigned char>p){queue_frame(w,2,p);}
void websocket_send_ping(WsSession&w,std::span<const unsigned char>p){queue_frame(w,9,p);}
void websocket_send_pong(WsSession&w,std::span<const unsigned char>p){queue_frame(w,10,p);}

std::size_t websocket_flush(WsSession&w,std::size_t byte_budget) {
  if(byte_budget==0)return 0;
  std::size_t written=0;
  while(!w.tx.empty()&&written<byte_budget) {
    auto&f=w.tx.front();
    if(f.offset>=f.data.size()) {
      account_completed_frame(w,f);
      w.tx.pop_front();
      continue;
    }
    const std::size_t want=std::min(f.data.size()-f.offset,byte_budget-written);
    auto n=io_write(w,f.data.data()+f.offset,want);
    if(n>0) {
      const auto nn=static_cast<std::size_t>(n);
      f.offset+=nn;written+=nn;w.tx_queued_bytes-=nn;w.tx_last_progress_ms=mono_ms();
      if(f.offset==f.data.size()) {
        account_completed_frame(w,f);
        w.tx.pop_front();
        if(w.tx.empty())w.tx_last_progress_ms=0;
        else w.tx_last_progress_ms=mono_ms();
      }
      continue;
    }
    if(n==-1&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
    throw std::runtime_error("WebSocket I/O write failed");
  }
  return written;
}

bool websocket_tx_pending(const WsSession&w){return !w.tx.empty();}
short websocket_tx_poll_events(const WsSession&w){
  if(w.tx.empty())return 0;
  if(w.tx_wait==1)return POLLIN;
  return POLLOUT;
}
short websocket_rx_poll_events(const WsSession&w){
  if(w.rx_wait==2)return POLLOUT;
  return POLLIN;
}
std::size_t websocket_tx_queued_bytes(const WsSession&w){return w.tx_queued_bytes;}
bool websocket_tx_stalled(const WsSession&w,int timeout_ms) {
  if(w.tx.empty()||w.tx_last_progress_ms==0||timeout_ms<=0)return false;
  const auto now=mono_ms();
  return now>=w.tx_last_progress_ms&&now-w.tx_last_progress_ms>static_cast<uint64_t>(timeout_ms);
}
std::vector<std::vector<unsigned char>> websocket_take_pongs(WsSession&w) {
  std::vector<std::vector<unsigned char>> out;
  out.reserve(w.pong_payloads.size());
  while(!w.pong_payloads.empty()) {out.push_back(std::move(w.pong_payloads.front()));w.pong_payloads.pop_front();}
  return out;
}

std::vector<std::vector<unsigned char>> websocket_read_messages(WsSession&w,int timeout_ms) {
  if(!w.prefetched_messages.empty()){auto messages=std::move(w.prefetched_messages);w.prefetched_messages.clear();return messages;}
  if(w.close_received)throw std::runtime_error(websocket_close_summary(w));
  if(w.peer_eof&&w.rx.empty())throw std::runtime_error("WebSocket peer closed");
  pollfd p{w.fd,websocket_rx_poll_events(w),0};
  if((!w.ssl||SSL_pending(w.ssl)==0)&&w.rx.empty()&&poll(&p,1,timeout_ms)<=0)return{};
  unsigned char b[65536];
  size_t received=0;
  while(received<256*1024){
    auto n=io_read(w,b,sizeof(b));
    if(n>0){
      if(w.rx.size()>kMaxWsRxBufferedBytes-static_cast<std::size_t>(n))
        throw std::runtime_error("WebSocket RX buffer limit exceeded");
      w.rx.insert(w.rx.end(),b,b+n);received+=static_cast<size_t>(n);continue;
    }
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
    if(n==0){w.peer_eof=true;break;}
    throw std::runtime_error("WebSocket read failed");
  }

  std::vector<std::vector<unsigned char>>out;
  size_t off=0;
  while(true){
    if(w.rx.size()-off<2)break;
    const uint8_t b0=w.rx[off],b1=w.rx[off+1];
    const bool fin=(b0&0x80)!=0;
    const bool masked=(b1&0x80)!=0;
    const uint8_t rsv=b0&0x70;
    const uint8_t op=b0&0x0f;
    const uint8_t len7=b1&0x7f;
    uint64_t n=len7;
    size_t pos=off+2;

    if(rsv)throw std::runtime_error("WebSocket RSV bits are not supported");
    const bool control=(op&0x8)!=0;
    if(control&&!fin)throw std::runtime_error("fragmented WebSocket control frame rejected");
    if(control&&len7>=126)throw std::runtime_error("invalid WebSocket control frame length");
    if(w.client&&masked)throw std::runtime_error("masked server WebSocket frame rejected");
    if(!w.client&&!masked)throw std::runtime_error("unmasked client WebSocket frame rejected");

    if(n==126){if(w.rx.size()<pos+2)break;n=(static_cast<uint64_t>(w.rx[pos])<<8)|w.rx[pos+1];pos+=2;}
    else if(n==127){
      if(w.rx.size()<pos+8)break;
      if(w.rx[pos]&0x80)throw std::runtime_error("invalid WebSocket 64-bit length");
      n=0;for(int i=0;i<8;++i)n=(n<<8)|w.rx[pos+i];pos+=8;
    }
    std::array<unsigned char,4>mk{};
    if(masked){if(w.rx.size()<pos+4)break;std::copy_n(w.rx.begin()+static_cast<std::ptrdiff_t>(pos),4,mk.begin());pos+=4;}
    if(n>(w.authenticated?kMaxWsMessageBytes:1024))throw std::runtime_error("WebSocket frame too large");
    if(n>std::numeric_limits<size_t>::max()-pos)throw std::runtime_error("WebSocket frame length overflow");
    if(w.rx.size()<pos+static_cast<size_t>(n))break;

    std::vector<unsigned char>pay(w.rx.begin()+static_cast<std::ptrdiff_t>(pos),w.rx.begin()+static_cast<std::ptrdiff_t>(pos+static_cast<size_t>(n)));
    if(masked)for(size_t i=0;i<pay.size();++i)pay[i]^=mk[i%4];
    off=pos+static_cast<size_t>(n);
    ++w.rx_frames;

    if(op==2) {
      if(w.fragment_opcode!=0)throw std::runtime_error("new WebSocket data frame during fragmented message");
      if(fin){w.rx_binary_payload_bytes+=pay.size();out.push_back(std::move(pay));}
      else {w.fragment_opcode=2;w.fragment_payload=std::move(pay);}
    }
    else if(op==0) {
      if(w.fragment_opcode==0)throw std::runtime_error("unexpected WebSocket continuation frame");
      if(w.fragment_payload.size()>kMaxWsMessageBytes-pay.size())throw std::runtime_error("fragmented WebSocket message too large");
      w.fragment_payload.insert(w.fragment_payload.end(),pay.begin(),pay.end());
      if(fin) {
        if(w.fragment_opcode!=2)throw std::runtime_error("unsupported fragmented WebSocket message");
        w.rx_binary_payload_bytes+=w.fragment_payload.size();
        out.push_back(std::move(w.fragment_payload));
        w.fragment_payload.clear();w.fragment_opcode=0;
      }
    }
    else if(op==9){++w.rx_ping_frames;websocket_send_pong(w,pay);}
    else if(op==10){
      ++w.rx_pong_frames;
      if(w.pong_payloads.size()>=kMaxRememberedPongs)w.pong_payloads.pop_front();
      w.pong_payloads.push_back(std::move(pay));
    }
    else if(op==8){
      if(pay.size()==1)throw std::runtime_error("invalid WebSocket close payload");
      if(pay.size()>=2){
        const auto code=static_cast<uint16_t>((uint16_t(pay[0])<<8)|pay[1]);
        if(!valid_close_status(code))throw std::runtime_error("invalid WebSocket close status");
        w.close_code=code;w.close_has_code=true;w.close_reason_bytes=pay.size()-2;
      }
      try{queue_frame(w,8,pay);}catch(...){}
      w.close_received=true;
      if(out.empty())throw std::runtime_error(websocket_close_summary(w));
      break;
    }
    else if(op==1)throw std::runtime_error("text WebSocket messages unsupported");
    else throw std::runtime_error("unsupported WebSocket opcode");
  }
  if(off){
    if(off==w.rx.size())w.rx.clear();
    else w.rx.erase(w.rx.begin(),w.rx.begin()+static_cast<std::ptrdiff_t>(off));
  }
  if(w.peer_eof&&!w.rx.empty())throw std::runtime_error("truncated WebSocket frame at EOF");
  if(w.peer_eof&&w.fragment_opcode!=0)throw std::runtime_error("truncated fragmented WebSocket message at EOF");
  if(w.peer_eof&&out.empty())throw std::runtime_error("WebSocket peer closed");
  return out;
}

void websocket_http_fallback(WsSession&w) {
  if(w.upgraded)return;
  const std::string body="<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Not found</title><h1>Not found</h1><p>The requested page is unavailable.</p></html>\n";
  const std::string response="HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "+std::to_string(body.size())+"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"+body;
  write_all_until(w,{reinterpret_cast<const unsigned char*>(response.data()),response.size()},Clock::now()+std::chrono::milliseconds(1000),"fallback");
}

void websocket_close(WsSession&w) {
  best_effort_close_frame(w);
  if(w.ssl){SSL_set_quiet_shutdown(w.ssl,1);SSL_free(w.ssl);w.ssl=nullptr;}
  if(w.fd>=0){shutdown(w.fd,SHUT_RDWR);close(w.fd);w.fd=-1;}
  w.tx.clear();w.tx_queued_bytes=0;w.tx_last_progress_ms=0;w.tx_wait=0;w.rx_wait=0;
}
}
