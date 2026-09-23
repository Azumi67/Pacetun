#include <future>
#include <functional>
#include "pacetun/runtime.hpp"
#include "pacetun/record.hpp"
#include "pacetun/tun.hpp"
#include "pacetun/websocket.hpp"
#include "pacetun/carrier.hpp"
#include "pacetun/admission.hpp"
#include "pacetun/traffic.hpp"
#include "pacetun/telemetry.hpp"
#include "pacetun/logging.hpp"
#include "pacetun/edge_selection.hpp"
#include "pacetun/flow_scheduler.hpp"
#include "pacetun/pool.hpp"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace pacetun { namespace {
using Clock=std::chrono::steady_clock;
std::atomic<bool> g_stop{false},g_force_disconnect{false};
std::atomic<int> g_state{0};
std::atomic<int> g_phase{0};
std::mutex g_events_mu;
std::deque<std::string> g_events;
constexpr std::size_t kMaxEvents=64;
void on_signal(int){g_stop=true;g_state=5;g_phase=9;}
const char* state_name(int s){switch(s){case 1:return"LISTENING";case 2:return"CONNECTING";case 3:return"ONLINE";case 4:return"RECONNECTING";case 5:return"STOPPING";default:return"STARTING";}}
const char* phase_name(int p){switch(p){case 1:return"TUN_READY";case 2:return"LISTENING";case 3:return"TCP_CONNECTING";case 4:return"TLS_HANDSHAKE";case 5:return"CARRIER_UPGRADE";case 6:return"AUTHENTICATED";case 7:return"ONLINE";case 8:return"RECONNECTING";case 9:return"STOPPING";case 10:return"LEGACY";default:return"STARTING";}}
const char* wire_name(const Config&c){if(c.transport=="websocket")return c.max_connections>1?"PTT8-POOL":"PTT5";return"PTT3";}
void event(std::string text){
  auto now=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm tm{};gmtime_r(&now,&tm);std::ostringstream o;o<<std::put_time(&tm,"%Y-%m-%dT%H:%M:%SZ")<<" "<<text;
  std::lock_guard<std::mutex>lk(g_events_mu);if(g_events.size()>=kMaxEvents)g_events.pop_front();g_events.push_back(o.str());
}
struct Stats{
 std::atomic<uint64_t>tun_in_bytes{0},tun_out_bytes{0},tun_in_pkts{0},tun_out_pkts{0};
 std::atomic<uint64_t>payload_tx{0},payload_rx{0},wire_tx{0},wire_rx{0};
 std::atomic<uint64_t>keepalive_tx{0},keepalive_rx{0},ping_tx{0},ping_rx{0},pong_tx{0},pong_rx{0};
 std::atomic<uint64_t>drop_queue{0},drop_delay{0},drop_malformed{0},auth_fail{0},reconnects{0},replay_drop{0},sequence_gap{0};
 std::atomic<uint64_t>queue_pkts{0},queue_bytes{0},last_rx_age_ms{0};
 std::atomic<bool>degraded{false};
 std::atomic<uint64_t>probe_pending_age_ms{0},reply_timeouts{0},candidate_attempts{0},candidate_failures{0},candidate_successes{0};
 std::atomic<uint64_t>rtt_sample_us{0},rtt_sample_seq{0},padding_extra_tx{0},padding_control_extra_tx{0};
 std::atomic<int64_t>rtt_us{-1},ws_rtt_us{-1};
 std::atomic<uint32_t>tcp_rtt_us{0},tcp_cwnd{0},tcp_unacked{0},tcp_retrans{0};
 std::atomic<uint64_t>ws_messages_tx{0},ws_messages_rx{0},ws_control_tx{0},ws_control_rx{0};
 std::atomic<uint64_t>ws_ping_tx{0},ws_ping_rx{0},ws_pong_tx{0},ws_pong_rx{0},ws_missed_pongs{0},session_renewals{0};
 std::atomic<uint64_t>ws_tx_pending_bytes{0};
 std::atomic<uint64_t>event_loop_delay_us{0},queue_oldest_age_us{0};
 std::atomic<uint64_t>queue_peak_pkts{0},queue_peak_bytes{0},tx_stalls{0},ptt5_sessions{0};
 std::atomic<uint64_t>reconnect_pong_timeout{0},reconnect_tx_timeout{0},reconnect_idle{0},reconnect_session{0},reconnect_network{0},reconnect_manual{0};
 std::atomic<int>adaptive_batch_packets{1};
 std::atomic<std::uint64_t> pool_dials{0},pool_dial_failures{0},pool_failures{0};
 std::atomic<std::uint32_t> pool_active{0};
 RttHistory rtt_history;
 std::atomic<int>carrier_local_family{0},carrier_peer_family{0};
 std::atomic<uint32_t>tcp_total_retrans{0},tcp_snd_mss{0},tcp_pmtu{0};
 std::atomic<uint64_t>payload_tx_rate_bps{0},payload_rx_rate_bps{0};
 std::atomic<uint64_t>latency_renewals{0},reply_renewals{0};
};
struct Queued{std::vector<unsigned char>data;Clock::time_point enqueued;bool payload=false;};
std::pair<std::string,std::string> split_hostport(const std::string&s){
 if(s.empty())throw std::runtime_error("empty host:port");
 if(s.front()=='['){auto rb=s.find(']');if(rb==std::string::npos||rb+1>=s.size()||s[rb+1]!=':'||rb==1||rb+2>=s.size())throw std::runtime_error("expected [ipv6]:port: "+s);return{s.substr(1,rb-1),s.substr(rb+2)};}
 auto p=s.rfind(':');if(p==std::string::npos||p==0||p+1>=s.size()||s.find(':')!=p)throw std::runtime_error("expected host:port (IPv6 must use [addr]:port): "+s);return{s.substr(0,p),s.substr(p+1)};
}
std::string sslerr(){unsigned long e=ERR_get_error();if(!e)return"no OpenSSL error";char b[256]{};ERR_error_string_n(e,b,sizeof(b));return b;}
void update_tcp_info(int fd,Stats&st){
#ifdef TCP_INFO
 tcp_info ti{};socklen_t n=sizeof(ti);if(getsockopt(fd,IPPROTO_TCP,TCP_INFO,&ti,&n)==0){st.tcp_rtt_us=ti.tcpi_rtt;st.tcp_cwnd=ti.tcpi_snd_cwnd;st.tcp_unacked=ti.tcpi_unacked;st.tcp_retrans=ti.tcpi_retransmits;st.tcp_total_retrans=ti.tcpi_total_retrans;st.tcp_snd_mss=ti.tcpi_snd_mss;st.tcp_pmtu=ti.tcpi_pmtu;}
#else
 (void)fd;(void)st;
#endif
}
const char* address_family(int family) {return family==AF_INET6?"IPv6":family==AF_INET?"IPv4":"unavailable";}
void update_socket_family(int fd,Stats& st){
 sockaddr_storage address{};socklen_t size=sizeof(address);
 if(getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size)==0)st.carrier_local_family=address.ss_family;
 size=sizeof(address);
 if(getpeername(fd,reinterpret_cast<sockaddr*>(&address),&size)==0)st.carrier_peer_family=address.ss_family;
}
void set_socket_options(int fd,const Config&c){int one=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&one,sizeof(one));setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&c.sndbuf,sizeof(c.sndbuf));setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&c.rcvbuf,sizeof(c.rcvbuf));
#ifdef TCP_KEEPIDLE
 setsockopt(fd,IPPROTO_TCP,TCP_KEEPIDLE,&c.tcp_keepidle_sec,sizeof(c.tcp_keepidle_sec));
#endif
#ifdef TCP_KEEPINTVL
 setsockopt(fd,IPPROTO_TCP,TCP_KEEPINTVL,&c.tcp_keepintvl_sec,sizeof(c.tcp_keepintvl_sec));
#endif
#ifdef TCP_KEEPCNT
 setsockopt(fd,IPPROTO_TCP,TCP_KEEPCNT,&c.tcp_keepcnt,sizeof(c.tcp_keepcnt));
#endif
#ifdef TCP_USER_TIMEOUT
 setsockopt(fd,IPPROTO_TCP,TCP_USER_TIMEOUT,&c.tcp_user_timeout_ms,sizeof(c.tcp_user_timeout_ms));
#endif
}
int connect_tcp(const std::string& hp, const Config& c) {
  auto [host, port] = split_hostport(hp);
  addrinfo hints{}, *result = nullptr;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = c.address_family=="ipv4"?AF_INET:c.address_family=="ipv6"?AF_INET6:AF_UNSPEC;
  hints.ai_flags = AI_ADDRCONFIG;
  const int gai = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
  if (gai != 0) throw std::runtime_error("DNS resolution failed for " + host + ": " + gai_strerror(gai));
  std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(result, freeaddrinfo);
  std::vector<addrinfo*> candidates;
  for (auto* a = result; a && candidates.size() < 8; a = a->ai_next) {
    if (a->ai_family == AF_INET || a->ai_family == AF_INET6) candidates.push_back(a);
  }
  if (candidates.empty()) throw std::runtime_error("DNS returned no usable TCP addresses for " + host);
  static std::atomic<std::uint64_t> dial_sequence{0};
  const auto dial = c.edge_dns_rotation ? dial_sequence.fetch_add(1, std::memory_order_relaxed) : 0;
  // The new rotation mode allows each of at most three edges its own timeout;
  // never spend unbounded time trying dozens of DNS answers.
  const std::size_t attempts = c.edge_dns_rotation ? std::min<std::size_t>(candidates.size(), 3) : candidates.size();
  const auto overall_deadline = Clock::now() + std::chrono::seconds(
      c.connect_timeout_sec);
  int last_error = ETIMEDOUT;
  for (std::size_t i=0; i<attempts && !g_stop; ++i) {
    const auto idx=edge_address_index(candidates.size(),dial,i,c.edge_dns_rotation);
    auto* address=candidates[idx];
    const auto remaining_ms=std::chrono::duration_cast<std::chrono::milliseconds>(overall_deadline-Clock::now()).count();
    if(remaining_ms<=0)break;
    const auto budget=std::max<long long>(250,remaining_ms/static_cast<long long>(attempts-i));
    const auto deadline=std::min(overall_deadline,Clock::now()+std::chrono::milliseconds(budget));
    int fd=socket(address->ai_family,address->ai_socktype|SOCK_CLOEXEC,address->ai_protocol);
    if(fd<0){last_error=errno;continue;}
    const int flags=fcntl(fd,F_GETFL,0);
    if(flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0){last_error=errno;close(fd);continue;}
    int rc=connect(fd,address->ai_addr,address->ai_addrlen);
    if(rc==0){set_socket_options(fd,c);return fd;}
    if(errno!=EINPROGRESS){last_error=errno;close(fd);continue;}
    bool connected=false;
    last_error=ETIMEDOUT;
    while(!g_stop && Clock::now()<deadline){
      auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
      pollfd pf{fd,POLLOUT,0};
      rc=poll(&pf,1,static_cast<int>(std::min<long long>(remaining,250)));
      if(rc<0 && errno==EINTR)continue;
      if(rc<0){last_error=errno;break;}
      if(rc==0)continue;
      if(pf.revents&POLLNVAL){last_error=EBADF;break;}
      int soerr=0;socklen_t size=sizeof(soerr);
      if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&size)<0){last_error=errno;break;}
      if(soerr==0 && (pf.revents&POLLOUT)){connected=true;break;}
      last_error=soerr?soerr:ECONNRESET;break;
    }
    if(connected){set_socket_options(fd,c);return fd;}
    close(fd);
  }
  if(g_stop)throw std::runtime_error("shutdown requested");
  throw std::runtime_error("TCP connect failed to " + hp + ": " + std::strerror(last_error));
}

int listen_tcp(const std::string&hp,int backlog){
 auto[host,port]=split_hostport(hp);addrinfo h{},*r=nullptr;h.ai_socktype=SOCK_STREAM;h.ai_family=AF_UNSPEC;h.ai_flags=AI_PASSIVE;
 const int gai=getaddrinfo(host=="0.0.0.0"?nullptr:host.c_str(),port.c_str(),&h,&r);
 if(gai!=0)throw std::runtime_error("getaddrinfo failed for listen endpoint: "+std::string(gai_strerror(gai)));
 int fd=-1,last_errno=0;
 for(auto*p=r;p;p=p->ai_next){
   fd=socket(p->ai_family,p->ai_socktype|SOCK_CLOEXEC,p->ai_protocol);if(fd<0){last_errno=errno;continue;}
   int one=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
   if(bind(fd,p->ai_addr,p->ai_addrlen)==0&&listen(fd,backlog)==0)break;
   last_errno=errno;close(fd);fd=-1;
 }
 freeaddrinfo(r);if(fd<0)throw std::runtime_error("listen failed: "+std::string(strerror(last_errno?last_errno:errno)));return fd;
}
void ssl_write_all(SSL*ssl,std::span<const unsigned char>data){size_t off=0;while(off<data.size()&&!g_stop){size_t n=0;int rc=SSL_write_ex(ssl,data.data()+off,data.size()-off,&n);if(rc==1){off+=n;continue;}int e=SSL_get_error(ssl,rc);if(e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE)continue;throw std::runtime_error("TLS write failed: "+sslerr());}}
std::string ssl_read_headers(SSL*ssl){std::string s;char b[2048];while(s.find("\r\n\r\n")==std::string::npos&&!g_stop){if(s.size()>16384)throw std::runtime_error("HTTP headers too large");size_t n=0;int rc=SSL_read_ex(ssl,b,sizeof(b),&n);if(rc==1){s.append(b,n);continue;}int e=SSL_get_error(ssl,rc);if(e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE)continue;throw std::runtime_error("TLS header read failed: "+sslerr());}return s;}
std::string header_value(const std::string&s,const std::string&name){std::string needle="\r\n"+name+":";auto p=s.find(needle);if(p==std::string::npos)return{};p+=needle.size();while(p<s.size()&&(s[p]==' '||s[p]=='\t'))++p;auto e=s.find("\r\n",p);return s.substr(p,e-p);}
SessionKeys client_handshake(SSL*ssl,const Config&cfg,std::span<const unsigned char>psk){auto challenge=ssl_read_headers(ssl);if(challenge.rfind("HTTP/1.1 103",0)!=0)throw std::runtime_error("invalid server challenge");auto snonce=header_value(challenge,"X-PaceTun-Server-Nonce");auto cnonce=random_nonce_hex();auto keys=derive_session_keys(psk,snonce,cnonce);auto token=handshake_token(keys.auth,cfg.server_name,cfg.path,snonce,cnonce);std::string req="CONNECT "+cfg.path+" HTTP/1.1\r\nHost: "+cfg.server_name+"\r\nUser-Agent: pacetun-tls/5.0.2-rc3\r\nX-PaceTun-Client-Nonce: "+cnonce+"\r\nAuthorization: Bearer "+token+"\r\nConnection: keep-alive\r\n\r\n";ssl_write_all(ssl,{reinterpret_cast<const unsigned char*>(req.data()),req.size()});auto r=ssl_read_headers(ssl);if(r.rfind("HTTP/1.1 200",0)!=0)throw std::runtime_error("server rejected tunnel: "+r.substr(0,r.find("\r\n")));g_state=3;event("online role=client");std::cerr<<"[TLS] state=ONLINE role=client wire=PTT3 kdf=HKDF-SHA256 path="<<cfg.path<<"\n";return keys;}
SessionKeys server_handshake(SSL*ssl,const Config&cfg,const std::vector<std::vector<unsigned char>>&psks,Stats&st){auto snonce=random_nonce_hex();std::string challenge="HTTP/1.1 103 PaceTun Challenge\r\nX-PaceTun-Server-Nonce: "+snonce+"\r\nCache-Control: no-store\r\n\r\n";ssl_write_all(ssl,{reinterpret_cast<const unsigned char*>(challenge.data()),challenge.size()});auto r=ssl_read_headers(ssl);auto eol=r.find("\r\n");std::string first=r.substr(0,eol),expect="CONNECT "+cfg.path+" HTTP/1.1",cnonce=header_value(r,"X-PaceTun-Client-Nonce"),auth=header_value(r,"Authorization");SessionKeys keys{};bool matched=false;std::size_t key_index=0;
 for(std::size_t i=0;i<psks.size()&&!matched;i++){try{auto k=derive_session_keys(psks[i],snonce,cnonce);auto want="Bearer "+handshake_token(k.auth,cfg.server_name,cfg.path,snonce,cnonce);if(first==expect&&auth.size()==want.size()&&CRYPTO_memcmp(auth.data(),want.data(),auth.size())==0){keys=k;matched=true;key_index=i;}}catch(...){} }
 if(!matched){st.auth_fail++;event("authentication_failure");std::string resp="HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";ssl_write_all(ssl,{reinterpret_cast<const unsigned char*>(resp.data()),resp.size()});throw std::runtime_error("invalid CONNECT request or challenge response");}
 std::string resp="HTTP/1.1 200 Connection Established\r\nContent-Type: application/octet-stream\r\nX-PaceTun-Wire: PTT3\r\nConnection: keep-alive\r\n\r\n";ssl_write_all(ssl,{reinterpret_cast<const unsigned char*>(resp.data()),resp.size()});g_state=3;event(std::string("online role=server psk=")+(key_index==0?"current":"previous"));std::cerr<<"[TLS] state=ONLINE role=server wire=PTT3 kdf=HKDF-SHA256 psk="<<(key_index==0?"current":"previous")<<" path="<<cfg.path<<"\n";return keys;}
void set_nonblock(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    throw std::runtime_error("set nonblocking failed");
  }
}

void wait_for_ssl_io(SSL* ssl, int ssl_error, int timeout_ms) {
  const int fd = SSL_get_fd(ssl);
  short events = 0;
  if (ssl_error == SSL_ERROR_WANT_READ) events |= POLLIN;
  if (ssl_error == SSL_ERROR_WANT_WRITE) events |= POLLOUT;
  if (events == 0) throw std::runtime_error("unexpected TLS wait state");

  while (!g_stop) {
    pollfd p{fd, events, 0};
    const int rc = poll(&p, 1, std::min(timeout_ms, 250));
    if (rc > 0) {
      if (p.revents & POLLNVAL) throw std::runtime_error("TLS socket invalid during handshake");
      if (p.revents & events) return;
      if (p.revents & (POLLERR | POLLHUP)) throw std::runtime_error("TLS socket closed during handshake");
      continue;
    }
    if (rc < 0 && errno != EINTR) {
      throw std::runtime_error("TLS handshake poll failed");
    }
    timeout_ms -= 250;
    if (timeout_ms <= 0) throw std::runtime_error("TLS handshake timeout");
  }
  throw std::runtime_error("shutdown requested");
}

void ssl_handshake(SSL* ssl, bool server, int timeout_sec) {
  set_nonblock(SSL_get_fd(ssl));
  const auto deadline = Clock::now() + std::chrono::seconds(timeout_sec);
  while (!g_stop) {
    const int rc = server ? SSL_accept(ssl) : SSL_connect(ssl);
    if (rc == 1) return;
    const int e = SSL_get_error(ssl, rc);
    if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
      throw std::runtime_error(std::string(server ? "TLS accept failed: " : "TLS connect failed: ") + sslerr());
    }
    const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    if (remain <= 0) throw std::runtime_error("TLS handshake timeout");
    wait_for_ssl_io(ssl, e, static_cast<int>(remain));
  }
  throw std::runtime_error("shutdown requested");
}

void close_ssl(SSL*& ssl, int& fd) {
  if (ssl != nullptr) {
    SSL_set_quiet_shutdown(ssl, 1);
    SSL_free(ssl);
    ssl = nullptr;
  }
  if (fd >= 0) {
    shutdown(fd, SHUT_RDWR);
    close(fd);
    fd = -1;
  }
}
std::array<unsigned char,8> encode_u64(uint64_t v){std::array<unsigned char,8>b{};for(int i=7;i>=0;--i){b[i]=v&0xff;v>>=8;}return b;}uint64_t decode_u64(std::span<const unsigned char>b){uint64_t v=0;for(auto x:b)v=(v<<8)|x;return v;}uint64_t mono_us(){return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count();}
void enqueue(std::deque<Queued>& q, size_t& qb, Queued x, const Config& cfg, Stats& st, bool protect_front=false) {
  if (x.data.size() > cfg.queue_bytes) { ++st.drop_queue; return; }
  while (!q.empty() && (q.size() >= cfg.queue_packets || qb + x.data.size() > cfg.queue_bytes)) {
    if (protect_front) {
      ++st.drop_queue;
      return;
    }
    qb -= q.front().data.size();
    q.pop_front();
    ++st.drop_queue;
  }
  qb += x.data.size();
  q.push_back(std::move(x));
  st.queue_pkts=q.size(); st.queue_bytes=qb;
  st.queue_peak_pkts.store(std::max<uint64_t>(st.queue_peak_pkts.load(),q.size()));
  st.queue_peak_bytes.store(std::max<uint64_t>(st.queue_peak_bytes.load(),qb));
}

int effective_batch_packets(const std::deque<Queued>&q,const Config&cfg,Stats&st,Clock::time_point now){
  if(!cfg.adaptive_batching){st.adaptive_batch_packets=cfg.batch_packets;return cfg.batch_packets;}
  int chosen=cfg.adaptive_batch_min_packets;
  if(!q.empty()){
    const auto age=std::chrono::duration_cast<std::chrono::milliseconds>(now-q.front().enqueued).count();
    const auto depth=static_cast<int>(std::min<std::size_t>(q.size(),64));
    const int span=cfg.adaptive_batch_max_packets-cfg.adaptive_batch_min_packets;
    chosen=cfg.adaptive_batch_min_packets+(span*depth)/64;
    if(age>=cfg.queue_target_delay_ms)chosen=cfg.adaptive_batch_max_packets;
    else if(age<cfg.queue_target_delay_ms/4&&q.size()<=4)chosen=cfg.adaptive_batch_min_packets;
  }
  chosen=std::clamp(chosen,cfg.adaptive_batch_min_packets,cfg.adaptive_batch_max_packets);
  st.adaptive_batch_packets=chosen;return chosen;
}

const char* failure_code(int phase,const std::string& reason){
 if(contains_insensitive(reason,"HTTP/1.1 502")||contains_insensitive(reason,"502 Bad Gateway"))return "HTTP_502_GATEWAY";
 if(contains_insensitive(reason,"HTTP/1.1 504")||contains_insensitive(reason,"504 Gateway"))return "HTTP_504_TIMEOUT";
 if(contains_insensitive(reason,"DNS resolution failed")||contains_insensitive(reason,"DNS returned no usable"))return "DNS_RESOLUTION_FAILED";
 if(contains_insensitive(reason,"certificate verify")||contains_insensitive(reason,"certificate has expired")||contains_insensitive(reason,"hostname mismatch"))return "TLS_CERTIFICATE_FAILED";
 if(contains_insensitive(reason,"TCP connect failed")&&contains_insensitive(reason,"timed out"))return "TCP_CONNECT_TIMEOUT";
 if(contains_insensitive(reason,"TLS handshake timeout"))return "TLS_HANDSHAKE_TIMEOUT";
 if(reason.find("authenticated probe reply timeout")!=std::string::npos)return "AUTH_PROBE_TIMEOUT";
 if(reason.find("control requested reconnect")!=std::string::npos)return "MANUAL_RECONNECT";
 if(reason.find("carrier PONG timeout")!=std::string::npos)return "WEBSOCKET_PONG_TIMEOUT";
 if(reason.find("WebSocket peer close received")!=std::string::npos)return "WEBSOCKET_PEER_CLOSE";
 if(reason.find("authentication")!=std::string::npos||reason.find("key confirmation")!=std::string::npos)return "AUTHENTICATION_FAILED";
 if(reason.find("WebSocket upgrade")!=std::string::npos)return "WEBSOCKET_UPGRADE_FAILED";
 if(phase==3)return "TCP_CONNECT_FAILED";
 if(phase==4)return "TLS_HANDSHAKE_FAILED";
 if(phase==5)return "CARRIER_UPGRADE_FAILED";
 return "ESTABLISHED_CONNECTION_LOST";
}

void classify_reconnect(const std::string&reason,Stats&st){
  if(reason.find("authenticated probe reply timeout")!=std::string::npos)return; // counted by reply_timeouts
  if(reason.find("PONG timeout")!=std::string::npos)++st.reconnect_pong_timeout;
  else if(reason.find("TX no-progress timeout")!=std::string::npos){++st.reconnect_tx_timeout;++st.tx_stalls;}
  else if(reason.find("idle timeout")!=std::string::npos)++st.reconnect_idle;
  else if(reason.find("session max age")!=std::string::npos)++st.reconnect_session;
  else if(reason.find("control requested reconnect")!=std::string::npos)++st.reconnect_manual;
  else ++st.reconnect_network;
}
void tunnel_loop(SSL* ssl, TunDevice& tun, const Config& cfg, Stats& st,
                 std::span<const unsigned char> tx_key,
                 std::span<const unsigned char> rx_key) {
  const int fd = SSL_get_fd(ssl);
  set_nonblock(fd);

  RecordDecoder dec(rx_key, cfg.max_record_buffer_bytes);
  std::deque<Queued> q;
  std::size_t queued_bytes = 0;
  std::size_t front_offset = 0;
  std::vector<unsigned char> read_buffer(65536);
  std::vector<unsigned char> tun_buffer(cfg.mtu + 256);
  uint64_t sequence = 1;
  auto last_rx = Clock::now();
  auto last_tx = Clock::now();
  auto last_probe = Clock::now();
  auto last_tcp_info = Clock::now();

  auto enqueue_control = [&](uint8_t flags, std::span<const unsigned char> payload) {
    auto record = encode_record(tx_key, sequence++, payload, flags);
    enqueue(q, queued_bytes, {std::move(record), Clock::now(), false}, cfg, st, front_offset > 0);
  };

  auto flush_tls = [&]() {
    int sent_records = 0;
    std::size_t sent_bytes = 0;
    while (!q.empty() && sent_records < std::max(1, cfg.batch_packets) &&
           sent_bytes < static_cast<std::size_t>(std::max<std::size_t>(1, cfg.batch_bytes))) {
      auto& item = q.front();
      std::size_t written = 0;
      const int rc = SSL_write_ex(ssl, item.data.data() + front_offset,
                                  item.data.size() - front_offset, &written);
      if (rc == 1 && written > 0) {
        front_offset += written;
        sent_bytes += written;
        st.wire_tx += written;
        last_tx = Clock::now();
        if (front_offset == item.data.size()) {
          queued_bytes -= item.data.size();
          q.pop_front();
          front_offset = 0;
          ++sent_records;
          st.queue_pkts = q.size();
          st.queue_bytes = queued_bytes;
        }
        continue;
      }
      const int e = SSL_get_error(ssl, rc);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return;
      if (e == SSL_ERROR_ZERO_RETURN) throw std::runtime_error("TLS peer closed");
      throw std::runtime_error("TLS write failed: " + sslerr());
    }
  };

  while (!g_stop) {
    if (g_force_disconnect.exchange(false)) {
      throw std::runtime_error("control requested reconnect");
    }

    auto now = Clock::now();
    while (!q.empty() && front_offset == 0 &&
           std::chrono::duration_cast<std::chrono::milliseconds>(now - q.front().enqueued).count() > cfg.queue_delay_ms) {
      queued_bytes -= q.front().data.size();
      q.pop_front();
      front_offset = 0;
      ++st.drop_delay;
      event("queue_delay_drop");
    }
    st.queue_pkts = q.size();
    st.queue_bytes = queued_bytes;
    st.last_rx_age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rx).count();

    short socket_events = POLLIN;
    if (!q.empty()) socket_events |= POLLOUT;
    pollfd pfds[2] = {{fd, socket_events, 0}, {tun.poll_fd(), POLLIN, 0}};
    const int poll_timeout_ms = q.empty() ? std::min(10, std::max(1, cfg.websocket_poll_ms)) : 0;
    const int poll_rc = poll(pfds, 2, poll_timeout_ms);
    if (poll_rc < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error("poll failed");
    }

    if (pfds[1].revents & POLLIN) {
      for (int reads = 0; reads < std::max(1, cfg.batch_packets); ++reads) {
        const ssize_t n = tun.read_packet({tun_buffer.data(), tun_buffer.size()});
        if (n > 0) {
          st.tun_in_bytes += static_cast<uint64_t>(n);
          ++st.tun_in_pkts;
          auto record = encode_record(tx_key, sequence++,
                                      {tun_buffer.data(), static_cast<std::size_t>(n)});
          st.payload_tx += static_cast<uint64_t>(n);
          enqueue(q, queued_bytes, {std::move(record), Clock::now(), true}, cfg, st, front_offset > 0);
          continue;
        }
        if (n < 0 && errno == EINTR) {
          if (g_stop) break;
          --reads;
          continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n == 0) throw std::runtime_error("TUN closed");
        throw std::runtime_error("TUN read failed: " + std::string(strerror(errno)));
      }
    }

    if ((pfds[0].revents & POLLIN) || SSL_pending(ssl) > 0) {
      while (true) {
        std::size_t n = 0;
        const int rc = SSL_read_ex(ssl, read_buffer.data(), read_buffer.size(), &n);
        if (rc == 1 && n > 0) {
          last_rx = Clock::now();
          st.wire_rx += n;
          std::string error;
          const auto old_replay = dec.replay_drops();
          const auto old_gaps = dec.sequence_gaps();
          if (!dec.feed({read_buffer.data(), n},
                        [&](uint8_t flags, uint64_t, std::span<const unsigned char> payload) {
                          if (flags == 0) {
                            if (tun.write_packet(payload) ==
                                static_cast<ssize_t>(payload.size())) {
                              st.tun_out_bytes += payload.size();
                              ++st.tun_out_pkts;
                              st.payload_rx += payload.size();
                            } else {
                              ++st.drop_malformed;
                            }
                          } else if (flags & RECORD_KEEPALIVE) {
                            ++st.keepalive_rx;
                          } else if (flags & RECORD_PING) {
                            ++st.ping_rx;
                            enqueue_control(RECORD_PONG, payload);
                            ++st.pong_tx;
                          } else if (flags & RECORD_PONG) {
                            ++st.pong_rx;
                            if (payload.size() == 8) {
                              const uint64_t sent = decode_u64(payload);
                              const uint64_t current = mono_us();
                              if (current >= sent) st.rtt_us = static_cast<int64_t>(current - sent);
                            }
                          }
                        }, error)) {
            st.replay_drop += dec.replay_drops() - old_replay;
            st.sequence_gap += dec.sequence_gaps() - old_gaps;
            if (error.find("authentication") != std::string::npos) ++st.auth_fail;
            else if (error.find("replay") == std::string::npos) ++st.drop_malformed;
            event("decoder_error " + error);
            throw std::runtime_error(error);
          }
          st.sequence_gap += dec.sequence_gaps() - old_gaps;
          continue;
        }
        const int e = SSL_get_error(ssl, rc);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) break;
        if (e == SSL_ERROR_ZERO_RETURN) throw std::runtime_error("TLS peer closed");
        throw std::runtime_error("TLS read failed: " + sslerr());
      }
    }

    now = Clock::now();
    if (cfg.rtt_probe_sec > 0 && std::chrono::duration_cast<std::chrono::seconds>(now - last_probe).count() >= cfg.rtt_probe_sec) {
      const auto encoded = encode_u64(mono_us());
      enqueue_control(RECORD_PING, encoded);
      ++st.ping_tx;
      last_probe = now;
    }
    if (cfg.keepalive_sec > 0 && q.empty() &&
        std::chrono::duration_cast<std::chrono::seconds>(now - last_tx).count() >= cfg.keepalive_sec) {
      enqueue_control(RECORD_KEEPALIVE, {});
      ++st.keepalive_tx;
    }

    if (!q.empty()) flush_tls();

    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_tcp_info).count() >= 1) {
      update_tcp_info(fd, st);
      last_tcp_info = now;
    }
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_rx).count() > cfg.idle_timeout_sec) {
      throw std::runtime_error("idle timeout");
    }
    if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
      throw std::runtime_error("TLS socket closed");
    }
  }
}


void carrier_tunnel_loop(Carrier& carrier, TunDevice& tun, const Config& cfg, Stats& st,
                         std::span<const unsigned char> tx_key,
                         std::span<const unsigned char> rx_key, const std::function<void()>& tick = {}) {
  const int carrier_fd=carrier.native_fd();
  set_nonblock(carrier_fd);
  update_socket_family(carrier_fd,st);
  RecordDecoderV5 dec(rx_key, cfg.max_record_buffer_bytes);
  std::deque<Queued> q;
  std::size_t queued_bytes = 0;
  FlowQueue pending_packets; 
  std::vector<unsigned char> tun_buffer(cfg.mtu + 256);
  uint64_t sequence = 1;
  auto last_rx = Clock::now();
  auto last_tx = Clock::now();
  auto last_probe = Clock::now();
  auto last_payload = Clock::now()-std::chrono::seconds(61);
  auto last_carrier_ping = Clock::now();
  auto last_tcp_info = Clock::now();
  auto session_started = Clock::now();

  std::mt19937 timing_rng(std::random_device{}());
  int keepalive_interval=traffic_interval_ms(cfg.keepalive_sec,cfg.timing_jitter_pct,timing_rng);
  int probe_interval=traffic_interval_ms(cfg.rtt_probe_sec,cfg.timing_jitter_pct,timing_rng);
  ShapeBudget shape_budget(cfg.traffic_shaping,cfg.shaping_rate_bytes,cfg.shaping_burst_bytes,mono_us());
  BurstShaper shaper(mono_us());
  PaddingBudget padding(cfg.padding_budget_pct,mono_us());
  st.rtt_us=-1;st.rtt_sample_us=0;st.ws_rtt_us=-1;st.rtt_history.reset();
  st.degraded=false;st.probe_pending_age_ms=0;st.last_rx_age_ms=0;
  ReplyWatchdog watchdog;
  probe_interval=traffic_interval_ms(std::clamp(cfg.rtt_probe_sec,5,20),cfg.timing_jitter_pct,timing_rng);
  auto encode = [&](std::span<const unsigned char> payload,uint8_t flags){
    const bool control=flags!=0;
    if(!control)shaper.observe(payload.size(),mono_us());
    int maximum=control?cfg.websocket_control_padding_bytes:cfg.websocket_padding_max_bytes;
    if(cfg.traffic_shaping&&!control)maximum=shaper.maximum(maximum,cfg.shaping_startup_ms,mono_us());
    int allowance=control?padding.control_allowance(maximum,mono_us()):padding.data_allowance(payload.size(),maximum);
    allowance=shape_budget.allowance(allowance,mono_us());
    std::vector<unsigned char> record;
    if(maximum>0 && allowance>=3){
      if(cfg.websocket_control_padding_bytes>0)record=encode_envelope_record_v5(tx_key,sequence++,payload,flags,allowance-3);
      else record=encode_padded_record_v5(tx_key,sequence++,payload,allowance-3);
    }else record=encode_record_v5(tx_key,sequence++,payload,flags);
    const size_t extra=record.size()-32-payload.size();
    shape_budget.spend(extra);
    if(control){padding.spend_control(extra);st.padding_control_extra_tx+=extra;}else{padding.spend_data(extra);st.padding_extra_tx+=extra;}
    return record;
  };
  auto seen=carrier.counters();
  bool carrier_ping_queued = false;
  bool carrier_ping_outstanding = false;
  std::array<unsigned char,8> carrier_ping_payload{};
  auto carrier_ping_sent_at = Clock::now();

  auto enqueue_control = [&](uint8_t flags, std::span<const unsigned char> payload) {
    auto record = encode(payload,flags);
    enqueue(q, queued_bytes, {std::move(record), Clock::now(), false}, cfg, st);
  };

  auto sync_carrier_tx = [&]() {
    const auto cur=carrier.counters();
    if (cur.tx_messages != seen.tx_messages) {
      st.ws_messages_tx += cur.tx_messages - seen.tx_messages;
      last_tx = Clock::now();
    }
    if (cur.tx_payload_bytes != seen.tx_payload_bytes) st.wire_tx += cur.tx_payload_bytes - seen.tx_payload_bytes;
    if (cur.tx_ping_frames != seen.tx_ping_frames) {
      const uint64_t delta = cur.tx_ping_frames - seen.tx_ping_frames;
      st.ws_ping_tx += delta;st.ws_control_tx += delta;
      if (carrier_ping_queued) {
        carrier_ping_queued = false;
        carrier_ping_outstanding = true;
        carrier_ping_sent_at = Clock::now();
      }
    }
    if (cur.tx_pong_frames != seen.tx_pong_frames) {
      const uint64_t delta = cur.tx_pong_frames - seen.tx_pong_frames;
      st.ws_pong_tx += delta;st.ws_control_tx += delta;
    }
    seen=cur;
    st.ws_tx_pending_bytes = carrier.tx_pending_bytes();
  };

  auto flush_transport = [&]() {
    carrier.flush(256 * 1024);
    sync_carrier_tx();
    if (carrier.tx_stalled(cfg.websocket_io_timeout_sec * 1000)) {
      throw std::runtime_error("carrier TX no-progress timeout");
    }
  };

  auto flush_carrier = [&]() {
    flush_transport();
    if (carrier.tx_pending() || q.empty()) return;
    if(cfg.traffic_shaping && std::all_of(q.begin(),q.end(),[](const Queued& p){return p.payload;}) &&
       !shaper.ready(q.size(),std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-q.front().enqueued).count(),cfg.shaping_delay_ms,mono_us())) return;

    std::vector<unsigned char> message;
    const int limit=effective_batch_packets(q,cfg,st,Clock::now());
    int count = 0;
    while (!q.empty() && count < std::max(1, limit) &&
           message.size() + q.front().data.size() <= cfg.batch_bytes) {
      message.insert(message.end(), q.front().data.begin(), q.front().data.end());
      queued_bytes -= q.front().data.size();
      q.pop_front();
      ++count;
    }
    if (!message.empty()) {
      carrier.send(message);
      st.queue_pkts = q.size();st.queue_bytes = queued_bytes;
      flush_transport();
    }
  };

  auto drain_pending = [&] {
    if (!cfg.flow_scheduler || pending_packets.empty()) return;
    if (carrier.tx_pending() && queued_bytes > cfg.batch_bytes * 2) return;
    const int budget = std::max(1, cfg.batch_packets);
    for (int i=0; i<budget && !pending_packets.empty(); ++i) {
      if (q.size()+pending_packets.packets() >= cfg.queue_packets && queued_bytes >= cfg.queue_bytes/2) break;
      auto item=pending_packets.pop();
      if (item.bytes.empty()) break;
      auto rec=encode(item.bytes,0);
      enqueue(q,queued_bytes,{std::move(rec),Clock::now(),true},cfg,st);
    }
    st.queue_pkts=q.size()+pending_packets.packets();
    st.queue_bytes=queued_bytes+pending_packets.bytes();
    st.queue_peak_pkts.store(std::max<uint64_t>(st.queue_peak_pkts.load(),st.queue_pkts.load()));
    st.queue_peak_bytes.store(std::max<uint64_t>(st.queue_peak_bytes.load(),st.queue_bytes.load()));
  };

  while (!g_stop) {
    const auto pending_ms=watchdog.age_us(mono_us())/1000;
    st.probe_pending_age_ms=pending_ms;
    bool degraded=pending_ms>=uint64_t(cfg.reply_degraded_sec)*1000;
    if(st.degraded.exchange(degraded)!=degraded)
      std::cerr<<(degraded?"[DEGRADED] authenticated probe overdue; reply watchdog active\n":"[RECOVERED] authenticated probe replies resumed\n");
    if(tick)tick();
    if(pending_ms>=uint64_t(cfg.reply_timeout_sec)*1000){
      ++st.reply_timeouts;throw std::runtime_error("authenticated probe reply timeout");
    }
    if (g_force_disconnect.exchange(false)) throw std::runtime_error("control requested reconnect");
    auto loop_started = Clock::now();
    auto now = loop_started;

    while (!q.empty() &&
           std::chrono::duration_cast<std::chrono::milliseconds>(now-q.front().enqueued).count() > cfg.queue_delay_ms) {
      queued_bytes -= q.front().data.size();q.pop_front();++st.drop_delay;event("queue_delay_drop");
    }
    if(cfg.flow_scheduler) {
      const auto expired=pending_packets.drop_expired(mono_us(),uint64_t(cfg.queue_delay_ms)*1000);
      if(expired) {st.drop_delay+=expired;event("plaintext_flow_queue_delay_drop");}
    }
    st.queue_pkts=q.size()+pending_packets.packets();st.queue_bytes=queued_bytes+pending_packets.bytes();
    st.queue_oldest_age_us = q.empty() ? 0 : std::chrono::duration_cast<std::chrono::microseconds>(now-q.front().enqueued).count();
    st.last_rx_age_ms=std::chrono::duration_cast<std::chrono::milliseconds>(now-last_rx).count();
    effective_batch_packets(q,cfg,st,now);

    flush_transport();
    drain_pending();
    flush_carrier();
    const bool tx_pending = carrier.tx_pending();
    const int timeout_ms = ((!q.empty() || !pending_packets.empty()) && !tx_pending) ? (cfg.traffic_shaping?1:0) : cfg.websocket_poll_ms;
    const short socket_events = static_cast<short>(carrier.rx_poll_events() | carrier.tx_poll_events());
    pollfd p[2]={{carrier_fd,socket_events,0},{tun.poll_fd(),POLLIN,0}};
    int pr=poll(p,2,timeout_ms);if(pr<0){if(errno==EINTR)continue;throw std::runtime_error("poll failed");}
    auto after_poll=Clock::now();
    st.event_loop_delay_us=std::chrono::duration_cast<std::chrono::microseconds>(after_poll-loop_started).count();

    if (p[0].revents & (POLLIN|POLLOUT)) flush_transport();

    if(p[1].revents&POLLIN){
      const int read_budget=cfg.adaptive_batching?cfg.adaptive_batch_max_packets:std::max(1,cfg.batch_packets);
      std::vector<std::vector<unsigned char>> burst;
      burst.reserve(static_cast<std::size_t>(std::max(1,read_budget)));
      for(int i=0;i<std::max(1,read_budget);++i){
        ssize_t n=tun.read_packet({tun_buffer.data(),tun_buffer.size()});
        if(n>0){
          last_payload=Clock::now();st.tun_in_bytes+=n;++st.tun_in_pkts;
          st.payload_tx+=n;
          burst.emplace_back(tun_buffer.begin(),tun_buffer.begin()+n);
          continue;
        }
        if(n<0&&errno==EINTR){if(g_stop)break;--i;continue;}
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(n==0)throw std::runtime_error("TUN closed");
        throw std::runtime_error("TUN read failed");
      }
      if (cfg.flow_scheduler) {
        for(auto& packet : burst) {
          const size_t overhead=64; 
          const bool room=(q.size()+pending_packets.packets()<cfg.queue_packets) &&
            packet.size()+overhead<=cfg.queue_bytes &&
            queued_bytes+pending_packets.bytes()<=cfg.queue_bytes-packet.size()-overhead;
          if (!room || !pending_packets.push(std::move(packet),mono_us(),cfg.queue_packets,cfg.queue_bytes)) {
            ++st.drop_queue;
          }
        }
        drain_pending();
      } else {
        for(auto& packet : burst) {
          auto rec=encode(packet,0);
          enqueue(q,queued_bytes,{std::move(rec),Clock::now(),true},cfg,st);
        }
      }
      flush_carrier();
    }

    const auto before=carrier.counters();
    auto messages=carrier.read(0);
    const auto after=carrier.counters();
    if(after.rx_frames!=before.rx_frames)last_rx=Clock::now();
    st.ws_ping_rx += after.rx_ping_frames-before.rx_ping_frames;
    st.ws_pong_rx += after.rx_pong_frames-before.rx_pong_frames;
    st.ws_control_rx += (after.rx_ping_frames-before.rx_ping_frames)+(after.rx_pong_frames-before.rx_pong_frames);
    seen.rx_frames=after.rx_frames;seen.rx_ping_frames=after.rx_ping_frames;seen.rx_pong_frames=after.rx_pong_frames;

    for (auto& pong : carrier.take_pongs()) {
      if (carrier_ping_outstanding && pong.size()==carrier_ping_payload.size() &&
          std::equal(pong.begin(),pong.end(),carrier_ping_payload.begin())) {
        const auto sent=decode_u64(pong);const auto cur=mono_us();
        if(cur>=sent)st.ws_rtt_us=static_cast<int64_t>(cur-sent);
        carrier_ping_outstanding=false;
      }
    }

    for(auto&msg:messages){
      ++st.ws_messages_rx;st.wire_rx+=msg.size();std::string error;auto oldr=dec.replay_drops(),oldg=dec.sequence_gaps();
      bool control_generated=false;
      if(!dec.feed(msg,[&](uint8_t flags,uint64_t,std::span<const unsigned char> payload){
        if(flags==0){last_payload=Clock::now();ssize_t n=tun.write_packet(payload);if(n==static_cast<ssize_t>(payload.size())){st.tun_out_bytes+=payload.size();++st.tun_out_pkts;st.payload_rx+=payload.size();}else ++st.drop_malformed;}
        else if(flags&RECORD_KEEPALIVE){++st.keepalive_rx;++st.ws_control_rx;}
        else if(flags&RECORD_PING){++st.ping_rx;++st.ws_control_rx;enqueue_control(RECORD_PONG,payload);++st.pong_tx;++st.ws_control_tx;control_generated=true;}
        else if(flags&RECORD_PONG){++st.pong_rx;++st.ws_control_rx;if(payload.size()==8){auto sent=decode_u64(payload);auto cur=mono_us();if(watchdog.reply(sent,cur)){st.rtt_us=static_cast<int64_t>(cur-sent);st.rtt_sample_us=cur;st.rtt_history.record(cur-sent,Clock::now()-last_payload<=std::chrono::seconds(60));++st.rtt_sample_seq;}}}
      },error)){
        st.replay_drop+=dec.replay_drops()-oldr;st.sequence_gap+=dec.sequence_gaps()-oldg;
        if(error.find("authentication")!=std::string::npos)++st.auth_fail;else ++st.drop_malformed;
        throw std::runtime_error(error);
      }
      st.sequence_gap+=dec.sequence_gaps()-oldg;
      if(control_generated)flush_carrier();
    }

    flush_transport();
    now=Clock::now();

    if(!watchdog.pending()&&std::chrono::duration_cast<std::chrono::milliseconds>(now-last_probe).count()>=probe_interval){
      auto token=mono_us();watchdog.sent(token);auto b=encode_u64(token);
      enqueue_control(RECORD_PING,b);++st.ping_tx;++st.ws_control_tx;last_probe=now;
      int seconds=(cfg.idle_probe_sec>0 && now-last_payload>std::chrono::seconds(60))?std::max(cfg.idle_probe_sec,cfg.rtt_probe_sec):cfg.rtt_probe_sec;
      probe_interval=traffic_interval_ms(std::clamp(seconds,5,20),cfg.timing_jitter_pct,timing_rng);flush_carrier();
    }

    if (cfg.websocket_ping_sec>0 && !carrier_ping_queued && !carrier_ping_outstanding &&
        std::chrono::duration_cast<std::chrono::seconds>(now-last_carrier_ping).count()>=cfg.websocket_ping_sec) {
      const auto b=encode_u64(mono_us());std::copy(b.begin(),b.end(),carrier_ping_payload.begin());
      carrier.send_ping(b);carrier_ping_queued=true;last_carrier_ping=now;flush_transport();
    }

    if (carrier_ping_outstanding && cfg.websocket_pong_timeout_sec>0 &&
        std::chrono::duration_cast<std::chrono::seconds>(now-carrier_ping_sent_at).count()>=cfg.websocket_pong_timeout_sec) {
      ++st.ws_missed_pongs;event("carrier_pong_timeout");throw std::runtime_error("carrier PONG timeout");
    }
    if (carrier_ping_outstanding && cfg.websocket_pong_timeout_sec==0 &&
        std::chrono::duration_cast<std::chrono::seconds>(now-carrier_ping_sent_at).count()>=cfg.websocket_ping_sec) carrier_ping_outstanding=false;

    if(cfg.keepalive_sec>0&&q.empty()&&pending_packets.empty()&&!carrier.tx_pending()&&
       std::chrono::duration_cast<std::chrono::milliseconds>(now-last_tx).count()>=keepalive_interval){enqueue_control(RECORD_KEEPALIVE,{});keepalive_interval=traffic_interval_ms(cfg.keepalive_sec,cfg.timing_jitter_pct,timing_rng);++st.keepalive_tx;++st.ws_control_tx;flush_carrier();}
    if(cfg.flow_scheduler)drain_pending();
    if(!q.empty())flush_carrier();
    if(std::chrono::duration_cast<std::chrono::seconds>(now-last_tcp_info).count()>=1){update_tcp_info(carrier_fd,st);last_tcp_info=now;}
    if(cfg.session_max_age_sec>0&&std::chrono::duration_cast<std::chrono::seconds>(now-session_started).count()>=cfg.session_max_age_sec){++st.session_renewals;event("carrier_session_renewal");throw std::runtime_error("session max age reached");}
    if(std::chrono::duration_cast<std::chrono::seconds>(now-last_rx).count()>cfg.idle_timeout_sec)throw std::runtime_error("idle timeout");
    if(p[0].revents&(POLLERR|POLLHUP|POLLNVAL))throw std::runtime_error("carrier closed");
  }
}


void log_certificate(const std::string&path){FILE*f=fopen(path.c_str(),"r");if(!f)return;X509*x=PEM_read_X509(f,nullptr,nullptr,nullptr);fclose(f);if(!x)return;char subj[512]{};X509_NAME_oneline(X509_get_subject_name(x),subj,sizeof(subj));int days=-1;const ASN1_TIME*na=X509_get0_notAfter(x);int d=0,s=0;if(ASN1_TIME_diff(&d,&s,nullptr,na)==1)days=d+(s>0?1:0);std::cerr<<"[CERT] subject="<<subj<<" days_remaining="<<days<<(days>=0&&days<=30?" warning=expiring":"")<<"\n";if(days>=0&&days<=30)event("certificate_expiring days="+std::to_string(days));X509_free(x);}
SSL_CTX*server_ctx(const Config&c){
 auto*x=SSL_CTX_new(TLS_server_method());if(!x)throw std::runtime_error("SSL_CTX_new failed");
 SSL_CTX_set_min_proto_version(x,TLS1_3_VERSION);SSL_CTX_set_max_proto_version(x,TLS1_3_VERSION);
 if(SSL_CTX_use_certificate_chain_file(x,c.tls_cert.c_str())!=1||SSL_CTX_use_PrivateKey_file(x,c.tls_key.c_str(),SSL_FILETYPE_PEM)!=1||SSL_CTX_check_private_key(x)!=1){auto e=sslerr();SSL_CTX_free(x);throw std::runtime_error("load certificate/key failed: "+e);}
 log_certificate(c.tls_cert);return x;
}
SSL_CTX*client_ctx(const Config&c){
 auto*x=SSL_CTX_new(TLS_client_method());if(!x)throw std::runtime_error("SSL_CTX_new failed");
 const int min_tls=(c.transport=="websocket")?TLS1_2_VERSION:TLS1_3_VERSION;
 if(SSL_CTX_set_min_proto_version(x,min_tls)!=1||SSL_CTX_set_max_proto_version(x,TLS1_3_VERSION)!=1){auto e=sslerr();SSL_CTX_free(x);throw std::runtime_error("configure TLS versions failed: "+e);}
 SSL_CTX_set_session_cache_mode(x,SSL_SESS_CACHE_CLIENT);
 if(c.transport=="websocket"){
   static const unsigned char alpn_http11[]={8,'h','t','t','p','/','1','.','1'};
   if(SSL_CTX_set_alpn_protos(x,alpn_http11,sizeof(alpn_http11))!=0){SSL_CTX_free(x);throw std::runtime_error("configure WSS ALPN failed");}
 }
 if(c.verify_peer){SSL_CTX_set_verify(x,SSL_VERIFY_PEER,nullptr);if(SSL_CTX_load_verify_locations(x,c.tls_ca.c_str(),nullptr)!=1){auto e=sslerr();SSL_CTX_free(x);throw std::runtime_error("load tls_ca failed: "+e);}}else SSL_CTX_set_verify(x,SSL_VERIFY_NONE,nullptr);
 return x;
}
std::string readable_status(const Stats&s,const Config&cfg){
  std::ostringstream o;o<<"["<<(g_state.load()==3&&s.degraded.load()?"DEGRADED":state_name(g_state.load()))<<"] role="<<(cfg.mode=="client"?"iran-client":"foreign-server")<<" | phase="<<phase_name(g_phase.load());
  auto sample=s.rtt_sample_us.load();auto r=s.rtt_us.load();
  if(g_state.load()==3&&sample&&r>=0)o<<" | tunnel_rtt_last="<<std::fixed<<std::setprecision(1)<<r/1000.0<<"ms (sample_age="<<(mono_us()-sample)/1000000<<"s, "<<((mono_us()-sample>30000000||s.degraded.load())?"stale":"fresh")<<")";
  else o<<" | tunnel_rtt=unavailable";
  if(g_state.load()==3){
    if(cfg.mode=="client" && cfg.tls_backend=="utls")o<<" | cdn_next_hop_tcp_rtt=unavailable(sidecar)";
    else o<<" | "<<(cfg.mode=="server"?"local_nginx_tcp_rtt=":"cdn_next_hop_tcp_rtt=")<<s.tcp_rtt_us.load()/1000.0<<"ms";
  }
  auto hist=s.rtt_history.snapshot();
  o<<" | rtt_samples="<<hist.count<<" rtt_p50="<<hist.p50_ms<<"ms rtt_p95="<<hist.p95_ms<<"ms rtt_p99="<<hist.p99_ms<<"ms";
  o<<" | carrier_local_family="<<address_family(s.carrier_local_family.load())<<" carrier_peer_family="<<address_family(s.carrier_peer_family.load());
  o<<" | authenticated_probe=enabled pending_age="<<s.probe_pending_age_ms.load()/1000<<"s";
  if(cfg.max_connections>1)o<<" | pool="<<s.pool_active.load()<<"/"<<cfg.max_connections;
  o<<" | ws_probe="<<(cfg.websocket_ping_sec>0?"enabled":"disabled")<<" | queue="<<s.queue_pkts.load()<<" packets/"<<s.queue_bytes.load()<<"B";
  o<<" | drops_total="<<s.drop_queue.load()+s.drop_delay.load()+s.drop_malformed.load()<<" | reconnects_total="<<s.reconnects.load()<<" | auth_errors_total="<<s.auth_fail.load();
  return o.str();
}
std::string overview_text(const Stats&s,const Config&cfg){
  const bool online=g_state.load()==3;
  std::ostringstream o;
  o<<"Connection: "<<(online?(s.degraded.load()?"DEGRADED (online but probe replies are overdue)":"ONLINE (authenticated)"):
                           g_state.load()==1?"WAITING for client":g_state.load()==2?"CONNECTING":g_state.load()==4?"RECONNECTING":"NOT ONLINE")<<"\n";
  o<<"Role: "<<(cfg.mode=="client"?"Iran client":"Foreign server")<<" | Stage: "<<phase_name(g_phase.load())<<"\n";
  const auto sample=s.rtt_sample_us.load(); const auto rtt=s.rtt_us.load();
  const auto age=sample?((mono_us()-sample)/1000000):0;
  if(online&&sample&&rtt>=0&&age<=30&&!s.degraded.load())
    o<<"Tunnel round-trip: "<<std::fixed<<std::setprecision(1)<<rtt/1000.0<<" ms (verified "<<age<<" s ago)\n";
  else o<<"Tunnel round-trip: unavailable or outdated (do not interpret this as 0 ms)\n";
  const auto hist=s.rtt_history.snapshot();
  if(hist.count>=5)o<<"Recent verified RTT: median "<<hist.p50_ms<<" ms; 95th percentile "<<hist.p95_ms<<" ms ("<<hist.count<<" samples)\n";
  else o<<"RTT trend: waiting for at least 5 authenticated measurements ("<<hist.count<<" so far)\n";
  if(online && cfg.mode=="client" && cfg.tls_backend=="utls")
    o<<"CDN TCP RTT: unavailable (TLS handled by the optional uTLS sidecar)\n";
  else if(online) {
    o<<(cfg.mode=="client"?"Client-to-CDN TCP RTT: ":"Local Nginx-to-PaceTun TCP RTT: ")<<s.tcp_rtt_us.load()/1000.0
     <<" ms (NOT the full CDN-to-origin path)\n";
  }
  o<<"This process's TCP peer: "<<address_family(s.carrier_peer_family.load())
   <<"; the CDN origin address family must be checked in Nginx, not inferred here.\n";
  if(cfg.max_connections>1)o<<"Physical WebSocket lanes: "<<s.pool_active.load()<<"/"<<cfg.max_connections<<" | failed lanes: "<<s.pool_failures.load()<<"\n";
  o<<"Actual data rate: sent "<<format_bytes_rate(s.payload_tx_rate_bps.load())
   <<", received "<<format_bytes_rate(s.payload_rx_rate_bps.load())<<"\n";
  auto drops=s.drop_queue.load()+s.drop_delay.load()+s.drop_malformed.load();
  o<<"Local queued packets: "<<s.queue_pkts.load()<<" | Local drops (since process start): "<<drops
   <<" | Reconnects: "<<s.reconnects.load()<<" | Authentication failures: "<<s.auth_fail.load()<<"\n";
  if(s.degraded.load())o<<"WARNING: authenticated probe replies are late. Inspect CDN buffering/path and check whether fresh RTT measurements return.\n";
  if(s.auth_fail.load())o<<"WARNING: authentication failures occurred. Verify PSK and matching protocol versions on both peers.\n";
  if(drops)o<<"NOTE: drops are cumulative since startup; compare two readings before deciding they are ongoing.\n";
  o<<"For raw metrics: --control SOCKET stats | For recent events: --control SOCKET events\n";
  return o.str();
}
void human_stats_loop(Stats&s,const Config&cfg,std::atomic<bool>&done){
  uint64_t tx=s.payload_tx.load(),rx=s.payload_rx.load(),prevdrops=s.drop_queue.load()+s.drop_delay.load()+s.drop_malformed.load();
  auto prev=Clock::now();
  while(!done&&!g_stop){
    for(int i=0;i<cfg.stats_interval_sec*10&&!done&&!g_stop;++i)std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if(done||g_stop)break;
    auto now=Clock::now();double seconds=std::max(0.001,std::chrono::duration<double>(now-prev).count());
    const auto nt=s.payload_tx.load(),nr=s.payload_rx.load();
    const auto send=static_cast<uint64_t>(double(nt-tx)/seconds),receive=static_cast<uint64_t>(double(nr-rx)/seconds);
    s.payload_tx_rate_bps=send;s.payload_rx_rate_bps=receive;
    const auto drops=s.drop_queue.load()+s.drop_delay.load()+s.drop_malformed.load();
    const bool online=g_state.load()==3, fresh=online&&s.rtt_sample_us.load()&&s.rtt_us.load()>=0
      && mono_us()-s.rtt_sample_us.load()<=30000000&&!s.degraded.load();
    std::ostringstream o;
    if(cfg.max_connections>1)o<<"[POOL] active="<<s.pool_active.load()<<"/"<<cfg.max_connections<<" dial_failures="<<s.pool_dial_failures.load()<<" lane_failures="<<s.pool_failures.load()<<"\n";
    o<<"[HEALTH] "<<(online?(s.degraded.load()?"DEGRADED":"ONLINE"):
           g_state.load()==1?"WAITING FOR CLIENT":g_state.load()==2?"CONNECTING":g_state.load()==4?"RECONNECTING":"NOT ONLINE");
    if(fresh)o<<" | authenticated round-trip "<<std::fixed<<std::setprecision(1)<<s.rtt_us.load()/1000.0<<" ms";
    else o<<" | authenticated round-trip unavailable/stale";
    const auto hist=s.rtt_history.snapshot();
    if(hist.count>=5)o<<" | RTT p95 "<<std::fixed<<std::setprecision(1)<<hist.p95_ms<<" ms ("<<hist.count<<" samples)";
    o<<" | queued "<<s.queue_pkts.load()<<" packets"
     <<" | dropped this interval "<<(drops>=prevdrops?drops-prevdrops:0)
     <<" | reconnects total "<<s.reconnects.load()<<"\n";
    o<<"[TRAFFIC] "<<((nt==tx&&nr==rx)?"idle":"active")
     <<" | sent "<<format_bytes_rate(send)<<" | received "<<format_bytes_rate(receive)
     <<" | TCP ";
    if(online && cfg.mode=="client" && cfg.tls_backend=="utls")o<<"Iran-to-CDN RTT unavailable (Go sidecar)";
    else if(online)o<<(cfg.mode=="client"?"Iran-to-CDN peer ":"foreign-to-local-Nginx ")
      <<std::fixed<<std::setprecision(1)<<s.tcp_rtt_us.load()/1000.0<<" ms";
    else o<<"unavailable";
    o<<" | TCP retransmissions cumulative "<<s.tcp_total_retrans.load()<<" (local socket only)\n";
    std::cerr<<o.str();tx=nt;rx=nr;prevdrops=drops;prev=now;
  }
}
void stats_loop(Stats&s,const Config&cfg,std::atomic<bool>&done){
  if(cfg.log_format=="human"){human_stats_loop(s,cfg,done);return;}
  const int sec=cfg.stats_interval_sec;
  uint64_t ti=0,to=0,tp=0,rp=0,wt=0,wr=0,dq=0,dd=0;
  while(!done&&!g_stop){
    for(int i=0;i<sec*10&&!done&&!g_stop;i++)std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto nti=s.tun_in_bytes.load(),nto=s.tun_out_bytes.load(),ntp=s.payload_tx.load(),nrp=s.payload_rx.load();
    auto nwt=s.wire_tx.load(),nwr=s.wire_rx.load(),ndq=s.drop_queue.load(),ndd=s.drop_delay.load();auto r=s.rtt_us.load();
    s.payload_tx_rate_bps=(ntp-tp)/std::max(1,sec);s.payload_rx_rate_bps=(nrp-rp)/std::max(1,sec);
    std::cerr<<"[STATS]/"<<sec<<"s state="<<state_name(g_state.load())
      <<" tun_in+="<<nti-ti<<" tun_out+="<<nto-to<<" payload_tx+="<<ntp-tp<<" payload_rx+="<<nrp-rp
      <<" wire_tx+="<<nwt-wt<<" wire_rx+="<<nwr-wr<<" queue="<<s.queue_pkts.load()<<"/"<<s.queue_bytes.load()<<"B"
      <<" peak_queue="<<s.queue_peak_pkts.load()<<"/"<<s.queue_peak_bytes.load()<<"B batch_now="<<s.adaptive_batch_packets.load()
      <<" rtt_ms="<<(r<0?0.0:double(r)/1000.0)<<" ws_rtt_ms="<<(s.ws_rtt_us.load()<0?0.0:double(s.ws_rtt_us.load())/1000.0)
      <<" tcp_rtt_ms="<<double(s.tcp_rtt_us.load())/1000.0<<" ws_tx_pending="<<s.ws_tx_pending_bytes.load()<<"B"
      <<" cwnd="<<s.tcp_cwnd.load()<<" unacked="<<s.tcp_unacked.load()<<" retrans="<<s.tcp_retrans.load()
      <<" drop_queue+="<<ndq-dq<<" drop_delay+="<<ndd-dd<<" malformed="<<s.drop_malformed.load()
      <<" replay_drop="<<s.replay_drop.load()<<" sequence_gap="<<s.sequence_gap.load()<<" auth_fail="<<s.auth_fail.load()
      <<" reconnects="<<s.reconnects.load()<<" tx_stalls="<<s.tx_stalls.load()<<" ws_missed_pongs="<<s.ws_missed_pongs.load()<<"\n";
    ti=nti;to=nto;tp=ntp;rp=nrp;wt=nwt;wr=nwr;dq=ndq;dd=ndd;
  }
}

std::string status_text(const Stats&s,const Config&cfg,Clock::time_point started,bool totals){
  auto up=std::chrono::duration_cast<std::chrono::seconds>(Clock::now()-started).count();std::ostringstream o;
  auto rt=s.rtt_history.snapshot(),ra=s.rtt_history.snapshot(1),ri=s.rtt_history.snapshot(2);
  o<<"version=6.0.0-alpha1 state="<<state_name(g_state.load())<<" phase="<<phase_name(g_phase.load())<<" mode="<<cfg.mode<<" transport="<<cfg.transport
   <<" wire="<<wire_name(cfg)<<" forward_secrecy="<<(cfg.transport=="websocket"?1:0)
   <<" carrier_tls="<<((cfg.transport=="websocket"&&cfg.mode=="client")?(cfg.websocket_tls?1:0):-1)
   <<" max_connections="<<cfg.max_connections<<" pool_active="<<s.pool_active.load()<<" pool_dials="<<s.pool_dials.load()<<" pool_dial_failures="<<s.pool_dial_failures.load()<<" pool_failures="<<s.pool_failures.load()
   <<" profile="<<cfg.profile<<" resource_profile="<<cfg.resource_profile<<" uptime_sec="<<up<<" daemon_instance="<<std::chrono::duration_cast<std::chrono::microseconds>(started.time_since_epoch()).count()
   <<" rtt_ms="<<((g_state.load()!=3||s.rtt_us.load()<0)?-1.0:double(s.rtt_us.load())/1000.0)
   <<" ws_rtt_ms="<<(s.ws_rtt_us.load()<0?0.0:double(s.ws_rtt_us.load())/1000.0)
   <<" tcp_rtt_ms="<<double(s.tcp_rtt_us.load())/1000.0<<" tcp_cwnd="<<s.tcp_cwnd.load()
   <<" tcp_unacked="<<s.tcp_unacked.load()<<" tcp_retrans="<<s.tcp_retrans.load()
   <<" tcp_total_retrans="<<s.tcp_total_retrans.load()<<" tcp_snd_mss="<<s.tcp_snd_mss.load()<<" tcp_pmtu="<<s.tcp_pmtu.load()
   <<" carrier_local_family="<<address_family(s.carrier_local_family.load())<<" carrier_peer_family="<<address_family(s.carrier_peer_family.load())
   <<" origin_family="<<(cfg.mode=="server"?"unavailable_via_local_nginx":"unavailable_from_client")
   <<" rtt_samples="<<rt.count<<" rtt_p50_ms="<<rt.p50_ms<<" rtt_p95_ms="<<rt.p95_ms<<" rtt_p99_ms="<<rt.p99_ms
   <<" active_rtt_samples="<<ra.count<<" active_rtt_p95_ms="<<ra.p95_ms<<" idle_rtt_samples="<<ri.count<<" idle_rtt_p95_ms="<<ri.p95_ms
   <<" payload_tx_rate_Bps="<<s.payload_tx_rate_bps.load()<<" payload_rx_rate_Bps="<<s.payload_rx_rate_bps.load()
   <<" degraded="<<(s.degraded.load()?1:0)<<" authenticated_probe=enabled"
   <<" rtt_sample_seq="<<s.rtt_sample_seq.load()
   <<" rtt_sample_age_ms="<<(g_state.load()==3&&s.rtt_sample_us.load()?int64_t((mono_us()-s.rtt_sample_us.load())/1000):-1)
   <<" probe_pending_age_ms="<<s.probe_pending_age_ms.load()<<" reply_timeouts="<<s.reply_timeouts.load()
   <<" candidate_attempts="<<s.candidate_attempts.load()<<" candidate_failures="<<s.candidate_failures.load()<<" candidate_successes="<<s.candidate_successes.load()
   <<" last_rx_age_ms="<<s.last_rx_age_ms.load()<<" queue_pkts="<<s.queue_pkts.load()<<" queue_bytes="<<s.queue_bytes.load()
   <<" queue_peak_pkts="<<s.queue_peak_pkts.load()<<" queue_peak_bytes="<<s.queue_peak_bytes.load()
   <<" traffic_shaping="<<cfg.traffic_shaping<<" padding_extra_tx="<<s.padding_extra_tx.load()<<" padding_control_extra_tx="<<s.padding_control_extra_tx.load()
   <<" adaptive_batch_packets="<<s.adaptive_batch_packets.load()<<" ws_tx_pending_bytes="<<s.ws_tx_pending_bytes.load()
   <<" reconnects="<<s.reconnects.load()<<" drops="<<(s.drop_queue.load()+s.drop_delay.load()+s.drop_malformed.load())
   <<" auth_fail="<<s.auth_fail.load()<<" replay_drop="<<s.replay_drop.load()<<" sequence_gap="<<s.sequence_gap.load();
  if(totals)o<<" tun_in_bytes="<<s.tun_in_bytes.load()<<" tun_out_bytes="<<s.tun_out_bytes.load()
   <<" payload_tx="<<s.payload_tx.load()<<" payload_rx="<<s.payload_rx.load()<<" wire_tx="<<s.wire_tx.load()<<" wire_rx="<<s.wire_rx.load()
   <<" keepalive_tx="<<s.keepalive_tx.load()<<" keepalive_rx="<<s.keepalive_rx.load()<<" ping_tx="<<s.ping_tx.load()<<" pong_rx="<<s.pong_rx.load()
   <<" ws_messages_tx="<<s.ws_messages_tx.load()<<" ws_messages_rx="<<s.ws_messages_rx.load()<<" ws_control_tx="<<s.ws_control_tx.load()<<" ws_control_rx="<<s.ws_control_rx.load()
   <<" ws_ping_tx="<<s.ws_ping_tx.load()<<" ws_ping_rx="<<s.ws_ping_rx.load()<<" ws_pong_tx="<<s.ws_pong_tx.load()<<" ws_pong_rx="<<s.ws_pong_rx.load()
   <<" ws_missed_pongs="<<s.ws_missed_pongs.load()<<" session_renewals="<<s.session_renewals.load()<<" ptt5_sessions="<<s.ptt5_sessions.load()
   <<" tx_stalls="<<s.tx_stalls.load()<<" event_loop_delay_us="<<s.event_loop_delay_us.load()<<" queue_oldest_age_us="<<s.queue_oldest_age_us.load()
   <<" reconnect_pong_timeout="<<s.reconnect_pong_timeout.load()<<" reconnect_tx_timeout="<<s.reconnect_tx_timeout.load()
   <<" reconnect_idle="<<s.reconnect_idle.load()<<" reconnect_session="<<s.reconnect_session.load()
   <<" reconnect_network="<<s.reconnect_network.load()<<" reconnect_manual="<<s.reconnect_manual.load()
   <<" latency_renewals="<<s.latency_renewals.load()<<" reply_renewals="<<s.reply_renewals.load();
  o<<"\n";return o.str();
}

std::string health_text(const Stats&s,const Config&cfg){
  const double pressure=cfg.queue_bytes?100.0*double(s.queue_bytes.load())/double(cfg.queue_bytes):0;
  const bool online=g_state.load()==3;
  const bool fresh=s.last_rx_age_ms.load()<static_cast<uint64_t>(cfg.idle_timeout_sec*1000);
  const bool queue_ok=pressure<95.0;
  const bool healthy=online&&fresh&&queue_ok&&!s.degraded.load();
  std::ostringstream o;o<<"healthy="<<(healthy?"true":"false")<<" state="<<state_name(g_state.load())<<" phase="<<phase_name(g_phase.load())
   <<" wire="<<wire_name(cfg)<<" forward_secrecy="<<(cfg.transport=="websocket"?1:0)
   <<" carrier_tls="<<((cfg.transport=="websocket"&&cfg.mode=="client")?(cfg.websocket_tls?1:0):-1)
   <<" rtt_ms="<<((g_state.load()!=3||s.rtt_us.load()<0)?-1.0:double(s.rtt_us.load())/1000.0)
   <<" ws_rtt_ms="<<(s.ws_rtt_us.load()<0?0.0:double(s.ws_rtt_us.load())/1000.0)
   <<" tcp_rtt_ms="<<double(s.tcp_rtt_us.load())/1000.0<<" queue_pressure_pct="<<std::fixed<<std::setprecision(1)<<pressure
   <<" last_rx_age_ms="<<s.last_rx_age_ms.load()<<" auth_fail_total="<<s.auth_fail.load()<<" replay_drop_total="<<s.replay_drop.load()
   <<" max_connections="<<cfg.max_connections<<" pool_active="<<s.pool_active.load()
   <<" reconnects="<<s.reconnects.load()<<" ws_missed_pongs="<<s.ws_missed_pongs.load()<<" tx_stalls="<<s.tx_stalls.load()
   <<" payload_tx_rate_Bps="<<s.payload_tx_rate_bps.load()<<" payload_rx_rate_Bps="<<s.payload_rx_rate_bps.load()<<"\n";return o.str();
}
std::string events_text(){std::lock_guard<std::mutex>lk(g_events_mu);std::ostringstream o;for(auto&s:g_events)o<<s<<"\n";return o.str();}

void control_loop(const Config&cfg,Stats&s,std::atomic<bool>&done,Clock::time_point started){int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0){std::cerr<<"[CONTROL] state=ERROR error=socket\n";return;}sockaddr_un a{};a.sun_family=AF_UNIX;if(cfg.control_socket.size()>=sizeof(a.sun_path)){close(fd);return;}std::strncpy(a.sun_path,cfg.control_socket.c_str(),sizeof(a.sun_path)-1);unlink(a.sun_path);if(bind(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))<0||listen(fd,8)<0){std::cerr<<"[CONTROL] state=ERROR path="<<cfg.control_socket<<" error="<<strerror(errno)<<"\n";close(fd);return;}chmod(a.sun_path,cfg.control_mode);std::cerr<<"[CONTROL] state=LISTENING path="<<cfg.control_socket<<"\n";while(!done&&!g_stop){pollfd p{fd,POLLIN,0};int pr=poll(&p,1,250);if(pr<=0)continue;int c=accept4(fd,nullptr,nullptr,SOCK_CLOEXEC);if(c<0)continue;struct ucred cred{};socklen_t clen=sizeof(cred);bool privileged=(getsockopt(c,SOL_SOCKET,SO_PEERCRED,&cred,&clen)==0&&(cred.uid==0||cred.uid==geteuid()));timeval deadline{2,0};setsockopt(c,SOL_SOCKET,SO_RCVTIMEO,&deadline,sizeof(deadline));setsockopt(c,SOL_SOCKET,SO_SNDTIMEO,&deadline,sizeof(deadline));char b[128]{};ssize_t n=read(c,b,sizeof(b)-1);std::string cmd=n>0?std::string(b,n):"";cmd.erase(std::remove(cmd.begin(),cmd.end(),'\n'),cmd.end());std::string out;if(cmd=="status")out=readable_status(s,cfg)+"\n";else if(cmd=="overview")out=overview_text(s,cfg);else if(cmd=="stats")out=status_text(s,cfg,started,true);else if(cmd=="health")out=health_text(s,cfg);else if(cmd=="events")out=events_text();else if(cmd=="diagnose"){
  out=overview_text(s,cfg)+"\n--- Detailed metrics (for support/benchmarking) ---\n"+status_text(s,cfg,started,true);
  out+="origin_family_note=the foreign PaceTun socket is Nginx loopback; verify external IPv6 on Nginx port 443 with ss -6\n";
}else if(cmd=="reconnect"){if(!privileged)out="error permission denied\n";else{g_force_disconnect=true;out="ok reconnect requested\n";}}else if(cmd=="stop"){if(!privileged)out="error permission denied\n";else{g_stop=true;g_state=5;g_phase=9;out="ok stopping\n";}}else out="error commands: overview status stats health events diagnose reconnect stop\n";size_t sent=0;while(sent<out.size()){ssize_t w=send(c,out.data()+sent,out.size()-sent,MSG_NOSIGNAL);if(w>0)sent+=static_cast<size_t>(w);else if(w<0&&errno==EINTR)continue;else break;}close(c);}unlink(a.sun_path);close(fd);}
int jittered(int base,int pct,std::mt19937&rng){if(pct==0)return base;int span=base*pct/100;std::uniform_int_distribution<int>d(-span,span);return std::max(1,base+d(rng));}
}

void check_secret_permissions(const Config& cfg) {
  if (!cfg.strict_file_permissions) return;
  for (const auto& path : {cfg.psk_file, cfg.psk_previous_file, cfg.tls_key}) {
    if (path.empty()) continue;
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) throw std::runtime_error("cannot stat secret file: "+path);
    if ((st.st_mode & 0077) != 0) throw std::runtime_error("insecure secret permissions (expected 0600): "+path);
  }
}

struct WarmSwitch : std::runtime_error { WarmSwitch():std::runtime_error("authenticated WebSocket replacement ready"){} };
int connect_utls_adapter(const std::string& path,int timeout_sec) {
  int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
  if(fd<0) throw std::runtime_error("uTLS adapter socket creation failed");
  sockaddr_un addr{};addr.sun_family=AF_UNIX;
  if(path.size()>=sizeof(addr.sun_path)){close(fd);throw std::runtime_error("uTLS adapter socket path too long");}
  std::memcpy(addr.sun_path,path.c_str(),path.size()+1);
  int r=connect(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr));
  if(r<0 && errno==EINPROGRESS){
    pollfd p{fd,POLLOUT,0};r=poll(&p,1,std::max(1,timeout_sec)*1000);
    if(r>0){int so=0;socklen_t n=sizeof(so);if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&so,&n)==0 && so==0)return fd;}
  }else if(r==0)return fd;
  close(fd);throw std::runtime_error("uTLS adapter unavailable or connection failed (no TLS fallback)");
}
void wait_utls_tls_ready(int fd,int timeout_sec){
  constexpr char marker[]="UTLSOK1\n";
  char received[sizeof(marker)-1]{};
  size_t count=0;
  const auto deadline=Clock::now()+std::chrono::seconds(std::max(1,timeout_sec)*2+2);
  while(count<sizeof(received)){
    const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
    if(remaining<=0)throw std::runtime_error("uTLS adapter TLS handshake timeout");
    pollfd p{fd,static_cast<short>(POLLIN|POLLHUP|POLLERR),0};
    const int r=poll(&p,1,static_cast<int>(std::min<long long>(remaining,250)));
    if(r<0){if(errno==EINTR)continue;throw std::runtime_error("uTLS adapter readiness poll failed");}
    if(r==0)continue;
    const auto n=recv(fd,received+count,sizeof(received)-count,MSG_DONTWAIT);
    if(n>0){count+=static_cast<size_t>(n);continue;}
    if(n==0)throw std::runtime_error("uTLS adapter closed before verified TLS handshake; check sidecar logs");
    if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)continue;
    throw std::runtime_error("uTLS adapter readiness read failed");
  }
  if(std::memcmp(received,marker,sizeof(received))!=0)
    throw std::runtime_error("uTLS adapter protocol version mismatch");
}
std::unique_ptr<AdmittedConnection> dial_websocket(const Config& cfg,SSL_CTX* ctx,bool background,int candidate_limit_ms=0){
  auto c=std::make_unique<AdmittedConnection>();auto& ws=c->ws;
  ws.browser_profile=cfg.browser_profile;
  ws.client=true;ws.io_timeout_ms=cfg.websocket_io_timeout_sec*1000;
  if(!background)g_phase=3;
  if(cfg.tls_backend=="utls"){
    if(!background)g_phase=4;
    ws.fd=connect_utls_adapter(cfg.tls_adapter_socket,cfg.connect_timeout_sec);
    wait_utls_tls_ready(ws.fd,cfg.connect_timeout_sec);
    std::cerr<<"[TLS] sidecar reports verified TLS ready; backend=utls (SNI/CA are configured on the sidecar)\n";
  } else ws.fd=connect_tcp(cfg.server,cfg);
  if(cfg.websocket_tls && cfg.tls_backend=="openssl"){
    if(!background)g_phase=4;
    ws.ssl=SSL_new(ctx);
    if(!ws.ssl)throw std::runtime_error("SSL_new failed");
    if(SSL_set_fd(ws.ssl,ws.fd)!=1||SSL_set_tlsext_host_name(ws.ssl,cfg.server_name.c_str())!=1)throw std::runtime_error("TLS setup failed");
    if(cfg.verify_peer&&SSL_set1_host(ws.ssl,cfg.server_name.c_str())!=1)throw std::runtime_error("TLS hostname setup failed");
    ssl_handshake(ws.ssl,false,cfg.connect_timeout_sec);
    const unsigned char* selected=nullptr;unsigned selected_len=0;SSL_get0_alpn_selected(ws.ssl,&selected,&selected_len);
    if(selected_len && (selected_len!=8||std::memcmp(selected,"http/1.1",8)!=0))throw std::runtime_error("CDN TLS ALPN did not negotiate http/1.1");
  }
  if(!background)g_phase=5;
  c->handshake=websocket_client_upgrade(ws,cfg.host_header.empty()?cfg.server_name:cfg.host_header,cfg.path,read_psk(cfg.psk_file),cfg.websocket_upgrade_timeout_sec*1000,candidate_limit_ms,background,cfg.max_connections);
  if(cfg.websocket_control_padding_bytes&&!c->handshake.peer_envelope)throw std::runtime_error("peer lacks envelope-v2; upgrade both peers or disable control padding");
  if(cfg.websocket_padding_max_bytes&&!c->handshake.peer_padding)throw std::runtime_error("peer lacks padding-v1");
  if(background&&!c->handshake.confirmed)throw std::runtime_error("replacement peer lacks key confirmation; upgrade foreign peer first");
  return c;
}

struct PoolLane {
  std::unique_ptr<AdmittedConnection> conn;
  RecordDecoderV5 decoder;
  FlowQueue waiting;
  BurstShaper shaper{mono_us()};
  const std::uint64_t id;
  std::uint64_t sequence=1;
  std::uint64_t probe_token=0;
  bool probe_outstanding=false;
  Clock::time_point connected=Clock::now(),last_rx=Clock::now(),last_probe=Clock::now(),last_tx=Clock::now();
  std::uint64_t ws_tx_bytes=0,ws_tx_frames=0;
  bool draining=false;
  Clock::time_point drain_until{},last_data{},last_report=Clock::now();
  std::int64_t rtt_us=-1;
  std::uint64_t rtt_sample=0;
  LatencyRenewal renewal;

  bool ws_ping_pending=false;
  std::array<unsigned char,8> ws_ping_payload{};
  Clock::time_point last_ws_ping=Clock::now();
  PoolLane(std::unique_ptr<AdmittedConnection> c,const Config& cfg,std::uint64_t serial)
    :conn(std::move(c)),decoder(cfg.mode=="server"?conn->handshake.keys.client_tx:conn->handshake.keys.server_tx,
                               cfg.max_record_buffer_bytes),id(serial){}
  Key32& tx_key(const Config& cfg){return cfg.mode=="server"?conn->handshake.keys.server_tx:conn->handshake.keys.client_tx;}
};
void pool_tunnel_loop(TunDevice& tun,const Config&cfg,Stats&st,
                      AdmissionServer* server,SSL_CTX*ctx){
  std::vector<std::unique_ptr<PoolLane>> lanes;
  PoolAffinity affinity;
  std::uint64_t next_id=1;
  std::future<std::unique_ptr<AdmittedConnection>> dial;
  Clock::time_point next_dial=Clock::now(), last_prune=Clock::now();
  int backoff=cfg.reconnect_initial_ms;
  std::uint64_t replacing=0;
  std::int64_t replacement_reference_rtt=-1;
  Clock::time_point next_replacement=Clock::now();
  std::mt19937 pool_rng(std::random_device{}());
  ShapeBudget shape_budget(cfg.traffic_shaping,cfg.shaping_rate_bytes,cfg.shaping_burst_bytes,mono_us());
  PaddingBudget padding(cfg.padding_budget_pct,mono_us()); // shared by ALL lanes
  auto encode=[&](PoolLane& lane,std::span<const unsigned char> payload,std::uint8_t flags=0){
    if(flags==RECORD_DRAIN)return encode_record_v5(lane.tx_key(cfg),lane.sequence++,payload,flags);
    const bool control=flags!=0;
    if(!control)lane.shaper.observe(payload.size(),mono_us());
    int maximum=control?cfg.websocket_control_padding_bytes:cfg.websocket_padding_max_bytes;
    if(cfg.traffic_shaping&&!control)maximum=lane.shaper.maximum(maximum,cfg.shaping_startup_ms,mono_us());
    if(maximum>0){
      const int allowance=shape_budget.allowance(control?padding.control_allowance(maximum,mono_us()):padding.data_allowance(payload.size(),maximum),mono_us());
      if(allowance>=3){
        auto record=encode_envelope_record_v5(lane.tx_key(cfg),lane.sequence++,payload,flags,allowance-3);
        const auto extra=record.size()-payload.size()-32;
        shape_budget.spend(extra);
        if(control){padding.spend_control(extra);st.padding_control_extra_tx+=extra;}
        else{padding.spend_data(extra);st.padding_extra_tx+=extra;}
        return record;
      }
    }
    return encode_record_v5(lane.tx_key(cfg),lane.sequence++,payload,flags);
  };
  std::vector<unsigned char> buffer(cfg.mtu+256);
  std::cerr<<"[POOL] PTT8 enabled max_connections="<<cfg.max_connections<<" independent_keys=1 flow_affinity=1\n";
  auto attach=[&](std::unique_ptr<AdmittedConnection> c){
    if(!c)return;
    if(c->handshake.pool_connections!=cfg.max_connections || !c->handshake.confirmed || !c->handshake.peer_trial)
      throw std::runtime_error("PTT8 authentication or pool agreement missing");
    c->ws.io_timeout_ms=cfg.websocket_io_timeout_sec*1000;
    set_socket_options(c->ws.fd,cfg);set_nonblock(c->ws.fd);
    lanes.push_back(std::make_unique<PoolLane>(std::move(c),cfg,next_id++));
    st.pool_active=lanes.size();++st.ptt5_sessions;g_state=3;g_phase=7;
    event("pool lane=added active="+std::to_string(lanes.size()));
    std::cerr<<"[POOL] authenticated lane online id="<<lanes.back()->id
             <<" active="<<lanes.size()<<"/"<<cfg.max_connections<<"\n";
    backoff=cfg.reconnect_initial_ms;
  };
  auto detach=[&](std::size_t i,const std::string&reason){
    if(i>=lanes.size())return;
    auto& lane=*lanes[i];
    st.drop_queue+=lane.waiting.packets();
    if(reason!="planned drain complete"){++st.pool_failures;++st.reconnects;}
    event("pool lane=removed id="+std::to_string(lane.id)+" reason="+reason);
    std::cerr<<"[POOL] lane="<<lane.id<<" closed reason="<<reason
             <<" remaining="<<lanes.size()-1<<"\n";
    lanes.erase(lanes.begin()+static_cast<std::ptrdiff_t>(i));
    st.pool_active=lanes.size();
    if(lanes.empty()) {g_state=cfg.mode=="server"?1:4;g_phase=cfg.mode=="server"?2:8;st.rtt_us=-1;}
  };
  while(!g_stop){
    if(server){
      while(lanes.size()<static_cast<std::size_t>(cfg.max_connections+1) && server->has_ready()){
        auto ready=server->take(0);
        try{attach(std::move(ready));}
        catch(const std::exception&){++st.pool_failures;}
      }
    }else{
      if(dial.valid() && dial.wait_for(std::chrono::milliseconds(0))==std::future_status::ready){
        try{
          auto candidate=dial.get();
          if(replacing && replacement_reference_rtt>0 &&
             candidate->handshake.trial_max_rtt_us>=replacement_reference_rtt*8/10)
            throw std::runtime_error("replacement trial did not improve authenticated RTT by 20 percent");
          attach(std::move(candidate));
          if(replacing){
            for(auto& old:lanes)if(old->id==replacing){
              old->draining=true;old->drain_until=Clock::now()+std::chrono::seconds(cfg.pool_drain_sec);
              try{auto drain=encode(*old,{},RECORD_DRAIN);websocket_send_binary(old->conn->ws,drain);}
              catch(...){old->drain_until=Clock::now();}
              ++st.session_renewals;
              event("pool replacement=verified retiring_lane="+std::to_string(replacing));
            }
          }
          replacing=0;
          next_replacement=Clock::now()+std::chrono::seconds(cfg.latency_renew_cooldown_sec);
        }
        catch(const std::exception&e){
          ++st.pool_dial_failures;
          event(std::string("pool dial_failed code=")+failure_code(g_phase.load(),e.what()));
          std::cerr<<"[POOL] dial failed: "<<clean_log_detail(e.what())<<"\n";
          next_dial=Clock::now()+std::chrono::milliseconds(jittered(backoff,cfg.reconnect_jitter_pct,pool_rng));
          if(replacing)next_replacement=next_dial;
          replacing=0;
          backoff=std::min(backoff*2,cfg.reconnect_max_ms);
        }
      }
      if(!dial.valid() && lanes.size()==static_cast<std::size_t>(cfg.max_connections) &&
         Clock::now()>=next_replacement && Clock::now()>=next_dial &&
         std::none_of(lanes.begin(),lanes.end(),[](const auto& l){return l->draining;})){
        const bool forced=g_force_disconnect.exchange(false);
        for(auto& ptr:lanes){
          auto& l=*ptr;const auto instant=Clock::now();
          const bool missing=l.probe_outstanding && instant-l.last_probe>=std::chrono::seconds(cfg.reply_renew_sec);
          const bool aged=cfg.session_max_age_sec>0 && instant-l.connected>=std::chrono::seconds(cfg.session_max_age_sec);
          const bool active=l.last_data!=Clock::time_point{} && instant-l.last_data<std::chrono::seconds(60);
          const bool slow=l.renewal.observe(l.rtt_sample,l.rtt_us,mono_us(),active,cfg.latency_renew_ms,
                                            cfg.latency_renew_samples,cfg.latency_renew_cooldown_sec);
          if(forced||missing||aged||slow){
            replacing=l.id;replacement_reference_rtt=slow?l.rtt_us:-1;next_replacement=instant+std::chrono::seconds(cfg.latency_renew_cooldown_sec);
            if(slow)++st.latency_renewals;
            if(missing)++st.reply_renewals;
            event("pool replacement=started lane="+std::to_string(l.id));break;
          }
        }
      }
      if((lanes.size()<static_cast<std::size_t>(cfg.max_connections) || replacing) && !dial.valid() && Clock::now()>=next_dial){
        if(lanes.empty()){g_state=2;g_phase=3;}
        ++st.pool_dials;
        dial=std::async(std::launch::async,[&cfg,ctx]{return dial_websocket(cfg,ctx,true);});
      }
    }
    st.pool_active=lanes.size();
    auto now=Clock::now();
    if(now-last_prune>std::chrono::seconds(10)){
      affinity.prune(mono_us());last_prune=now;
    }
    std::size_t outstanding_pkts=0,outstanding_bytes=0,ws_pending=0;
    for(auto&ptr:lanes){
      auto&lane=*ptr;
      st.drop_delay+=lane.waiting.drop_expired(mono_us(),static_cast<std::uint64_t>(cfg.queue_delay_ms)*1000);
      outstanding_pkts+=lane.waiting.packets();outstanding_bytes+=lane.waiting.bytes();
      ws_pending+=lane.conn->ws.tx_queued_bytes;
    }
    st.queue_pkts=outstanding_pkts;st.queue_bytes=outstanding_bytes;st.ws_tx_pending_bytes=ws_pending;
    st.queue_peak_pkts=std::max<std::uint64_t>(st.queue_peak_pkts.load(),outstanding_pkts);
    st.queue_peak_bytes=std::max<std::uint64_t>(st.queue_peak_bytes.load(),outstanding_bytes);
    std::vector<pollfd> polls;
    polls.reserve(lanes.size()+1);
    for(auto&lane:lanes){auto&w=lane->conn->ws;
      polls.push_back({w.fd,static_cast<short>(websocket_rx_poll_events(w)|websocket_tx_poll_events(w)),0});
    }
    const bool can_read=!lanes.empty() && outstanding_pkts<cfg.queue_packets && outstanding_bytes<cfg.queue_bytes;
    polls.push_back({tun.poll_fd(),static_cast<short>(can_read?POLLIN:0),0});
    bool buffered=false;
    for(const auto& l:lanes)if(l->conn->ws.ssl && SSL_pending(l->conn->ws.ssl)>0)buffered=true;
    const bool send_ready=std::any_of(lanes.begin(),lanes.end(),[&](const auto& l){return !l->waiting.empty() && l->conn->ws.tx_queued_bytes<cfg.batch_bytes*2;});
    const int poll_ms=buffered?0:(send_ready?(cfg.traffic_shaping?1:0):cfg.pool_idle_poll_ms);
    int result=poll(polls.data(),static_cast<nfds_t>(polls.size()),poll_ms);
    if(result<0){if(errno==EINTR)continue;throw std::runtime_error("PTT8 poll failed");}
    if(can_read && (polls.back().revents&POLLIN)){
      std::vector<std::uint64_t> live;
      for(const auto&lane:lanes)live.push_back(lane->id);
      for(int read_count=0;read_count<std::max(1,cfg.batch_packets);++read_count){
        auto n=tun.read_packet(buffer);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(n<0&&errno==EINTR)continue;
        if(n<=0)throw std::runtime_error("PTT8 TUN read failed");
        ++st.tun_in_pkts;st.tun_in_bytes+=n;
        const std::span<const unsigned char> p(buffer.data(),static_cast<std::size_t>(n));
        const auto instant=mono_us();
        std::uint64_t preferred=0;long double best=std::numeric_limits<long double>::max();
        for(const auto& l:lanes){
          if(l->draining)continue;
          const auto pending_age=l->probe_outstanding?
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-l->last_probe).count():0;
          const long double score=(l->rtt_us<0?100000:l->rtt_us)+
            l->waiting.oldest_age_us(instant)+
            (l->waiting.bytes()+l->conn->ws.tx_queued_bytes)*8.0L+
            (pending_age>=cfg.reply_degraded_sec*1000?1.0e12L:0.0L);
          if(score<best){best=score;preferred=l->id;}
        }
        const auto chosen=affinity.choose(p,live,instant,preferred);
        auto match=std::find_if(lanes.begin(),lanes.end(),[&](const auto&l){return l->id==chosen;});
        if(match==lanes.end()){++st.drop_queue;continue;}
        if(outstanding_pkts>=cfg.queue_packets || outstanding_bytes+p.size()+64>cfg.queue_bytes ||
           !(*match)->waiting.push(std::vector<unsigned char>(p.begin(),p.end()),mono_us(),
                                   cfg.queue_packets,cfg.queue_bytes)){
          ++st.drop_queue;continue;
        }
        (*match)->last_data=Clock::now();
        ++outstanding_pkts;outstanding_bytes+=p.size()+64;
      }
    }
    for(std::size_t i=0;i<lanes.size();){
      auto&lane=*lanes[i];auto&w=lane.conn->ws;
      try{
        if(server && g_force_disconnect.exchange(false))throw std::runtime_error("operator requested reconnect");
        if(lane.draining && Clock::now()>=lane.drain_until)throw std::runtime_error("planned drain complete");
        if(websocket_tx_stalled(w,cfg.websocket_io_timeout_sec*1000)){
          ++st.tx_stalls;throw std::runtime_error("pool WebSocket write stalled");
        }
        const auto txbefore=w.tx_binary_payload_bytes,frames_before=w.tx_binary_frames;
        const auto ping_before=w.rx_ping_frames,pong_before=w.rx_pong_frames;
        const auto ping_tx_before=w.tx_ping_frames,pong_tx_before=w.tx_pong_frames;
        websocket_flush(w,256*1024);
        if(w.tx_queued_bytes<cfg.batch_bytes*2 && !lane.waiting.empty() && (!cfg.traffic_shaping || lane.shaper.ready(lane.waiting.packets(),lane.waiting.oldest_age_us(mono_us()),cfg.shaping_delay_ms,mono_us()))){
          std::vector<unsigned char> message;
          int batch=cfg.batch_packets;
          if(cfg.adaptive_batching){
            batch=static_cast<int>(std::clamp<std::size_t>(lane.waiting.packets(),
                cfg.adaptive_batch_min_packets,cfg.adaptive_batch_max_packets));
            if(lane.waiting.oldest_age_us(mono_us())>static_cast<std::uint64_t>(cfg.queue_target_delay_ms)*1000)
              batch=cfg.adaptive_batch_max_packets;
          }
          for(int sent=0;sent<std::max(1,batch) && !lane.waiting.empty();++sent){
            auto item=lane.waiting.pop();
            if(item.bytes.empty())break;
            if(message.size()+item.bytes.size()+64>cfg.batch_bytes && !message.empty()){
              websocket_send_binary(w,message);message.clear();
            }
            auto rec=encode(lane,item.bytes);
            message.insert(message.end(),rec.begin(),rec.end());
            st.payload_tx+=item.bytes.size();
          }
          if(!message.empty())websocket_send_binary(w,message);
          lane.last_tx=Clock::now();
        }
        websocket_flush(w,256*1024);
        auto before=w.rx_frames;
        auto messages=websocket_read_messages(w,0);
        if(w.rx_frames!=before)lane.last_rx=Clock::now();
        st.ws_ping_rx+=w.rx_ping_frames-ping_before;st.ws_pong_rx+=w.rx_pong_frames-pong_before;
        st.ws_control_rx+=(w.rx_ping_frames-ping_before)+(w.rx_pong_frames-pong_before);
        for(auto&pong:websocket_take_pongs(w)){
          if(lane.ws_ping_pending && pong.size()==lane.ws_ping_payload.size() &&
             std::equal(pong.begin(),pong.end(),lane.ws_ping_payload.begin())){
            const auto token=decode_u64(pong),instant=mono_us();
            if(instant>=token)st.ws_rtt_us=static_cast<std::int64_t>(instant-token);
            lane.ws_ping_pending=false;
          }
        }
        for(const auto&msg:messages){
          ++st.ws_messages_rx;st.wire_rx+=msg.size();
          std::string error;auto gap=lane.decoder.sequence_gaps(),replays=lane.decoder.replay_drops();
          if(!lane.decoder.feed(msg,[&](std::uint8_t flags,std::uint64_t,std::span<const unsigned char>payload){
              if(flags==RECORD_DRAIN){
                if(!server)throw std::runtime_error("unexpected server drain command");
                if(!lane.draining){lane.draining=true;lane.drain_until=Clock::now()+std::chrono::seconds(cfg.pool_drain_sec+5);}
              }else if(flags==0){
                lane.last_data=Clock::now();
                if(payload.empty()||payload.size()>static_cast<std::size_t>(cfg.mtu+256)){
                  ++st.drop_malformed;return;
                }
                auto written=tun.write_packet(payload);
                if(written==static_cast<ssize_t>(payload.size())){
                  ++st.tun_out_pkts;st.tun_out_bytes+=payload.size();st.payload_rx+=payload.size();
                }else ++st.drop_malformed;
              }else if(flags&RECORD_PING){
                ++st.ping_rx;auto response=encode(lane,payload,RECORD_PONG);
                websocket_send_binary(w,response);++st.pong_tx;++st.ws_control_tx;
              }else if(flags&RECORD_PONG){
                ++st.pong_rx;
                if(payload.size()==8 && lane.probe_outstanding && decode_u64(payload)==lane.probe_token){
                  const auto us=mono_us();
                  if(us>=lane.probe_token){st.rtt_us=static_cast<int64_t>(us-lane.probe_token);
                    lane.rtt_us=static_cast<std::int64_t>(us-lane.probe_token);lane.rtt_sample=us;
                    st.rtt_sample_us=us;++st.rtt_sample_seq;
                    st.rtt_history.record(us-lane.probe_token,true);}
                  lane.probe_outstanding=false;
                }
              }else if(flags&RECORD_KEEPALIVE)++st.keepalive_rx;
            },error)){
              st.replay_drop+=lane.decoder.replay_drops()-replays;
              if(error.find("authentication")!=std::string::npos)++st.auth_fail;
              else ++st.drop_malformed;
              throw std::runtime_error("PTT8 invalid authenticated record");
          }
          st.sequence_gap+=lane.decoder.sequence_gaps()-gap;
        }
        now=Clock::now();
        if(lane.probe_outstanding && now-lane.last_probe>=std::chrono::seconds(cfg.reply_timeout_sec)){
          ++st.reply_timeouts;throw std::runtime_error("pool authenticated reply timeout");
        }
        const bool active_data=lane.last_data!=Clock::time_point{} && now-lane.last_data<std::chrono::seconds(60);
        const int probe_interval=active_data?std::clamp(cfg.rtt_probe_sec,5,20):std::clamp(cfg.idle_probe_sec,5,120);
        if(!lane.probe_outstanding && now-lane.last_probe>=std::chrono::seconds(probe_interval)){
          const auto token=mono_us();auto data=encode_u64(token);
          lane.probe_token=token;lane.probe_outstanding=true;lane.last_probe=now;
          auto record=encode(lane,data,RECORD_PING);
          websocket_send_binary(w,record);++st.ping_tx;++st.ws_control_tx;
        }
        if(lane.ws_ping_pending && cfg.websocket_pong_timeout_sec>0 &&
           now-lane.last_ws_ping>=std::chrono::seconds(cfg.websocket_pong_timeout_sec)){
          ++st.ws_missed_pongs;throw std::runtime_error("pool WebSocket PONG timeout");
        }
        if(lane.ws_ping_pending && cfg.websocket_pong_timeout_sec==0 && cfg.websocket_ping_sec>0 &&
           now-lane.last_ws_ping>=std::chrono::seconds(cfg.websocket_ping_sec))lane.ws_ping_pending=false;
        if(cfg.websocket_ping_sec>0 && !lane.ws_ping_pending &&
           now-lane.last_ws_ping>=std::chrono::seconds(cfg.websocket_ping_sec)){
          auto payload=encode_u64(mono_us());
          std::copy(payload.begin(),payload.end(),lane.ws_ping_payload.begin());
          websocket_send_ping(w,payload);lane.ws_ping_pending=true;lane.last_ws_ping=now;
        }
        if(cfg.keepalive_sec>0 && now-lane.last_tx>=std::chrono::seconds(cfg.keepalive_sec) && !websocket_tx_pending(w)){
          const auto rec=encode(lane,{},RECORD_KEEPALIVE);
          websocket_send_binary(w,rec);lane.last_tx=now;++st.keepalive_tx;
        }
        websocket_flush(w,256*1024);
        if(w.tx_binary_payload_bytes>txbefore)st.wire_tx+=w.tx_binary_payload_bytes-txbefore;
        if(w.tx_binary_frames>frames_before)st.ws_messages_tx+=w.tx_binary_frames-frames_before;
        st.ws_ping_tx+=w.tx_ping_frames-ping_tx_before;st.ws_pong_tx+=w.tx_pong_frames-pong_tx_before;
        st.ws_control_tx+=(w.tx_ping_frames-ping_tx_before)+(w.tx_pong_frames-pong_tx_before);
        if(now-lane.last_rx>=std::chrono::seconds(cfg.idle_timeout_sec))throw std::runtime_error("pool lane idle timeout");
        if(now-lane.last_report>=std::chrono::seconds(cfg.stats_interval_sec)){
          lane.last_report=now;
          std::cerr<<"[LANE] id="<<lane.id<<" state="<<(lane.draining?"DRAINING":"ACTIVE")
            <<" authenticated_rtt_ms="<<(lane.rtt_us<0?-1:lane.rtt_us/1000)
            <<" queue_bytes="<<lane.waiting.bytes()<<" pending_bytes="<<w.tx_queued_bytes<<"\n";
        }
        if(polls[i].revents&(POLLERR|POLLHUP|POLLNVAL))throw std::runtime_error("pool socket closed");
        ++i;
      }catch(const std::exception&e){
        detach(i,clean_log_detail(e.what()));
        break;
      }
    }
    if(!lanes.empty()){
      g_state=3;g_phase=7;
      std::uint64_t oldest_ms=0;
      for(const auto&lane:lanes)oldest_ms=std::max<std::uint64_t>(oldest_ms,
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-lane->last_rx).count());
      st.last_rx_age_ms=oldest_ms;
      st.degraded=lanes.size()<static_cast<std::size_t>(cfg.max_connections);
    }else{st.last_rx_age_ms=static_cast<std::uint64_t>(cfg.idle_timeout_sec)*1000;st.degraded=true;}
  }
  if(dial.valid()){
    try{auto leftover=dial.get();(void)leftover;}catch(...){}
  }
  st.pool_active=0;
}

int run(const Config& cfg) {
  signal(SIGINT,on_signal); signal(SIGTERM,on_signal); signal(SIGPIPE,SIG_IGN);
  OPENSSL_init_ssl(0,nullptr);
  check_secret_permissions(cfg);
  TunDevice tun(cfg.dev,cfg.cidr,cfg.peer_cidr,cfg.mtu);g_phase=1;
  std::cerr<<"[TUN] dev="<<tun.name()<<" cidr="<<cfg.cidr<<" peer="<<cfg.peer_cidr<<" mtu="<<cfg.mtu<<"\n";
  if(cfg.traffic_shaping)std::cerr<<"[SHAPING] experimental startup_ms="<<cfg.shaping_startup_ms<<" delay_budget_ms="<<cfg.shaping_delay_ms<<" padding_rate_Bps="<<cfg.shaping_rate_bytes<<" padding_burst_B="<<cfg.shaping_burst_bytes<<" data_padding_pct="<<cfg.padding_budget_pct<<"\n";
  std::cerr<<"[PROFILE] name="<<cfg.profile<<" resource="<<cfg.resource_profile<<" queue="<<cfg.queue_packets<<"/"<<cfg.queue_bytes<<"B batch="<<cfg.batch_packets<<"/"<<cfg.batch_bytes<<"B ws_poll_ms="<<cfg.websocket_poll_ms<<"\n";
  Stats st; auto started=Clock::now(); std::atomic<bool>done=false;
  std::thread sl(stats_loop,std::ref(st),std::cref(cfg),std::ref(done));
  std::thread cl(control_loop,std::cref(cfg),std::ref(st),std::ref(done),started);
  std::mt19937 rng(std::random_device{}()); if(cfg.transport!="websocket")g_phase=10; event("started mode="+cfg.mode+" transport="+cfg.transport);
  try {
    if(cfg.transport=="tls") {
      if(cfg.mode=="server") {
        SSL_CTX*ctx=server_ctx(cfg); int lfd=listen_tcp(cfg.listen,cfg.listen_backlog); g_state=1;
        std::cerr<<"[TLS] state=LISTENING listen="<<cfg.listen<<" transport=tls13-connect path="<<cfg.path<<"\n";
        while(!g_stop){g_state=1;pollfd p{lfd,POLLIN,0};int pr=poll(&p,1,250);if(pr<0){if(errno==EINTR)continue;throw std::runtime_error("listen poll failed");}if(pr==0)continue;int fd=accept4(lfd,nullptr,nullptr,SOCK_CLOEXEC);if(fd<0){if(errno==EINTR)continue;throw std::runtime_error("accept failed");}set_socket_options(fd,cfg);SSL*ssl=SSL_new(ctx);if(!ssl){close(fd);throw std::runtime_error("SSL_new failed");}if(SSL_set_fd(ssl,fd)!=1){SSL_free(ssl);close(fd);throw std::runtime_error("SSL_set_fd failed");}try{ssl_handshake(ssl,true,cfg.connect_timeout_sec);std::cerr<<"[TLS] state=ACCEPTED peer=connected\n";std::vector<std::vector<unsigned char>>psks{read_psk(cfg.psk_file)};if(!cfg.psk_previous_file.empty())psks.push_back(read_psk(cfg.psk_previous_file));auto keys=server_handshake(ssl,cfg,psks,st);tunnel_loop(ssl,tun,cfg,st,keys.server_tx,keys.client_tx);}catch(const std::exception&e){if(!g_stop){event("disconnected error="+std::string(e.what()));std::cerr<<"[TLS] state=DISCONNECTED error="<<e.what()<<"\n";}}close_ssl(ssl,fd);}close(lfd);SSL_CTX_free(ctx);
      } else {
        SSL_CTX*ctx=client_ctx(cfg);int delay=cfg.reconnect_initial_ms,attempt=0;while(!g_stop){int fd=-1;SSL*ssl=nullptr;try{++attempt;g_state=2;std::cerr<<"[TLS] state=CONNECTING target="<<cfg.server<<" sni="<<cfg.server_name<<" path="<<cfg.path<<"\n";fd=connect_tcp(cfg.server,cfg);ssl=SSL_new(ctx);if(!ssl)throw std::runtime_error("SSL_new failed");if(SSL_set_fd(ssl,fd)!=1)throw std::runtime_error("SSL_set_fd failed");if(SSL_set_tlsext_host_name(ssl,cfg.server_name.c_str())!=1)throw std::runtime_error("failed to set TLS SNI");if(cfg.verify_peer&&SSL_set1_host(ssl,cfg.server_name.c_str())!=1)throw std::runtime_error("failed to set TLS hostname verification");ssl_handshake(ssl,false,cfg.connect_timeout_sec);auto psk=read_psk(cfg.psk_file);auto keys=client_handshake(ssl,cfg,psk);delay=cfg.reconnect_initial_ms;tunnel_loop(ssl,tun,cfg,st,keys.client_tx,keys.server_tx);}catch(const std::exception&e){if(!g_stop){g_state=4;st.reconnects++;int wait=jittered(delay,cfg.reconnect_jitter_pct,rng);event("reconnecting error="+std::string(e.what()));std::cerr<<"[TLS] state=RECONNECTING attempt="<<attempt<<" delay="<<wait<<"ms error="<<e.what()<<"\n";close_ssl(ssl,fd);for(int left=wait;left>0&&!g_stop;left-=100)std::this_thread::sleep_for(std::chrono::milliseconds(std::min(left,100)));delay=std::min(delay*2,cfg.reconnect_max_ms);continue;}}close_ssl(ssl,fd);}SSL_CTX_free(ctx);
      }
    } else if(cfg.transport=="websocket") {
      if(cfg.mode=="server") {
        int lfd=listen_tcp(cfg.listen,cfg.listen_backlog);g_state=1;g_phase=2;std::cerr<<"[WS] state=LISTENING listen="<<cfg.listen<<" origin=plaintext wire="<<wire_name(cfg)<<" kex=X25519 path="<<cfg.path<<"\n";
        std::vector<std::vector<unsigned char>>psks{read_psk(cfg.psk_file)};if(!cfg.psk_previous_file.empty())psks.push_back(read_psk(cfg.psk_previous_file));
        AdmissionServer admission(lfd,cfg.host_header.empty()?cfg.server_name:cfg.host_header,cfg.path,psks,std::clamp(cfg.websocket_upgrade_timeout_sec*1000,5000,15000),4,16,cfg.max_connections);
        if(cfg.max_connections>1)pool_tunnel_loop(tun,cfg,st,&admission,nullptr);
        while(cfg.max_connections==1 && !g_stop){
          auto connection=admission.take();if(!connection)continue;
          auto& ws=connection->ws;auto& hs=connection->handshake;
          ws.io_timeout_ms=cfg.websocket_io_timeout_sec*1000;set_socket_options(ws.fd,cfg);
          const auto session_start=Clock::now();
          try{
            if(cfg.websocket_padding_max_bytes&&!hs.peer_padding)throw std::runtime_error("peer lacks padding-v1; upgrade both peers or disable padding");
            if(cfg.websocket_control_padding_bytes&&!hs.peer_envelope)throw std::runtime_error("peer lacks envelope-v2; upgrade both peers or disable control padding");
            WebSocketCarrier carrier(ws);++st.ptt5_sessions;g_state=3;g_phase=7;
            event("online role=server transport=websocket");std::cerr<<"[OK] Tunnel ONLINE: foreign server accepted authenticated Iran connection. Transport=WebSocket; inner encryption=ChaCha20-Poly1305.\n";
            carrier_tunnel_loop(carrier,tun,cfg,st,hs.keys.server_tx,hs.keys.client_tx,[&]{if(admission.has_ready())throw WarmSwitch();});
          }catch(const WarmSwitch&){++st.reconnects;std::cerr<<"[OK] Foreign server switching to authenticated replacement connection.\n";}catch(const std::exception&e){if(!g_stop){classify_reconnect(e.what(),st);++st.reconnects;event("disconnected error="+std::string(e.what()));std::cerr<<friendly_failure("ONLINE",failure_code(7,e.what()),e.what())<<"[INFO] Foreign server is waiting for Iran to reconnect.\n";}}
          std::cerr<<"[SESSION] duration_ms="<<std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-session_start).count()
                   <<" ws_tx_payload_bytes="<<ws.tx_binary_payload_bytes
                   <<" ws_rx_payload_bytes="<<ws.rx_binary_payload_bytes
                   <<" peer_close="<<(ws.close_received?"yes":"no")
                   <<" close_code="<<(ws.close_has_code?std::to_string(ws.close_code):"none")<<"\n";
          connection.reset();if(!g_stop){g_state=1;g_phase=2;}
        }

      } else {
        std::unique_ptr<SSL_CTX,decltype(&SSL_CTX_free)> ctx(cfg.websocket_tls && cfg.tls_backend=="openssl"?client_ctx(cfg):nullptr,SSL_CTX_free);
        if(cfg.max_connections>1)pool_tunnel_loop(tun,cfg,st,nullptr,ctx.get());
        std::unique_ptr<AdmittedConnection> connection;
        std::future<std::unique_ptr<AdmittedConnection>> warm;
        LatencyRenewal policy;
        RecoveryBackoff recovery;
        uint64_t payload_seen=st.payload_tx.load()+st.payload_rx.load(),last_active=0;
        int delay=cfg.reconnect_initial_ms;
        auto dial_next=[&](bool background,int limit=0){
          return dial_websocket(cfg,ctx.get(),background,limit);
        };
        while(cfg.max_connections==1 && !g_stop){
          auto connection_started=Clock::now();
          try{
            if(!connection){g_state=2;std::cerr<<"[INFO] Connecting Iran client to CDN hostname "<<cfg.server<<" via WebSocket.\n";connection=dial_next(false);}
            connection_started=Clock::now();
            auto& ws=connection->ws;auto& hs=connection->handshake;
            WebSocketCarrier carrier(ws);++st.ptt5_sessions;g_state=3;g_phase=7;policy.reset_samples();
            std::cerr<<"[OK] Tunnel ONLINE: Iran client authenticated; key_confirmation="<<(hs.confirmed?"yes":"legacy")<<" measured_handover="<<(hs.peer_trial?"enabled":"unavailable-upgrade-foreign")<<"\n";
            auto tick=[&]{
              if(warm.valid()&&warm.wait_for(std::chrono::milliseconds(0))==std::future_status::ready){
                try{auto replacement=warm.get();std::cerr<<"[CANDIDATE] trial_max_rtt_ms="<<replacement->handshake.trial_max_rtt_us/1000.0<<"; committed\n";connection.swap(replacement);recovery.succeeded(mono_us());++st.candidate_successes;++st.reconnects;event("recovery code=HANDOVER_COMMITTED");std::cerr<<"[OK] Authenticated replacement accepted (HANDOVER_COMMITTED). New WebSocket is active; previous connection closed.\n";}
                catch(const std::exception& e){recovery.failed(mono_us());++st.candidate_failures;event("recovery code=CANDIDATE_REJECTED");std::cerr<<"[WARN] Replacement connection was rejected (CANDIDATE_REJECTED): "<<clean_log_detail(e.what())<<". Keeping existing link; next trial permitted in "<<recovery.remaining_sec(mono_us())<<" s.\n";return;}
                throw WarmSwitch();
              }
              auto now=mono_us(),payload=st.payload_tx.load()+st.payload_rx.load();
              if(payload!=payload_seen){payload_seen=payload;last_active=now;}
              if(Clock::now()-connection_started>std::chrono::seconds(120))delay=cfg.reconnect_initial_ms;
              const bool missing=st.probe_pending_age_ms.load()>=uint64_t(cfg.reply_renew_sec)*1000;
              const auto baseline=st.rtt_history.snapshot(1);
              const int threshold=baseline.count>=8
                ? std::max(cfg.latency_renew_ms,static_cast<int>(baseline.p50_ms*3))
                : cfg.latency_renew_ms;
              if(!warm.valid()&&hs.peer_trial&&recovery.ready(now)&&(missing||policy.observe(st.rtt_sample_us.load(),st.rtt_us.load(),now,last_active&&now-last_active<=60000000,threshold,cfg.latency_renew_samples,cfg.latency_renew_cooldown_sec))){
                int limit=cfg.candidate_max_rtt_ms;
                if(!missing&&st.rtt_us.load()>0)limit=std::min(limit,std::max(100,int(st.rtt_us.load()/1000*8/10)));
                recovery.started(now);++st.candidate_attempts;
                if(missing)++st.reply_renewals;else ++st.latency_renewals;
                event(missing?"recovery reason=missing_authenticated_reply":"recovery reason=sustained_latency");
                std::cerr<<"[INFO] Testing a replacement connection because "<<(missing?"authenticated replies are late":"latency stayed high")<<". Current link stays in place during the trial; candidate RTT limit="<<limit<<" ms.\n";
                warm=std::async(std::launch::async,[&,limit]{return dial_next(true,limit);});
              }
            };
            carrier_tunnel_loop(carrier,tun,cfg,st,hs.keys.client_tx,hs.keys.server_tx,tick);
          }catch(const WarmSwitch&){continue;}
          catch(const std::exception&e){
            const int failed_phase=g_phase.load();
            g_state=4;g_phase=8;st.rtt_us=-1;st.rtt_sample_us=0;
            if(connection){
              const auto& oldws=connection->ws;
              std::cerr<<"[SESSION] duration_ms="<<std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-connection_started).count()
                       <<" ws_tx_payload_bytes="<<oldws.tx_binary_payload_bytes
                       <<" ws_rx_payload_bytes="<<oldws.rx_binary_payload_bytes
                       <<" peer_close="<<(oldws.close_received?"yes":"no")
                       <<" close_code="<<(oldws.close_has_code?std::to_string(oldws.close_code):"none")<<"\n";
            }
            connection.reset();
            if(warm.valid()){
              try{connection=warm.get();recovery.succeeded(mono_us());++st.candidate_successes;if(!g_stop){++st.reconnects;std::cerr<<"[OK] Old connection ended; continuing with the previously authenticated replacement.\n";continue;}}
              catch(const std::exception& error){recovery.failed(mono_us());++st.candidate_failures;std::cerr<<"[WARN] Candidate failed after disconnect: "<<clean_log_detail(error.what())<<". Will use normal reconnect.\n";}
            }
            if(!g_stop){
              event(std::string("failure stage=")+phase_name(failed_phase)+" code="+failure_code(failed_phase,e.what()));std::cerr<<friendly_failure(phase_name(failed_phase),failure_code(failed_phase,e.what()),e.what());
              g_state=4;g_phase=8;++st.reconnects;classify_reconnect(e.what(),st);
              int wait=jittered(delay,cfg.reconnect_jitter_pct,rng);
              std::cerr<<"[INFO] Automatic retry in "<<wait<<" ms; existing configuration is unchanged.\n";
              for(int left=wait;left>0&&!g_stop;left-=100)std::this_thread::sleep_for(std::chrono::milliseconds(std::min(left,100)));
              delay=std::min(delay*2,cfg.reconnect_max_ms);
            }
          }
        }
      }

    } else {
      throw std::runtime_error("unsupported transport");
    }
  } catch(...) {done=true;g_stop=true;if(sl.joinable())sl.join();if(cl.joinable())cl.join();throw;}
  done=true;g_stop=true;if(sl.joinable())sl.join();if(cl.joinable())cl.join();event("stopped");std::cerr<<"[CORE] stopped cleanly\n";return 0;
}
int control_command(const std::string&path,const std::string&command){int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)throw std::runtime_error("control socket create failed");sockaddr_un a{};a.sun_family=AF_UNIX;if(path.size()>=sizeof(a.sun_path)){close(fd);throw std::runtime_error("control socket path too long");}std::strncpy(a.sun_path,path.c_str(),sizeof(a.sun_path)-1);if(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))<0){auto e=std::string(strerror(errno));close(fd);throw std::runtime_error("control connect failed: "+e);}std::string q=command+"\n";if(write(fd,q.data(),q.size())!=(ssize_t)q.size()){close(fd);throw std::runtime_error("control write failed");}char b[16384];ssize_t n=read(fd,b,sizeof(b));close(fd);if(n<0)throw std::runtime_error("control read failed");std::cout.write(b,n);return 0;}
}
