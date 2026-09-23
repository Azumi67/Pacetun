#include "pacetun/admission.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>
#include <stdexcept>
namespace pacetun {
AdmissionServer::AdmissionServer(int fd,std::string host,std::string path,std::vector<std::vector<unsigned char>> keys,int timeout,int workers,int limit,int pool_connections):listener_(fd),timeout_(timeout),limit_(limit),pool_connections_(pool_connections),max_active_(pool_connections>1?pool_connections+1:2),host_(std::move(host)),path_(std::move(path)),keys_(std::move(keys)) {
  if(workers<1||workers>16||limit<1||limit>128||timeout<100||timeout>120000||pool_connections<1||pool_connections>4){close(fd);throw std::runtime_error("invalid admission limits");}
  try{for(int i=0;i<workers;++i)workers_.emplace_back(&AdmissionServer::worker,this);acceptor_=std::thread(&AdmissionServer::accept_loop,this);}
  catch(...){stop_=true;pending_cv_.notify_all();for(auto&t:workers_)t.join();close(listener_);throw;}
}
AdmissionServer::~AdmissionServer(){
  stop_=true;pending_cv_.notify_all();ready_cv_.notify_all();
  if(acceptor_.joinable())acceptor_.join();
  for(auto&t:workers_)t.join();
  while(!pending_.empty()){close(pending_.front());pending_.pop();}
  while(!ready_.empty())ready_.pop();
  close(listener_);
}
void AdmissionServer::accept_loop(){
  while(!stop_){pollfd p{listener_,POLLIN,0};int n=poll(&p,1,100);if(n<=0)continue;
    if(!(p.revents&POLLIN))break;
    int fd=accept4(listener_,nullptr,nullptr,SOCK_CLOEXEC|SOCK_NONBLOCK);if(fd<0)continue;
    std::lock_guard<std::mutex> lock(mu_);
    if(stop_||static_cast<int>(pending_.size())>=limit_){++overloaded;close(fd);continue;}
    pending_.push(fd);pending_cv_.notify_one();
  }
}
void AdmissionServer::worker(){
  while(!stop_){int fd;
    {std::unique_lock<std::mutex> lock(mu_);pending_cv_.wait(lock,[&]{return stop_||!pending_.empty();});if(stop_)return;fd=pending_.front();pending_.pop();}
    auto c=std::make_unique<AdmittedConnection>();c->ws.fd=fd;c->ws.client=false;
    int one=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
    try{
      c->handshake=websocket_server_upgrade(c->ws,host_,path_,keys_,timeout_,pool_connections_);
      {std::lock_guard<std::mutex> lock(mu_);
        auto count=claimed_->load();
        if(stop_||count>=static_cast<unsigned>(max_active_)||(count>0&&!c->handshake.confirmed))throw std::runtime_error("busy");
        claimed_->fetch_add(1);c->claimed=claimed_;ready_.push(std::move(c));
      }
      ready_cv_.notify_one();
    }catch(...){++rejected;if(c&&!c->ws.upgraded){try{websocket_http_fallback(c->ws);}catch(...){}}}
  }
}
bool AdmissionServer::has_ready(){std::lock_guard<std::mutex> lock(mu_);return !ready_.empty();}
std::unique_ptr<AdmittedConnection> AdmissionServer::take(int wait_ms){
  std::unique_lock<std::mutex> lock(mu_);ready_cv_.wait_for(lock,std::chrono::milliseconds(wait_ms),[&]{return stop_||!ready_.empty();});if(ready_.empty())return {};auto out=std::move(ready_.front());ready_.pop();return out;
}
}
