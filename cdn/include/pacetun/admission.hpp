#pragma once
#include "pacetun/websocket.hpp"
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
namespace pacetun {
struct AdmittedConnection {
  WsSession ws;
  WsHandshakeResult handshake;
  std::shared_ptr<std::atomic<unsigned>> claimed;
  ~AdmittedConnection(){websocket_close(ws);if(claimed)claimed->fetch_sub(1);}
};
class AdmissionServer {
 public:
  AdmissionServer(int listener,std::string host,std::string path,std::vector<std::vector<unsigned char>> keys,int timeout_ms,int workers=4,int queue_limit=16,int pool_connections=1);
  ~AdmissionServer();
  std::unique_ptr<AdmittedConnection> take(int wait_ms=250);
  bool has_ready();
  std::atomic<uint64_t> rejected{0},overloaded{0};
 private:
  void accept_loop();void worker();
  int listener_,timeout_,limit_,pool_connections_,max_active_;std::string host_,path_;
  std::vector<std::vector<unsigned char>> keys_;
  std::atomic<bool> stop_{false};
  std::shared_ptr<std::atomic<unsigned>> claimed_=std::make_shared<std::atomic<unsigned>>(0);
  std::mutex mu_;std::condition_variable pending_cv_,ready_cv_;
  std::queue<int> pending_;std::queue<std::unique_ptr<AdmittedConnection>> ready_;
  std::thread acceptor_;std::vector<std::thread> workers_;
};
}
