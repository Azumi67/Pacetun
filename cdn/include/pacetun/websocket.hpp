#pragma once
#include <openssl/ssl.h>
#include "pacetun/record.hpp"
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <vector>

namespace pacetun {

struct WsTxFrame {
  std::vector<unsigned char> data;
  std::size_t offset = 0;
  std::size_t payload_bytes = 0;
  uint8_t opcode = 0;
};

struct WsSession {
  int fd = -1;
  SSL* ssl = nullptr; // client-side WSS
  bool client = false;
  std::string browser_profile = "none";
  std::vector<unsigned char> rx;
  std::vector<std::vector<unsigned char>> prefetched_messages;
  int io_timeout_ms = 30000;

  uint64_t rx_frames = 0;
  uint64_t rx_ping_frames = 0;
  uint64_t rx_pong_frames = 0;
  uint64_t tx_binary_frames = 0;
  uint64_t tx_binary_payload_bytes = 0;
  uint64_t tx_ping_frames = 0;
  uint64_t tx_pong_frames = 0;

  bool peer_eof = false;
  bool close_received = false;
  bool close_has_code = false;
  uint16_t close_code = 0; // RFC 6455 
  std::size_t close_reason_bytes = 0;
  uint64_t rx_binary_payload_bytes = 0;
  bool upgraded = false;
  bool authenticated = false; // cap frames at 1024 bytes 

  std::deque<WsTxFrame> tx;
  std::size_t tx_queued_bytes = 0;
  uint64_t tx_last_progress_ms = 0;
  uint8_t tx_wait = 0; // 0=none/default, 1=read, 2=write
  uint8_t rx_wait = 0; 

  uint8_t fragment_opcode = 0;
  std::vector<unsigned char> fragment_payload;

  std::deque<std::vector<unsigned char>> pong_payloads;
};

struct WsHandshakeResult {
  SessionKeys keys{};
  bool peer_padding = false;
  bool peer_envelope = false;
  bool confirmed = false;
  bool peer_trial = false;
  int64_t trial_max_rtt_us = -1;
  std::size_t psk_index = 0;
  int pool_connections = 1;
  std::string client_nonce;
  std::string server_nonce;
};

WsHandshakeResult websocket_client_upgrade(WsSession& ws,const std::string& host,const std::string& path,
                                           std::span<const unsigned char> psk,int timeout_ms,int candidate_max_rtt_ms=0,bool require_trial=false,int pool_connections=1);
WsHandshakeResult websocket_server_upgrade(WsSession& ws,const std::string& expected_host,const std::string& path,
                                           const std::vector<std::vector<unsigned char>>& psks,int timeout_ms,int pool_connections=1);

void websocket_send_binary(WsSession& ws,std::span<const unsigned char> payload);
void websocket_send_ping(WsSession& ws,std::span<const unsigned char> payload);
void websocket_send_pong(WsSession& ws,std::span<const unsigned char> payload);
std::size_t websocket_flush(WsSession& ws,std::size_t byte_budget = 256 * 1024);
bool websocket_tx_pending(const WsSession& ws);
short websocket_tx_poll_events(const WsSession& ws);
short websocket_rx_poll_events(const WsSession& ws);
std::size_t websocket_tx_queued_bytes(const WsSession& ws);
bool websocket_tx_stalled(const WsSession& ws,int timeout_ms);
std::vector<std::vector<unsigned char>> websocket_take_pongs(WsSession& ws);

std::vector<std::vector<unsigned char>> websocket_read_messages(WsSession& ws,int timeout_ms);
void websocket_http_fallback(WsSession& ws);
std::string websocket_close_summary(const WsSession& ws);
void websocket_close(WsSession& ws);
}
