#pragma once
#include <cstddef>
#include <string>

namespace pacetun {
struct Config {
  std::string mode;
  std::string transport = "tls"; // tls|websocket
  std::string listen;
  std::string server;
  std::string server_name;
  std::string path = "/assets/api/v6";
  std::string host_header;
  // `websocket_tls=1` WSS, `0` plain WS.
  int max_connections = 1; // authenticated independent WebSocket lanes: 1=legacy, 2..4=PTT8 pool
  int pool_drain_sec = 30; 
  int pool_idle_poll_ms = 100;
  std::string address_family = "auto"; // auto | ipv4 | ipv6 (OpenSSL dial)
  bool flow_scheduler = false; 
  bool edge_dns_rotation = false; 
  bool websocket_tls = true;
  std::string tls_backend = "openssl"; // openssl (default) | utls (Iran client only)
  std::string tls_adapter_socket = "/run/pacetun-utls/bridge.sock";
  int websocket_ping_sec = 0;           // RFC6455 ping; 0 disables
  int websocket_pong_timeout_sec = 0;   
  int websocket_poll_ms = 5;
  int websocket_upgrade_timeout_sec = 10;
  int websocket_io_timeout_sec = 30;
  int websocket_padding_max_bytes = 0; 
  int websocket_control_padding_bytes = 0;
  int padding_budget_pct = 10;
  int timing_jitter_pct = 15;
  int reply_degraded_sec=10,reply_renew_sec=30,reply_timeout_sec=60,candidate_max_rtt_ms=1500;
  int latency_renew_ms=600,latency_renew_samples=3,latency_renew_cooldown_sec=180,idle_probe_sec=45;
  std::string log_format = "human";
  int listen_backlog = 128;
  int session_max_age_sec = 0;            // 0 disables renewal
  std::string dev = "phtun0";
  std::string cidr;
  std::string peer_cidr;
  int mtu = 1280;
  std::string tls_cert;
  std::string tls_key;
  std::string tls_ca;
  bool verify_peer = true;
  std::string psk_file;
  std::string psk_previous_file;

  std::string profile = "balanced";          // balanced|lightning|bulk|ultra
  std::string resource_profile = "normal";   // normal|lowmem
  std::size_t max_record_buffer_bytes = 262144;
  int control_mode = 0660;

  std::size_t queue_packets = 4096;
  std::size_t queue_bytes = 8 * 1024 * 1024;
  int queue_delay_ms = 500;
  int batch_packets = 8;
  std::size_t batch_bytes = 16384;
  bool adaptive_batching = true;
  int adaptive_batch_min_packets = 1;
  int adaptive_batch_max_packets = 16;
  int queue_target_delay_ms = 40;

  int connect_timeout_sec = 10;
  int idle_timeout_sec = 300;
  int keepalive_sec = 10;
  int rtt_probe_sec = 30;
  int reconnect_initial_ms = 500;
  int reconnect_max_ms = 15000;
  int reconnect_jitter_pct = 20;

  int tcp_keepidle_sec = 15;
  int tcp_keepintvl_sec = 5;
  int tcp_keepcnt = 3;
  int tcp_user_timeout_ms = 20000;
  int sndbuf = 4 * 1024 * 1024;
  int rcvbuf = 4 * 1024 * 1024;
  int stats_interval_sec = 5;
  std::string control_socket;
  bool strict_file_permissions = true;
};
Config load_config(const std::string& path);
void validate_config(const Config& cfg);
std::string effective_config(const Config& cfg);
}
