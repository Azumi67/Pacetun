#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace pacetun {
struct WsSession;

struct CarrierCounters {
  uint64_t rx_frames = 0;
  uint64_t rx_ping_frames = 0;
  uint64_t rx_pong_frames = 0;
  uint64_t tx_messages = 0;
  uint64_t tx_payload_bytes = 0;
  uint64_t tx_ping_frames = 0;
  uint64_t tx_pong_frames = 0;
};

class Carrier {
 public:
  virtual ~Carrier() = default;
  virtual std::string_view name() const = 0;
  virtual int native_fd() const = 0;
  virtual void send(std::span<const unsigned char> payload) = 0;
  virtual std::vector<std::vector<unsigned char>> read(int timeout_ms) = 0;
  virtual std::size_t flush(std::size_t byte_budget) = 0;
  virtual bool tx_pending() const = 0;
  virtual short tx_poll_events() const = 0;
  virtual short rx_poll_events() const = 0;
  virtual std::size_t tx_pending_bytes() const = 0;
  virtual bool tx_stalled(int timeout_ms) const = 0;
  virtual void send_ping(std::span<const unsigned char> payload) = 0;
  virtual std::vector<std::vector<unsigned char>> take_pongs() = 0;
  virtual CarrierCounters counters() const = 0;
};

class WebSocketCarrier final : public Carrier {
 public:
  explicit WebSocketCarrier(WsSession& session) : ws_(session) {}
  std::string_view name() const override;
  int native_fd() const override;
  void send(std::span<const unsigned char> payload) override;
  std::vector<std::vector<unsigned char>> read(int timeout_ms) override;
  std::size_t flush(std::size_t byte_budget) override;
  bool tx_pending() const override;
  short tx_poll_events() const override;
  short rx_poll_events() const override;
  std::size_t tx_pending_bytes() const override;
  bool tx_stalled(int timeout_ms) const override;
  void send_ping(std::span<const unsigned char> payload) override;
  std::vector<std::vector<unsigned char>> take_pongs() override;
  CarrierCounters counters() const override;
 private:
  WsSession& ws_;
};
}
