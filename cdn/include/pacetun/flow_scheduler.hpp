#pragma once
// Burst-local, packet
// Packets are scheduled BEFORE record encryption so authenticated sequence numers remain legit
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iterator>
#include <span>
#include <vector>

namespace pacetun {
namespace detail {
struct PacketFlow {
  std::array<unsigned char, 38> bytes{};
  std::size_t length = 0;
  bool operator==(const PacketFlow& other) const {
    return length == other.length &&
        std::equal(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length), other.bytes.begin());
  }
};
inline PacketFlow packet_flow(std::span<const unsigned char> p) {
  PacketFlow result{};
  if (p.empty()) return result;
  const unsigned version = p[0] >> 4;
  std::size_t ports = 0;
  if (version == 4 && p.size() >= 20) {
    const auto ihl = static_cast<std::size_t>(p[0] & 15) * 4;
    const auto total = (static_cast<std::size_t>(p[2]) << 8) | p[3];
    if (ihl < 20 || total < ihl || p.size() < ihl || p.size() < total) return result;
    result.bytes[0] = 4;
    result.bytes[1] = p[9];
    std::copy_n(p.begin() + 12, 8, result.bytes.begin() + 2);
    result.length = 10;
    const bool fragmented = (p[6] & 0x3f) != 0 || p[7] != 0;
    if (!fragmented && (p[9] == 6 || p[9] == 17) && total >= ihl + 4) ports = ihl;
  } else if (version == 6 && p.size() >= 40) {
    result.bytes[0] = 6;
    result.bytes[1] = p[6];
    std::copy_n(p.begin() + 8, 32, result.bytes.begin() + 2);
    result.length = 34;
    if ((p[6] == 6 || p[6] == 17) && p.size() >= 44) ports = 40;
  } else return result;
  if (ports) {
    std::copy_n(p.begin() + static_cast<std::ptrdiff_t>(ports), 4,
                result.bytes.begin() + static_cast<std::ptrdiff_t>(result.length));
    result.length += 4;
  }
  return result;
}
} 

inline std::vector<std::size_t> schedule_packet_batch(
    const std::vector<std::vector<unsigned char>>& packets, bool enabled) {
  std::vector<std::size_t> order;
  order.reserve(packets.size());
  if (!enabled || packets.size() < 2) {
    for (std::size_t i = 0; i < packets.size(); ++i) order.push_back(i);
    return order;
  }
  struct Flow {
    detail::PacketFlow id;
    std::deque<std::size_t> indices;
    bool interactive;
  };
  std::vector<Flow> flows;
  flows.reserve(packets.size());
  for (std::size_t i = 0; i < packets.size(); ++i) {
    auto id = detail::packet_flow(packets[i]);
    auto found = std::find_if(flows.begin(), flows.end(),
                              [&](const Flow& f) { return f.id == id; });
    if (found == flows.end()) {
      Flow flow{id, {}, packets[i].size() <= 256};
      flow.indices.push_back(i);
      flows.push_back(std::move(flow));
    } else found->indices.push_back(i);
  }
  std::size_t interactive_cursor = 0, bulk_cursor = 0, interactive_turns = 0;
  auto take = [&](bool interactive, std::size_t& cursor) -> bool {
    if (flows.empty()) return false;
    for (std::size_t visited = 0; visited < flows.size(); ++visited) {
      const auto index = (cursor + visited) % flows.size();
      auto& flow = flows[index];
      if (flow.interactive == interactive && !flow.indices.empty()) {
        order.push_back(flow.indices.front());
        flow.indices.pop_front();
        cursor = (index + 1) % flows.size();
        return true;
      }
    }
    return false;
  };
  while (order.size() < packets.size()) {
    if (interactive_turns < 2 && take(true, interactive_cursor)) {
      ++interactive_turns;
    } else if (take(false, bulk_cursor)) {
      interactive_turns = 0;
    } else if (take(true, interactive_cursor)) {
      interactive_turns = 1;
    } else break;
  }
  return order;
}

struct FlowPacket {
  std::vector<unsigned char> bytes;
  std::uint64_t enqueued_us = 0;
};
class FlowQueue {
  struct Flow {
    detail::PacketFlow key;
    std::deque<FlowPacket> packets;
    bool interactive = false;
  };
  std::vector<Flow> flows_;
  std::size_t packets_ = 0, bytes_ = 0;
  std::size_t interactive_cursor_ = 0, bulk_cursor_ = 0, interactive_turns_ = 0;
  void prune_if_needed() {
    if (flows_.size() <= packets_ + 32) return;
    flows_.erase(std::remove_if(flows_.begin(),flows_.end(),
          [](const Flow& flow){return flow.packets.empty();}),flows_.end());
    interactive_cursor_ = bulk_cursor_ = interactive_turns_ = 0;
  }
 public:
  std::size_t packets() const noexcept { return packets_; }
  std::size_t bytes() const noexcept { return bytes_; }
  std::size_t flows() const noexcept { return flows_.size(); }
  bool empty() const noexcept { return packets_ == 0; }
  std::uint64_t oldest_age_us(std::uint64_t now) const {
    std::uint64_t age=0;
    for(const auto& f:flows_)if(!f.packets.empty() && now>=f.packets.front().enqueued_us)
      age=std::max(age,now-f.packets.front().enqueued_us);
    return age;
  }
  bool push(std::vector<unsigned char> packet, std::uint64_t at_us,
            std::size_t max_packets, std::size_t max_bytes) {
    if (packet.empty() || packets_ >= max_packets || packet.size() > max_bytes ||
        bytes_ > max_bytes - packet.size()) return false;
    prune_if_needed();
    const auto id = detail::packet_flow(packet);
    auto it = std::find_if(flows_.begin(), flows_.end(),
          [&](const Flow& f) { return f.key == id; });
    if (it == flows_.end()) {
      flows_.push_back(Flow{id, {}, packet.size() <= 256});
      it = std::prev(flows_.end());
    }
    bytes_ += packet.size(); ++packets_;
    it->packets.push_back(FlowPacket{std::move(packet), at_us});
    return true;
  }
  std::size_t drop_expired(std::uint64_t now_us, std::uint64_t ttl_us) {
    std::size_t dropped = 0;
    for (auto& f : flows_) {
      while (!f.packets.empty()) {
        const auto& front = f.packets.front();
        if (now_us < front.enqueued_us || now_us - front.enqueued_us <= ttl_us) break;
        bytes_ -= front.bytes.size(); --packets_; ++dropped;
        f.packets.pop_front();
      }
    }
    if (packets_ == 0) clear(); else prune_if_needed();
    return dropped;
  }
  FlowPacket pop() {
    if (empty()) return {};
    auto take = [&](bool interactive, std::size_t& cursor) -> std::size_t {
      for (std::size_t visited = 0; visited < flows_.size(); ++visited) {
        const auto index = (cursor + visited) % flows_.size();
        if (flows_[index].interactive == interactive && !flows_[index].packets.empty()) {
          cursor = (index + 1) % flows_.size(); return index;
        }
      }
      return flows_.size();
    };
    std::size_t idx = flows_.size();
    if (interactive_turns_ < 2) {
      idx = take(true, interactive_cursor_);
      if (idx != flows_.size()) ++interactive_turns_;
    }
    if (idx == flows_.size()) {
      idx = take(false, bulk_cursor_);
      if (idx != flows_.size()) interactive_turns_ = 0;
    }
    if (idx == flows_.size()) {
      idx = take(true, interactive_cursor_);
      if (idx != flows_.size()) interactive_turns_ = 1;
    }
    if (idx == flows_.size()) return {}; // defensive;nonempty queue
    auto& f = flows_[idx];
    FlowPacket result = std::move(f.packets.front());
    f.packets.pop_front();
    --packets_; bytes_ -= result.bytes.size();
    if (packets_ == 0) clear(); else prune_if_needed();
    return result;
  }
  void clear() {
    flows_.clear(); packets_ = bytes_ = 0;
    interactive_cursor_ = bulk_cursor_ = interactive_turns_ = 0;
  }
};
} 
