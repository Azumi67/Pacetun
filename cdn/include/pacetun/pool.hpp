#pragma once
// each lane has independent keys
// Pooling is not yamux
#include "pacetun/flow_scheduler.hpp"
#include <algorithm>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

namespace pacetun {
struct PacketFlowHash {
  std::size_t operator()(const detail::PacketFlow& key) const noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    for(std::size_t i=0;i<key.length;++i){hash ^= key.bytes[i];hash *= 1099511628211ULL;}
    hash ^= key.length;return static_cast<std::size_t>(hash);
  }
};
class PoolAffinity {
  struct Entry { std::uint64_t lane, last_us; };
  std::unordered_map<detail::PacketFlow,Entry,PacketFlowHash> flows_;
  static constexpr std::size_t kCap = 4096;
  static constexpr std::uint64_t kIdleUS = 180'000'000ULL;
public:
  std::size_t size() const noexcept {return flows_.size();}
  void prune(std::uint64_t now) {
    for(auto i=flows_.begin();i!=flows_.end();){
      if(now>=i->second.last_us && now-i->second.last_us>kIdleUS)i=flows_.erase(i);
      else ++i;
    }
  }
  std::uint64_t choose(std::span<const unsigned char> packet,
                       const std::vector<std::uint64_t>& live_ids,std::uint64_t now,
                       std::uint64_t preferred=0) {
    if(live_ids.empty())return 0;
    const auto key=detail::packet_flow(packet);
    auto it=flows_.find(key);
    if(it!=flows_.end() && std::find(live_ids.begin(),live_ids.end(),it->second.lane)!=live_ids.end()){
      it->second.last_us=now;return it->second.lane;
    }
    const auto lane=preferred && std::find(live_ids.begin(),live_ids.end(),preferred)!=live_ids.end()
      ? preferred : live_ids[PacketFlowHash{}(key)%live_ids.size()];
    if(it!=flows_.end()) {it->second={lane,now};return lane;}
    if(flows_.size()>=kCap){
      prune(now);
      if(flows_.size()>=kCap){
        auto oldest=flows_.begin();
        for(auto e=flows_.begin();e!=flows_.end();++e)if(e->second.last_us<oldest->second.last_us)oldest=e;
        flows_.erase(oldest);
      }
    }
    flows_.emplace(key,Entry{lane,now});return lane;
  }
};
}
