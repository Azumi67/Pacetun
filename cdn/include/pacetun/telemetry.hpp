#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

namespace pacetun {
struct RttPercentiles {
  std::size_t count=0;
  double p50_ms=-1, p95_ms=-1, p99_ms=-1;
};
class RttHistory {
 public:
  void reset() { std::lock_guard<std::mutex> lock(mu_); all_.clear(); active_.clear(); idle_.clear(); }
  void record(uint64_t rtt_us, bool active) {
    std::lock_guard<std::mutex> lock(mu_);
    append(all_,rtt_us); append(active ? active_ : idle_,rtt_us);
  }
  RttPercentiles snapshot(int group=0) const {
    std::lock_guard<std::mutex> lock(mu_);
    const auto& samples=group==1 ? active_ : group==2 ? idle_ : all_;
    if(samples.empty()) return {};
    std::vector<uint64_t> sorted(samples.begin(),samples.end());
    std::sort(sorted.begin(),sorted.end());
    auto percentile=[&](std::size_t numerator){
      std::size_t rank=(sorted.size()*numerator+99)/100;
      return double(sorted[std::max<std::size_t>(1,rank)-1])/1000.0;
    };
    return {sorted.size(),percentile(50),percentile(95),percentile(99)};
  }
 private:
  static void append(std::deque<uint64_t>& q,uint64_t v) {
    constexpr std::size_t kMax=128;
    if(q.size()==kMax) q.pop_front();
    q.push_back(v);
  }
  mutable std::mutex mu_;
  std::deque<uint64_t> all_,active_,idle_;
};
}
