#include "pacetun/flow_scheduler.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <vector>
using namespace pacetun;
static std::vector<unsigned char> ipv4(unsigned char source, unsigned char target,
                                       unsigned short port, std::size_t size) {
  std::vector<unsigned char> p(size, 0);
  p[0] = 0x45; p[2] = static_cast<unsigned char>(size >> 8); p[3] = static_cast<unsigned char>(size);
  p[9] = 6; p[12] = source; p[16] = target;
  p[20] = static_cast<unsigned char>(port >> 8); p[21] = static_cast<unsigned char>(port);
  p[22] = 1; p[23] = 187;
  return p;
}
int main() {
  std::vector<std::vector<unsigned char>> packets{
      ipv4(1, 2, 1001, 1200), ipv4(1, 2, 1001, 1200),
      ipv4(3, 2, 1002, 80), ipv4(1, 2, 1001, 1200),
      ipv4(3, 2, 1002, 80), ipv4(4, 2, 1003, 100)};
  auto order = schedule_packet_batch(packets, true);
  assert(order.size() == packets.size());
  auto sorted = order;
  std::sort(sorted.begin(), sorted.end());
  for (std::size_t i = 0; i < sorted.size(); ++i) assert(sorted[i] == i);
  auto pos = [&](std::size_t id) {return std::find(order.begin(), order.end(), id) - order.begin();};
  assert(pos(0) < pos(1) && pos(1) < pos(3));
  assert(pos(2) < pos(4));
  assert(pos(2) < pos(1)); 
  assert((schedule_packet_batch(packets, false) == std::vector<std::size_t>{0,1,2,3,4,5}));
  packets.push_back({}); packets.push_back({0x45});
  assert(schedule_packet_batch(packets, true).size() == packets.size());
  auto first = ipv4(5, 6, 8080, 80);
  first[6] = 0x20;
  auto later = first;
  later[6] = 0; later[7] = 1;
  assert(detail::packet_flow(first) == detail::packet_flow(later));
  std::vector<unsigned char> v6(80,0); v6[0]=0x60; v6[6]=6; v6[8]=1; v6[24]=2;
  v6[40]=1; v6[41]=2; v6[42]=3; v6[43]=4;
  auto id=detail::packet_flow(v6); assert(id.length==38 && id.bytes[0]==6);
  std::cout << "flow scheduler PASS: deterministic fairness, flow FIFO, disabled legacy order, malformed and IPv6\n";
}
