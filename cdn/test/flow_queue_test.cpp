#include "pacetun/flow_scheduler.hpp"
#include "pacetun/record.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
using namespace pacetun;
static std::vector<unsigned char> packet(unsigned char source, unsigned short port, std::size_t length) {
  std::vector<unsigned char> p(length,0);
  p[0]=0x45; p[2]=static_cast<unsigned char>(length>>8);p[3]=static_cast<unsigned char>(length);
  p[9]=6;p[12]=source;p[16]=9;p[20]=static_cast<unsigned char>(port>>8);p[21]=static_cast<unsigned char>(port);
  p[22]=1;p[23]=187;
  return p;
}
int main() {
  std::array<unsigned char,32> key{};
  for (std::size_t i=0;i<key.size();++i)key[i]=static_cast<unsigned char>(i);
  std::vector<std::vector<unsigned char>> packets{
    packet(1,1001,1200),packet(1,1001,1200),packet(2,1002,80),
    packet(2,1002,80),packet(1,1001,1200)};
  RecordDecoderV5 decoder(key,262144);
  std::vector<std::vector<unsigned char>> output;
  std::string error;
  uint64_t sequence=1;
  for (const auto index : schedule_packet_batch(packets,true)) {
    auto encrypted=encode_record_v5(key,sequence++,packets[index],0);
    assert(decoder.feed(encrypted,[&](uint8_t flags,uint64_t seq,std::span<const unsigned char> payload) {
      assert(flags==0 && seq==output.size()+1);
      output.emplace_back(payload.begin(),payload.end());
    },error));
  }
  assert(output.size()==packets.size());
  assert(decoder.replay_drops()==0 && decoder.sequence_gaps()==0);
  assert(output[1]==packets[2]);
  std::cout<<"flow/record integration PASS: strict PTT5 ordering with AEAD replay protection\n";
}
