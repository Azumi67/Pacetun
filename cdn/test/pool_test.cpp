#include "pacetun/pool.hpp"
#include "pacetun/record.hpp"
#include <array>
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace pacetun;
static std::vector<unsigned char> ipv4(unsigned char sport,unsigned char dest){
  std::vector<unsigned char> p(44);p[0]=0x45;p[2]=0;p[3]=44;p[9]=6;p[12]=10;p[15]=sport;p[16]=10;p[19]=dest;p[20]=sport;p[22]=dest;return p;
}
int main(){
  PoolAffinity affinity;std::vector<std::uint64_t> ids={7,11};
  auto a=ipv4(12,2),b=ipv4(13,3);
  const auto first=affinity.choose(a,ids,1);
  for(int i=0;i<300;i++)assert(affinity.choose(a,ids,2+i)==first);
  const auto wanted=first==7?11:7;
  auto other=affinity.choose(b,ids,100,wanted);assert(other==wanted);
  assert(affinity.choose(a,ids,101,wanted)==first); // health preference 
  ids.push_back(15);assert(affinity.choose(a,ids,500)==first); 
  ids.erase(std::remove(ids.begin(),ids.end(),first),ids.end());
  const auto migrated=affinity.choose(a,ids,600);assert(migrated!=first);
  std::array<unsigned char,32> key1{},key2{};key1.fill(0x11);key2.fill(0x22);
  RecordDecoderV5 d1(key1,65536),d2(key2,65536);std::string error;
  int n1=0,n2=0;
  for(std::uint64_t seq=1;seq<=50;seq++){
    auto r1=encode_record_v5(key1,seq,a),r2=encode_record_v5(key2,seq,b);
    assert(d1.feed(r1,[&](auto,auto,std::span<const unsigned char> p){assert(p.size()==a.size());++n1;},error));
    assert(d2.feed(r2,[&](auto,auto,std::span<const unsigned char> p){assert(p.size()==b.size());++n2;},error));
  }
  assert(n1==50&&n2==50);
  auto wrong=encode_record_v5(key1,51,a);
  assert(!d2.feed(wrong,[](auto,auto,auto){},error)); // keys never interchangeable

  ids={1,2};for(int i=0;i<10000;i++){
    auto p=ipv4(static_cast<unsigned char>(i),static_cast<unsigned char>(i>>8));
    p[12]=static_cast<unsigned char>(i>>16);p[13]=static_cast<unsigned char>(i>>8);
    affinity.choose(p,ids,700+i);
  }
  assert(affinity.size()<=4096);
  std::cout<<"PTT7 pool affinity, per-lane authenticated sequence, bounded metadata OK\n";
}
