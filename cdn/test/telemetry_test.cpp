#include "pacetun/telemetry.hpp"
#include <cassert>
#include <iostream>
int main(){
 pacetun::RttHistory h;auto s=h.snapshot();assert(s.count==0&&s.p50_ms<0);
 for(unsigned i=1;i<=100;i++)h.record(i*1000,i%2==0);
 s=h.snapshot();assert(s.count==100&&s.p50_ms==50&&s.p95_ms==95&&s.p99_ms==99);
 auto active=h.snapshot(1);assert(active.count==50&&active.p50_ms==50&&active.p95_ms==96);
 assert(h.snapshot(2).count==50);
 for(unsigned i=0;i<250;i++)h.record(1000,false);
 assert(h.snapshot().count==128&&h.snapshot().p99_ms==1);
 h.reset();assert(h.snapshot().count==0);
 std::cout<<"RTT telemetry percentile/bound/reset PASS\n";
}
