#include "pacetun/traffic.hpp"
#include <cassert>
#include <iostream>
using namespace pacetun;
int main(){
 ShapeBudget all(true,100,200,1000000);size_t total=0;
 for(unsigned i=0;i<10000;++i){auto n=all.allowance(43,1000000+i*1000);all.spend(n);total+=n;assert(total<=200+i/10);}
 ShapeBudget off(true,0,0,0);assert(off.allowance(400,99999999)==0);
 PaddingBudget relative(5,0);ShapeBudget absolute(true,4096,4096,0);size_t extra=0;
 for(unsigned i=0;i<1000;++i){int n=absolute.allowance(relative.data_allowance(128,256),i*1000);relative.spend_data(n);absolute.spend(n);extra+=n;assert(extra<=(i+1)*128*5/100);}
 BurstShaper sh(1000000);assert(sh.maximum(512,1500,1000000)==256);assert(sh.maximum(512,1500,3000000)==96);
 sh.observe(65536,3000000);assert(sh.maximum(512,1500,3000000)==16);assert(sh.ready(1,0,10,3000000));
 assert(sh.maximum(512,1500,5000000)==96);
 assert(sh.ready(1,3000,3,5000000));assert(sh.ready(8,0,3,5000000));
 std::cout<<"shared absolute/relative padding caps and burst scheduling PASS\n";
}
