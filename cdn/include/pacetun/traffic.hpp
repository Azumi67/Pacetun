#pragma once
#include <algorithm>
#include <cstdint>
#include <random>
namespace pacetun {
// encrypted probe
// PONGs cannot postpone deadline
class ReplyWatchdog {
 uint64_t token_=0;
 public:
 bool pending()const{return token_!=0;}
 void sent(uint64_t token){if(!pending())token_=token;}
 uint64_t age_us(uint64_t now)const{return token_&&now>=token_?now-token_:0;}
 bool reply(uint64_t token,uint64_t now){
   if(!token_||token!=token_||now<token_)return false;
   token_=0;return true;
 }
};
class RecoveryBackoff {
 uint64_t next_=0;unsigned failures_=0;
 public:
 bool ready(uint64_t now)const{return now>=next_;}
 void started(uint64_t now){next_=now+30000000;}
 void failed(uint64_t now){failures_=std::min(5u,failures_+1);next_=now+uint64_t(std::min(300u,30u<<(failures_-1)))*1000000;}
 void succeeded(uint64_t now){failures_=0;next_=now+30000000;}
 uint64_t remaining_sec(uint64_t now)const{return now<next_?(next_-now+999999)/1000000:0;}
};
inline int traffic_interval_ms(int seconds,int jitter_pct,std::mt19937& rng){
  const int base=seconds*1000,spread=base*jitter_pct/100;
  return std::max(1,base+std::uniform_int_distribution<int>(-spread,spread)(rng));
}
class PaddingBudget {
 double data_=0,control_=128;uint64_t last_;int pct_;
 public:
 explicit PaddingBudget(int percent,uint64_t now):last_(now),pct_(percent){}
 int data_allowance(size_t bytes,int maximum){data_=std::min(4096.0,data_+bytes*pct_/100.0);return std::min(maximum+3,static_cast<int>(data_));}
 void spend_data(size_t extra){data_=std::max(0.0,data_-extra);}
 int control_allowance(int maximum,uint64_t now){if(now>=last_)control_=std::min(128.0,control_+(now-last_)*64.0/1000000.0);last_=now;return std::min(maximum+3,static_cast<int>(control_));}
 void spend_control(size_t extra){control_=std::max(0.0,control_-extra);}
};
// padding budget shared by every lane, including control padding
// shaping enabled: extra = burst + rate * elapsed & existing budgets
class ShapeBudget {
 double tokens_; uint64_t last_; int rate_, burst_; bool enabled_;
 public:
 ShapeBudget(bool enabled,int rate,int burst,uint64_t now):tokens_(burst),last_(now),rate_(rate),burst_(burst),enabled_(enabled){}
 int allowance(int requested,uint64_t now){
  if(!enabled_)return requested;
  if(now>last_)tokens_=std::min(double(burst_),tokens_+double(now-last_)*rate_/1000000.0);
  last_=now;return std::min(requested,static_cast<int>(tokens_));
 }
 void spend(size_t n){if(enabled_)tokens_=std::max(0.0,tokens_-n);}
};
// per lane startup/interactive/bulk state
class BurstShaper {
 uint64_t start_,window_,bytes_=0,due_=0; std::mt19937 rng_;
 public:
 explicit BurstShaper(uint64_t now):start_(now),window_(now),rng_(std::random_device{}()){}
 void observe(size_t n,uint64_t now){if(now-window_>=1000000){window_=now;bytes_=0;}bytes_+=n;}
 bool bulk(uint64_t now)const{return now-window_<1000000 && bytes_>=65536;}
 int maximum(int configured,int startup_ms,uint64_t now)const{
  return std::min(configured,now-start_<uint64_t(startup_ms)*1000?256:(bulk(now)?16:96));
 }
 bool ready(size_t packets,uint64_t age_us,int max_delay_ms,uint64_t now){
  if(!packets){due_=0;return false;}
  if(!max_delay_ms || packets>=8 || bulk(now) || age_us>=uint64_t(max_delay_ms)*1000){due_=0;return true;}
  if(!due_)due_=now+std::uniform_int_distribution<int>(0,max_delay_ms*1000)(rng_);
  if(now>=due_){due_=0;return true;}return false;
 }
};

class LatencyRenewal {
 uint64_t sample_=0,last_attempt_=0;int streak_=0;bool attempted_=false;
 public:
 bool observe(uint64_t sample,int64_t rtt_us,uint64_t now,bool active,int threshold_ms,int required,int cooldown_sec){
   if(!active){streak_=0;sample_=sample;return false;}
   if(!sample||sample==sample_||sample>now)return false;
   sample_=sample;
   if(now-sample>60000000||threshold_ms<=0||rtt_us<=int64_t(threshold_ms)*1000){streak_=0;return false;}
   ++streak_;
   if(streak_<required||(attempted_&&now-last_attempt_<uint64_t(cooldown_sec)*1000000))return false;
   streak_=0;last_attempt_=now;attempted_=true;return true;
 }
 void reset_samples(){streak_=0;sample_=0;}
};
}
