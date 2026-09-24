#include "pacetun/logging.hpp"
#include <cassert>
#include <iostream>
#include <string>
int main(){
  using namespace pacetun;
  auto bad=explain_problem("WEBSOCKET_UPGRADE_FAILED","WebSocket upgrade rejected: HTTP/1.1 502 Bad Gateway");
  assert(std::string(bad.meaning).find("CDN OR origin")!=std::string::npos);
  auto slow=explain_problem("WEBSOCKET_UPGRADE_FAILED","HTTP/1.1 504 Gateway Time-out");
  assert(std::string(slow.meaning).find("504")!=std::string::npos);
  assert(std::string(explain_problem("HTTP_502_GATEWAY").meaning).find("502")!=std::string::npos);
  assert(std::string(explain_problem("HTTP_504_TIMEOUT").meaning).find("504")!=std::string::npos);
  assert(std::string(explain_problem("WEBSOCKET_PEER_CLOSE").meaning).find("CDN")!=std::string::npos);
  auto auth=explain_problem("AUTHENTICATION_FAILED");
  assert(std::string(auth.next_step).find("PSK")!=std::string::npos);
  auto output=friendly_failure("CARRIER_UPGRADE","WEBSOCKET_UPGRADE_FAILED","HTTP/1.1 502 Bad Gateway\nInjected line");
  assert(output.find("Next step:")!=std::string::npos);
  assert(output.find("Bad Gateway\nInjected")==std::string::npos);
  assert(format_bytes_rate(0)=="0 B/s");
  assert(format_bytes_rate(2048)=="2.0 KiB/s");
  assert(format_bytes_rate(1048576)=="1.0 MiB/s");
  assert(std::string(explain_problem("TCP_CONNECT_FAILED").meaning).find("TCP")!=std::string::npos);
  if(std::string(explain_problem("TCP_CONNECT_TIMEOUT").meaning).find("TCP")==std::string::npos)
    throw std::runtime_error("TCP timeout explanation missing");
  if(std::string(explain_problem("TLS_CERTIFICATE_FAILED").next_step).find("Never disable")==std::string::npos)
    throw std::runtime_error("certificate security advice missing");
  std::cout<<"human logging explanations, error formatting and rate display: PASS\n";
}
