#include "pacetun/carrier.hpp"
#include "pacetun/websocket.hpp"

namespace pacetun {
std::string_view WebSocketCarrier::name() const{return "websocket";}
int WebSocketCarrier::native_fd() const{return ws_.fd;}
void WebSocketCarrier::send(std::span<const unsigned char>payload){websocket_send_binary(ws_,payload);}
std::vector<std::vector<unsigned char>> WebSocketCarrier::read(int timeout_ms){return websocket_read_messages(ws_,timeout_ms);}
std::size_t WebSocketCarrier::flush(std::size_t byte_budget){return websocket_flush(ws_,byte_budget);}
bool WebSocketCarrier::tx_pending() const{return websocket_tx_pending(ws_);}
short WebSocketCarrier::tx_poll_events() const{return websocket_tx_poll_events(ws_);}
short WebSocketCarrier::rx_poll_events() const{return websocket_rx_poll_events(ws_);}
std::size_t WebSocketCarrier::tx_pending_bytes() const{return websocket_tx_queued_bytes(ws_);}
bool WebSocketCarrier::tx_stalled(int timeout_ms) const{return websocket_tx_stalled(ws_,timeout_ms);}
void WebSocketCarrier::send_ping(std::span<const unsigned char>payload){websocket_send_ping(ws_,payload);}
std::vector<std::vector<unsigned char>> WebSocketCarrier::take_pongs(){return websocket_take_pongs(ws_);}
CarrierCounters WebSocketCarrier::counters() const{
  return CarrierCounters{ws_.rx_frames,ws_.rx_ping_frames,ws_.rx_pong_frames,
                         ws_.tx_binary_frames,ws_.tx_binary_payload_bytes,
                         ws_.tx_ping_frames,ws_.tx_pong_frames};
}
}
