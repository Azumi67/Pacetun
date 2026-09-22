#pragma once
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

namespace pacetun
{
  struct ProblemExplanation
  {
    const char *meaning;
    const char *next_step;
  };
  inline bool contains_insensitive(std::string_view text, std::string_view pattern)
  {
    auto eq = [](char a, char b)
    { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); };
    return std::search(text.begin(), text.end(), pattern.begin(), pattern.end(), eq) != text.end();
  }
  inline ProblemExplanation explain_problem(std::string_view code, std::string_view detail = {})
  {
    if (code == "HTTP_502_GATEWAY" || (contains_insensitive(detail, "502") && (contains_insensitive(detail, "bad gateway") || contains_insensitive(detail, "http/1.1 502"))))
      return {"A gateway returned HTTP 502 while opening the tunnel. The CDN OR origin proxy may be responsible.",
              "Check the foreign Nginx IPv6 listener and error/access logs. Verify Arvan's origin IPv6 and local PaceTun port; also test the health URL via the CDN."};
    if (code == "HTTP_504_TIMEOUT" || (contains_insensitive(detail, "504") && (contains_insensitive(detail, "gateway") || contains_insensitive(detail, "http/1.1 504"))))
      return {"A gateway returned HTTP 504: an upstream response was too slow or absent.",
              "Compare CDN health-check timings with a direct foreign-origin check. Inspect Arvan-to-origin reachability and Nginx logs; do not assume the Iran-to-edge connection is slow."};
    if (contains_insensitive(detail, "certificate") || contains_insensitive(detail, "hostname verification") || contains_insensitive(detail, "verify failed"))
      return {"The TLS certificate or hostname check failed.",
              "Check the CDN hostname, SNI, certificate validity and trusted CA path; keep TLS verification enabled."};
    if (contains_insensitive(detail, "name or service not known") || contains_insensitive(detail, "temporary failure in name resolution"))
      return {"The tunnel hostname could not be resolved by DNS.",
              "Check DNS resolution for the configured CDN hostname on the client. Do not replace the origin address until DNS is verified."};
    if (code == "DNS_RESOLUTION_FAILED")
      return {"DNS could not resolve the configured CDN hostname.", "Check the DNS resolver and the saved hostname on the Iran client; do not assume the foreign origin is failing."};
    if (code == "WEBSOCKET_UPGRADE_FAILED" || code == "CARRIER_UPGRADE_FAILED")
      return {"The HTTPS connection did not complete the WebSocket upgrade.",
              "Confirm the CDN accepts WebSocket and the Host/path match Nginx. Test HTTPS health, then inspect Nginx access and error logs for the upgrade path."};
    if (code == "AUTHENTICATION_FAILED")
      return {"The endpoints could not authenticate or agree on session keys.",
              "Check that both servers use the intended PSK and compatible versions. Never paste PSK contents into logs or support chats."};
    if (code == "AUTH_PROBE_TIMEOUT")
      return {"An authenticated round-trip probe did not receive a reply in time.",
              "Look for simultaneous network loss or CDN buffering. Compare fresh tunnel RTT and TCP retransmission counters; one timeout alone does not identify the faulty segment."};
    if (code == "WEBSOCKET_PONG_TIMEOUT")
      return {"An optional WebSocket control PONG did not arrive before its deadline.",
              "Check whether WebSocket control probes are enabled and whether CDN idle or buffering behavior affects the session."};
    if (code == "TCP_CONNECT_TIMEOUT")
      return {"TCP attempts to DNS-resolved CDN addresses timed out; the failed segment is not identified.",
              "Check client-to-CDN reachability, DNS answers and CDN edge availability. Changing tunnel encryption cannot fix a TCP timeout."};
    if (code == "TLS_CERTIFICATE_FAILED")
      return {"TLS peer certificate validation failed; the connection was correctly rejected.",
              "Verify the configured hostname, CA trust and CDN certificate. Never disable verify_peer as a workaround."};
    if (code == "TLS_HANDSHAKE_TIMEOUT")
      return {"TCP connected but TLS did not finish before its deadline.",
              "Check CDN edge TLS availability and compare from another network; no assumption about the origin can be made yet."};
    if (code == "TCP_CONNECT_FAILED")
      return {"The client could not establish its TCP connection to the configured destination.",
              "Check DNS, the destination port, routing and the CDN endpoint from the client. On the origin, check listeners and firewall rules."};
    if (code == "TLS_HANDSHAKE_FAILED")
      return {"TCP connected, but the TLS handshake could not finish.",
              "Check the hostname/SNI, HTTPS port, supported TLS versions, certificate and CDN TLS settings."};
    if (code == "WEBSOCKET_PEER_CLOSE")
      return {"The peer sent a WebSocket close frame; the sender behind a CDN is not established.",
              "Compare close status, session age, Nginx logs and CDN timing. A close frame alone does not identify the responsible hop."};
    if (code == "MANUAL_RECONNECT")
      return {"An administrator requested a reconnection.", "No network failure is implied; verify the replacement becomes ONLINE."};
    if (code == "ESTABLISHED_CONNECTION_LOST")
      return {"An established tunnel connection was interrupted.",
              "Inspect the detailed error, recent tunnel RTT, retransmissions and CDN/foreign logs. A disconnect alone does not prove which hop failed."};
    return {"An issue was reported, but the cause is not established.",
            "Inspect the detailed error and run the read-only diagnose command; preserve the working configuration until the failure is located."};
  }
  inline std::string clean_log_detail(std::string_view raw)
  {
    std::string out;
    out.reserve(std::min<std::size_t>(raw.size(), 240));
    for (char c : raw)
    {
      if (out.size() == 240)
      {
        out += "...";
        break;
      }
      unsigned char u = static_cast<unsigned char>(c);
      out += (u < 32 || u == 127) ? ' ' : c;
    }
    return out;
  }
  inline std::string friendly_failure(std::string_view stage, std::string_view code, std::string_view detail)
  {
    auto problem = explain_problem(code, detail);
    return std::string("[ERROR] Connection problem (code=") + std::string(code) + ", stage=" + std::string(stage) + ")\n" + "        Meaning: " + problem.meaning + "\n" + "        Next step: " + problem.next_step + "\n" + "        Technical detail: " + clean_log_detail(detail) + "\n";
  }
  inline std::string format_bytes_rate(uint64_t bytes_per_second)
  {
    std::ostringstream o;
    o << std::fixed << std::setprecision(1);
    if (bytes_per_second >= 1024ull * 1024ull)
      o << double(bytes_per_second) / (1024.0 * 1024.0) << " MiB/s";
    else if (bytes_per_second >= 1024)
      o << double(bytes_per_second) / 1024.0 << " KiB/s";
    else
      o << bytes_per_second << " B/s";
    return o.str();
  }
}
