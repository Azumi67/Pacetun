#pragma once
#include <string>
#include <span>
#include <cstddef>

namespace pacetun {
  // non-destructive validation
  void validate_tun_inputs(const std::string &dev, const std::string &cidr,
                           const std::string &peer_cidr, int mtu);
  class TunDevice
  {
  public:
    TunDevice(const std::string &dev, const std::string &cidr,
              const std::string &peer_cidr, int mtu);
    ~TunDevice();
    TunDevice(const TunDevice &) = delete;
    TunDevice &operator=(const TunDevice &) = delete;
    // packet-I/O for future TUN implementations
    int poll_fd() const { return fd_; }
    std::ptrdiff_t read_packet(std::span<unsigned char> packet);
    std::ptrdiff_t write_packet(std::span<const unsigned char> packet);
    const std::string &name() const { return name_; }

  private:
    int fd_ = -1;
    std::string name_;
  };
}
