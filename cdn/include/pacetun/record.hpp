#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace pacetun {
constexpr std::uint8_t RECORD_KEEPALIVE = 0x01;
constexpr std::uint8_t RECORD_PING      = 0x02;
constexpr std::uint8_t RECORD_PONG      = 0x04;
constexpr std::uint8_t RECORD_DRAIN     = 0x08; 

constexpr std::uint8_t RECORD_PADDED = 0x10; 
constexpr std::uint8_t RECORD_ENVELOPE = 0x20; // authenticated flags + length + padding
using Key32 = std::array<unsigned char, 32>;
struct SessionKeys { Key32 client_tx{}, server_tx{}, auth{}; ~SessionKeys(); };
struct X25519KeyPair { Key32 private_key{}, public_key{}; };

std::vector<unsigned char> read_psk(const std::string& path);
std::string random_nonce_hex();

SessionKeys derive_session_keys(std::span<const unsigned char> psk,
                                const std::string& server_nonce_hex,
                                const std::string& client_nonce_hex);
std::string handshake_token(std::span<const unsigned char> auth_key,
                            const std::string& authority,
                            const std::string& path,
                            const std::string& server_nonce_hex,
                            const std::string& client_nonce_hex);
std::vector<unsigned char> encode_record(std::span<const unsigned char> key,
                                         std::uint64_t seq,
                                         std::span<const unsigned char> payload,
                                         std::uint8_t flags = 0);

SessionKeys derive_session_keys_v4(std::span<const unsigned char> psk,
                                   const std::string& server_nonce_hex,
                                   const std::string& client_nonce_hex);
std::string websocket_auth_token(std::span<const unsigned char> psk,
                                 const std::string& authority,
                                 const std::string& path,
                                 const std::string& client_nonce_hex);
std::vector<unsigned char> encode_record_v4(std::span<const unsigned char> key,
                                            std::uint64_t seq,
                                            std::span<const unsigned char> payload,
                                            std::uint8_t flags = 0);

X25519KeyPair generate_x25519_keypair();
Key32 x25519_shared_secret(std::span<const unsigned char> private_key,
                           std::span<const unsigned char> peer_public_key);
std::string key32_hex(std::span<const unsigned char> key);
Key32 key32_from_hex(const std::string& hex);
std::string websocket_client_auth_token_v5(std::span<const unsigned char> psk,
                                           const std::string& authority,
                                           const std::string& path,
                                           const std::string& client_nonce_hex,
                                           const std::string& client_public_hex);
std::string websocket_server_proof_v5(std::span<const unsigned char> psk,
                                      const std::string& authority,
                                      const std::string& path,
                                      const std::string& client_nonce_hex,
                                      const std::string& server_nonce_hex,
                                      const std::string& client_public_hex,
                                      const std::string& server_public_hex);
SessionKeys derive_session_keys_v5(std::span<const unsigned char> psk,
                                   std::span<const unsigned char> shared_secret,
                                   const std::string& server_nonce_hex,
                                   const std::string& client_nonce_hex,
                                   std::span<const unsigned char> client_public_key,
                                   std::span<const unsigned char> server_public_key);
std::vector<unsigned char> encode_record_v5(std::span<const unsigned char> key,
                                            std::uint64_t seq,
                                            std::span<const unsigned char> payload,
                                            std::uint8_t flags = 0);

std::vector<unsigned char> encode_padded_record_v5(std::span<const unsigned char> key, std::uint64_t seq, std::span<const unsigned char> payload, int max_padding);

std::vector<unsigned char> encode_envelope_record_v5(std::span<const unsigned char> key, std::uint64_t seq, std::span<const unsigned char> payload, std::uint8_t flags, int max_padding);

class RecordDecoder {
 public:
  using Callback = std::function<void(std::uint8_t,std::uint64_t,std::span<const unsigned char>)>;
  RecordDecoder(std::span<const unsigned char> key, std::size_t max_buffer_bytes);
  bool feed(std::span<const unsigned char> bytes,const Callback& on_record,std::string& error);
  std::uint64_t replay_drops() const { return replay_drops_; }
  std::uint64_t sequence_gaps() const { return sequence_gaps_; }
 private:
  bool verify_one(std::size_t total,std::string& error) const;
  std::vector<unsigned char> key_,buffer_;
  std::size_t max_buffer_bytes_;
  bool have_seq_ = false;
  std::uint64_t highest_seq_ = 0;
  std::uint64_t replay_drops_ = 0;
  std::uint64_t sequence_gaps_ = 0;
};

class RecordDecoderV4 {
 public:
  using Callback = std::function<void(std::uint8_t,std::uint64_t,std::span<const unsigned char>)>;
  RecordDecoderV4(std::span<const unsigned char> key, std::size_t max_buffer_bytes);
  bool feed(std::span<const unsigned char> bytes,const Callback& on_record,std::string& error);
  std::uint64_t replay_drops() const { return replay_drops_; }
  std::uint64_t sequence_gaps() const { return sequence_gaps_; }
 private:
  std::vector<unsigned char> key_,buffer_;
  std::size_t max_buffer_bytes_;
  bool have_seq_ = false;
  std::uint64_t highest_seq_ = 0,replay_drops_=0,sequence_gaps_=0;
};

class RecordDecoderV5 {
 public:
  using Callback = std::function<void(std::uint8_t,std::uint64_t,std::span<const unsigned char>)>;
  RecordDecoderV5(std::span<const unsigned char> key, std::size_t max_buffer_bytes);
  ~RecordDecoderV5();
  bool feed(std::span<const unsigned char> bytes,const Callback& on_record,std::string& error);
  std::uint64_t replay_drops() const { return replay_drops_; }
  std::uint64_t sequence_gaps() const { return sequence_gaps_; }
 private:
  std::vector<unsigned char> key_,buffer_;
  std::size_t max_buffer_bytes_;
  bool have_seq_ = false;
  std::uint64_t highest_seq_ = 0,replay_drops_=0,sequence_gaps_=0;
};
}
