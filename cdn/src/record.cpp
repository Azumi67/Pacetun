#include "pacetun/record.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace pacetun { namespace {
Key32 mac(std::span<const unsigned char> key,std::span<const unsigned char> data){
  Key32 out{};unsigned int n=0;
  if(key.size()>static_cast<std::size_t>(std::numeric_limits<int>::max()))throw std::runtime_error("HMAC key too large");
  if(!HMAC(EVP_sha256(),key.data(),static_cast<int>(key.size()),data.data(),data.size(),out.data(),&n)||n!=out.size())throw std::runtime_error("HMAC-SHA256 failed");
  return out;
}
int hex_nibble(unsigned char c){
  if(c>='0'&&c<='9')return c-'0';
  if(c>='a'&&c<='f')return c-'a'+10;
  if(c>='A'&&c<='F')return c-'A'+10;
  return -1;
}
std::vector<unsigned char> hex_decode(const std::string&s){
  if(s.size()%2)throw std::runtime_error("invalid hex");
  std::vector<unsigned char>v;v.reserve(s.size()/2);
  for(size_t i=0;i<s.size();i+=2){
    const int hi=hex_nibble(static_cast<unsigned char>(s[i]));
    const int lo=hex_nibble(static_cast<unsigned char>(s[i+1]));
    if(hi<0||lo<0)throw std::runtime_error("invalid hex");
    v.push_back(static_cast<unsigned char>((hi<<4)|lo));
  }
  return v;
}
std::string hex_encode(std::span<const unsigned char> v){
  std::ostringstream o;
  for(auto b:v)o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b;
  return o.str();
}
Key32 hkdf_expand_one(std::span<const unsigned char> prk,const std::string&label){
  std::vector<unsigned char>d(label.begin(),label.end());d.push_back(1);return mac(prk,d);
}
std::array<unsigned char,12> nonce12_label(std::span<const unsigned char> key,uint64_t seq,std::string_view label){
  auto p=mac(key,std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(label.data()),label.size()));
  std::array<unsigned char,12>n{};std::copy_n(p.begin(),4,n.begin());
  for(int i=0;i<8;++i)n[4+i]=static_cast<unsigned char>((seq>>(56-8*i))&0xff);
  return n;
}
void validate_record_shape(uint8_t flags,uint16_t len,const char* wire){
  if(flags==RECORD_ENVELOPE && std::string_view(wire)=="PTT5") {if(len<3)throw std::runtime_error("invalid envelope length");return;}
  if(flags==RECORD_PADDED && std::string_view(wire)=="PTT5") { if(len<22) throw std::runtime_error("invalid padded record length"); return; }
  if(flags==RECORD_DRAIN && std::string_view(wire)=="PTT5") {if(len!=0)throw std::runtime_error("invalid drain length");return;}
  const uint8_t known=RECORD_KEEPALIVE|RECORD_PING|RECORD_PONG;
  if((flags&~known)!=0)throw std::runtime_error(std::string("unknown ")+wire+" flags");
  if(flags!=0&&flags!=RECORD_KEEPALIVE&&flags!=RECORD_PING&&flags!=RECORD_PONG)
    throw std::runtime_error(std::string("ambiguous ")+wire+" control flags");
  if(flags==0&&len<20)throw std::runtime_error("invalid inner packet length");
  if(flags==RECORD_KEEPALIVE&&len!=0)throw std::runtime_error("invalid keepalive");
  if((flags==RECORD_PING||flags==RECORD_PONG)&&len!=8)throw std::runtime_error("invalid control record");
}
std::vector<unsigned char> encode_aead_record(std::span<const unsigned char>key,uint64_t seq,
                                              std::span<const unsigned char>payload,uint8_t flags,
                                              char magic4,uint8_t version,std::string_view nonce_label){
  if(key.size()!=32)throw std::runtime_error("AEAD key must be 32 bytes");
  if(seq==0)throw std::runtime_error("record sequence exhausted");
  if(payload.size()>65535)throw std::runtime_error("packet too large");
  validate_record_shape(flags,static_cast<uint16_t>(payload.size()),magic4=='5'?"PTT5":"PTT4");
  std::vector<unsigned char>v(16+payload.size()+16);
  v[0]='P';v[1]='T';v[2]='T';v[3]=static_cast<unsigned char>(magic4);v[4]=version;v[5]=flags;
  v[6]=static_cast<unsigned char>((payload.size()>>8)&0xff);v[7]=static_cast<unsigned char>(payload.size()&0xff);
  for(int i=0;i<8;++i)v[8+i]=static_cast<unsigned char>((seq>>(56-8*i))&0xff);
  auto n=nonce12_label(key,seq,nonce_label);
  EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new();if(!ctx)throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  int out=0,total=0;
  bool ok=EVP_EncryptInit_ex(ctx,EVP_chacha20_poly1305(),nullptr,nullptr,nullptr)==1&&
          EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_IVLEN,static_cast<int>(n.size()),nullptr)==1&&
          EVP_EncryptInit_ex(ctx,nullptr,nullptr,key.data(),n.data())==1&&
          EVP_EncryptUpdate(ctx,nullptr,&out,v.data(),16)==1&&
          EVP_EncryptUpdate(ctx,v.data()+16,&out,payload.data(),static_cast<int>(payload.size()))==1;
  total=out;ok=ok&&EVP_EncryptFinal_ex(ctx,v.data()+16+total,&out)==1;total+=out;
  ok=ok&&EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,16,v.data()+16+payload.size())==1;
  EVP_CIPHER_CTX_free(ctx);
  if(!ok||total!=static_cast<int>(payload.size()))throw std::runtime_error("ChaCha20-Poly1305 encrypt failed");
  return v;
}
bool feed_aead(std::vector<unsigned char>&buffer,std::span<const unsigned char>key,std::size_t max_buffer_bytes,
               bool&have_seq,uint64_t&highest_seq,uint64_t&replay_drops,uint64_t&sequence_gaps,
               std::span<const unsigned char>bytes,
               const std::function<void(uint8_t,uint64_t,std::span<const unsigned char>)>&cb,
               std::string&error,char magic4,uint8_t version,std::string_view nonce_label){
  if(buffer.size()+bytes.size()>max_buffer_bytes){error="record buffer limit exceeded";return false;}
  buffer.insert(buffer.end(),bytes.begin(),bytes.end());
  while(true){
    if(buffer.size()<16)return true;
    if(!(buffer[0]=='P'&&buffer[1]=='T'&&buffer[2]=='T'&&buffer[3]==static_cast<unsigned char>(magic4))||buffer[4]!=version){
      error=std::string("PTT")+magic4+" record mismatch";return false;
    }
    uint8_t flags=buffer[5];uint16_t len=static_cast<uint16_t>((buffer[6]<<8)|buffer[7]);
    try{validate_record_shape(flags,len,magic4=='5'?"PTT5":"PTT4");}catch(const std::exception&e){error=e.what();return false;}
    size_t total=16u+len+16u;if(total>max_buffer_bytes){error="record exceeds buffer limit";return false;}if(buffer.size()<total)return true;
    uint64_t seq=0;for(int i=0;i<8;++i)seq=(seq<<8)|buffer[8+i];
    if(seq==0){error="invalid record sequence";return false;}
    auto n=nonce12_label(key,seq,nonce_label);std::vector<unsigned char>plain(len);
    EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new();int out=0,totalp=0;
    bool ok=ctx&&EVP_DecryptInit_ex(ctx,EVP_chacha20_poly1305(),nullptr,nullptr,nullptr)==1&&
            EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_IVLEN,static_cast<int>(n.size()),nullptr)==1&&
            EVP_DecryptInit_ex(ctx,nullptr,nullptr,key.data(),n.data())==1&&
            EVP_DecryptUpdate(ctx,nullptr,&out,buffer.data(),16)==1&&
            EVP_DecryptUpdate(ctx,plain.data(),&out,buffer.data()+16,len)==1;
    totalp=out;
    ok=ok&&EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG,16,buffer.data()+16+len)==1&&EVP_DecryptFinal_ex(ctx,plain.data()+totalp,&out)==1;
    totalp+=out;if(ctx)EVP_CIPHER_CTX_free(ctx);
    if(!ok||totalp!=len){error="record authentication failed";return false;}
    if(have_seq&&seq<=highest_seq){++replay_drops;error="record replay detected";return false;}
    if(have_seq&&seq>highest_seq+1)sequence_gaps+=seq-highest_seq-1;
    highest_seq=seq;have_seq=true;
    if(flags==RECORD_ENVELOPE) {
      const uint8_t inner_flags=plain[0];const size_t inner=(static_cast<size_t>(plain[1])<<8)|plain[2];
      if((inner_flags!=0&&inner_flags!=RECORD_KEEPALIVE&&inner_flags!=RECORD_PING&&inner_flags!=RECORD_PONG)||inner>plain.size()-3||plain.size()-3-inner>1024){error="invalid envelope payload";return false;}
      try{validate_record_shape(inner_flags,static_cast<uint16_t>(inner),"PTT5");}catch(const std::exception&e){error=e.what();return false;}
      cb(inner_flags,seq,std::span<const unsigned char>(plain.data()+3,inner));
    } else if(flags==RECORD_PADDED) {
      const size_t inner=(static_cast<size_t>(plain[0])<<8)|plain[1];
      if(inner<20 || inner>plain.size()-2 || plain.size()-2-inner>1024) {error="invalid padded payload";return false;}
      cb(0,seq,std::span<const unsigned char>(plain.data()+2,inner));
    } else cb(flags,seq,plain);
    buffer.erase(buffer.begin(),buffer.begin()+static_cast<std::ptrdiff_t>(total));
  }
}
}

SessionKeys::~SessionKeys(){OPENSSL_cleanse(client_tx.data(),client_tx.size());OPENSSL_cleanse(server_tx.data(),server_tx.size());OPENSSL_cleanse(auth.data(),auth.size());}
RecordDecoderV5::~RecordDecoderV5(){OPENSSL_cleanse(key_.data(),key_.size());}

std::vector<unsigned char> read_psk(const std::string& path){
  std::ifstream f(path,std::ios::binary);if(!f)throw std::runtime_error("cannot open psk_file: "+path);
  std::vector<unsigned char>v((std::istreambuf_iterator<char>(f)),{});
  while(!v.empty()&&(v.back()=='\n'||v.back()=='\r'||v.back()==' '||v.back()=='\t'))v.pop_back();
  if(v.size()<32)throw std::runtime_error("PSK must contain at least 32 bytes");
  return v;
}
std::string random_nonce_hex(){std::array<unsigned char,32>b{};if(RAND_bytes(b.data(),static_cast<int>(b.size()))!=1)throw std::runtime_error("RAND_bytes failed");return hex_encode(b);}

SessionKeys derive_session_keys(std::span<const unsigned char> psk,const std::string&snonce,const std::string&cnonce){
  auto s=hex_decode(snonce),c=hex_decode(cnonce);if(s.size()!=32||c.size()!=32)throw std::runtime_error("nonce must be 32 bytes");
  std::vector<unsigned char>salt;salt.reserve(64);salt.insert(salt.end(),s.begin(),s.end());salt.insert(salt.end(),c.begin(),c.end());
  auto prk=mac(salt,psk);SessionKeys k;k.client_tx=hkdf_expand_one(prk,"pacetun-v3 client-to-server");k.server_tx=hkdf_expand_one(prk,"pacetun-v3 server-to-client");k.auth=hkdf_expand_one(prk,"pacetun-v3 handshake-auth");return k;
}
std::string handshake_token(std::span<const unsigned char> auth_key,const std::string&authority,const std::string&path,const std::string&snonce,const std::string&cnonce){
  std::string s="pacetun-tls-v3\n"+authority+"\n"+path+"\n"+snonce+"\n"+cnonce;auto m=mac(auth_key,std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()),s.size()));return hex_encode(m);
}
std::vector<unsigned char> encode_record(std::span<const unsigned char> key,uint64_t seq,std::span<const unsigned char> payload,uint8_t flags){
  if(payload.size()>65535)throw std::runtime_error("packet too large");
  std::vector<unsigned char>v(16+payload.size()+16);v[0]='P';v[1]='T';v[2]='T';v[3]='3';v[4]=3;v[5]=flags;v[6]=static_cast<unsigned char>((payload.size()>>8)&0xff);v[7]=static_cast<unsigned char>(payload.size()&0xff);for(int i=0;i<8;++i)v[8+i]=static_cast<unsigned char>((seq>>(56-8*i))&0xff);std::copy(payload.begin(),payload.end(),v.begin()+16);auto m=mac(key,std::span<const unsigned char>(v.data(),16+payload.size()));std::copy_n(m.begin(),16,v.begin()+16+payload.size());return v;
}
RecordDecoder::RecordDecoder(std::span<const unsigned char> key,std::size_t max_buffer_bytes):key_(key.begin(),key.end()),max_buffer_bytes_(max_buffer_bytes){}
bool RecordDecoder::verify_one(std::size_t total,std::string&error)const{auto m=mac(key_,std::span<const unsigned char>(buffer_.data(),total-16));if(CRYPTO_memcmp(m.data(),buffer_.data()+total-16,16)!=0){error="record authentication failed";return false;}return true;}
bool RecordDecoder::feed(std::span<const unsigned char> bytes,const Callback&on_record,std::string&error){
  if(buffer_.size()+bytes.size()>max_buffer_bytes_){error="record buffer limit exceeded";return false;}buffer_.insert(buffer_.end(),bytes.begin(),bytes.end());
  while(true){if(buffer_.size()<16)return true;if(!(buffer_[0]=='P'&&buffer_[1]=='T'&&buffer_[2]=='T'&&buffer_[3]=='3')){error="record magic mismatch";return false;}if(buffer_[4]!=3){error="unsupported record version";return false;}uint8_t flags=buffer_[5];uint16_t len=static_cast<uint16_t>((buffer_[6]<<8)|buffer_[7]);if(flags==0&&len<20){error="invalid inner packet length";return false;}if((flags&RECORD_KEEPALIVE)&&len!=0){error="invalid keepalive record";return false;}if((flags&(RECORD_PING|RECORD_PONG))&&len!=8){error="invalid RTT control record";return false;}if((flags&~(RECORD_KEEPALIVE|RECORD_PING|RECORD_PONG))!=0){error="unknown record flags";return false;}size_t total=16u+len+16u;if(total>max_buffer_bytes_){error="record exceeds configured buffer limit";return false;}if(buffer_.size()<total)return true;if(!verify_one(total,error))return false;uint64_t seq=0;for(int i=0;i<8;++i)seq=(seq<<8)|buffer_[8+i];if(have_seq_){if(seq<=highest_seq_){++replay_drops_;error="record replay or reordering detected";return false;}if(seq>highest_seq_+1)sequence_gaps_+=seq-highest_seq_-1;}highest_seq_=seq;have_seq_=true;on_record(flags,seq,std::span<const unsigned char>(buffer_.data()+16,len));buffer_.erase(buffer_.begin(),buffer_.begin()+static_cast<std::ptrdiff_t>(total));}
}

SessionKeys derive_session_keys_v4(std::span<const unsigned char> psk,const std::string&snonce,const std::string&cnonce){
  auto s=hex_decode(snonce),c=hex_decode(cnonce);if(s.size()!=32||c.size()!=32)throw std::runtime_error("nonce must be 32 bytes");std::vector<unsigned char>salt;salt.insert(salt.end(),s.begin(),s.end());salt.insert(salt.end(),c.begin(),c.end());auto prk=mac(salt,psk);SessionKeys k;k.client_tx=hkdf_expand_one(prk,"pacetun-v4 client-to-server");k.server_tx=hkdf_expand_one(prk,"pacetun-v4 server-to-client");k.auth=hkdf_expand_one(prk,"pacetun-v4 handshake-auth");return k;
}
std::string websocket_auth_token(std::span<const unsigned char>psk,const std::string&authority,const std::string&path,const std::string&cnonce){std::string s="pacetun-websocket-v4\n"+authority+"\n"+path+"\n"+cnonce;auto m=mac(psk,std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()),s.size()));return hex_encode(m);}
std::vector<unsigned char> encode_record_v4(std::span<const unsigned char>key,uint64_t seq,std::span<const unsigned char>payload,uint8_t flags){return encode_aead_record(key,seq,payload,flags,'4',4,"pacetun-v4-nonce");}
RecordDecoderV4::RecordDecoderV4(std::span<const unsigned char>key,std::size_t max):key_(key.begin(),key.end()),max_buffer_bytes_(max){}
bool RecordDecoderV4::feed(std::span<const unsigned char>bytes,const Callback&cb,std::string&error){return feed_aead(buffer_,key_,max_buffer_bytes_,have_seq_,highest_seq_,replay_drops_,sequence_gaps_,bytes,cb,error,'4',4,"pacetun-v4-nonce");}

X25519KeyPair generate_x25519_keypair(){
  EVP_PKEY_CTX*ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,nullptr);if(!ctx)throw std::runtime_error("X25519 context creation failed");
  EVP_PKEY*key=nullptr;bool ok=EVP_PKEY_keygen_init(ctx)==1&&EVP_PKEY_keygen(ctx,&key)==1;EVP_PKEY_CTX_free(ctx);
  if(!ok||!key){if(key)EVP_PKEY_free(key);throw std::runtime_error("X25519 key generation failed");}
  X25519KeyPair out;size_t privlen=out.private_key.size(),publen=out.public_key.size();
  ok=EVP_PKEY_get_raw_private_key(key,out.private_key.data(),&privlen)==1&&EVP_PKEY_get_raw_public_key(key,out.public_key.data(),&publen)==1&&privlen==32&&publen==32;
  EVP_PKEY_free(key);if(!ok)throw std::runtime_error("X25519 raw key export failed");return out;
}
Key32 x25519_shared_secret(std::span<const unsigned char>private_key,std::span<const unsigned char>peer_public_key){
  if(private_key.size()!=32||peer_public_key.size()!=32)throw std::runtime_error("X25519 keys must be 32 bytes");
  EVP_PKEY*priv=EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,nullptr,private_key.data(),private_key.size());
  EVP_PKEY*peer=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,nullptr,peer_public_key.data(),peer_public_key.size());
  if(!priv||!peer){if(priv)EVP_PKEY_free(priv);if(peer)EVP_PKEY_free(peer);throw std::runtime_error("X25519 key import failed");}
  EVP_PKEY_CTX*ctx=EVP_PKEY_CTX_new(priv,nullptr);Key32 out{};size_t n=out.size();
  bool ok=ctx&&EVP_PKEY_derive_init(ctx)==1&&EVP_PKEY_derive_set_peer(ctx,peer)==1&&EVP_PKEY_derive(ctx,out.data(),&n)==1&&n==out.size();
  if(ctx)EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);EVP_PKEY_free(priv);
  unsigned char nz=0;for(auto b:out)nz|=b;
  if(!ok||nz==0)throw std::runtime_error("X25519 shared secret derivation failed");
  return out;
}
std::string key32_hex(std::span<const unsigned char>key){if(key.size()!=32)throw std::runtime_error("key must be 32 bytes");return hex_encode(key);}
Key32 key32_from_hex(const std::string&hex){auto v=hex_decode(hex);if(v.size()!=32)throw std::runtime_error("key hex must encode 32 bytes");Key32 out{};std::copy(v.begin(),v.end(),out.begin());return out;}
std::string websocket_client_auth_token_v5(std::span<const unsigned char>psk,const std::string&authority,const std::string&path,const std::string&cnonce,const std::string&cpub){
  std::string s="pacetun-websocket-v5-client\n"+authority+"\n"+path+"\n"+cnonce+"\n"+cpub;auto m=mac(psk,std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()),s.size()));return hex_encode(m);
}
std::string websocket_server_proof_v5(std::span<const unsigned char>psk,const std::string&authority,const std::string&path,const std::string&cnonce,const std::string&snonce,const std::string&cpub,const std::string&spub){
  std::string s="pacetun-websocket-v5-server\n"+authority+"\n"+path+"\n"+cnonce+"\n"+snonce+"\n"+cpub+"\n"+spub;auto m=mac(psk,std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()),s.size()));return hex_encode(m);
}
SessionKeys derive_session_keys_v5(std::span<const unsigned char>psk,std::span<const unsigned char>shared,const std::string&snonce,const std::string&cnonce,std::span<const unsigned char>cpub,std::span<const unsigned char>spub){
  if(shared.size()!=32||cpub.size()!=32||spub.size()!=32)throw std::runtime_error("PTT5 key material must be 32 bytes");
  auto s=hex_decode(snonce),c=hex_decode(cnonce);if(s.size()!=32||c.size()!=32)throw std::runtime_error("nonce must be 32 bytes");
  std::vector<unsigned char>transcript;const std::string label="PaceTun-PTT5";transcript.insert(transcript.end(),label.begin(),label.end());transcript.insert(transcript.end(),s.begin(),s.end());transcript.insert(transcript.end(),c.begin(),c.end());transcript.insert(transcript.end(),cpub.begin(),cpub.end());transcript.insert(transcript.end(),spub.begin(),spub.end());
  Key32 salt{};SHA256(transcript.data(),transcript.size(),salt.data());
  std::vector<unsigned char>ikm;ikm.reserve(shared.size()+psk.size());ikm.insert(ikm.end(),shared.begin(),shared.end());ikm.insert(ikm.end(),psk.begin(),psk.end());
  auto prk=mac(salt,ikm);SessionKeys k;k.client_tx=hkdf_expand_one(prk,"pacetun-v5 client-to-server");k.server_tx=hkdf_expand_one(prk,"pacetun-v5 server-to-client");k.auth=hkdf_expand_one(prk,"pacetun-v5 transcript-auth");
  OPENSSL_cleanse(ikm.data(),ikm.size());return k;
}
std::vector<unsigned char> encode_record_v5(std::span<const unsigned char>key,uint64_t seq,std::span<const unsigned char>payload,uint8_t flags){return encode_aead_record(key,seq,payload,flags,'5',5,"pacetun-v5-nonce");}
std::vector<unsigned char> encode_padded_record_v5(std::span<const unsigned char> key,uint64_t seq,std::span<const unsigned char> payload,int max_padding){
  if(max_padding<0 || max_padding>1024)throw std::runtime_error("padding out of range");
  if(max_padding==0)return encode_record_v5(key,seq,payload);
  if(payload.size()<20 || payload.size()+2+max_padding>65535)throw std::runtime_error("invalid padded packet size");
  unsigned char r[2];if(RAND_bytes(r,2)!=1)throw std::runtime_error("padding RNG failed");
  const size_t pad=((static_cast<unsigned>(r[0])<<8)|r[1])%static_cast<unsigned>(max_padding+1);
  std::vector<unsigned char> out(2+payload.size()+pad);
  out[0]=static_cast<unsigned char>(payload.size()>>8);out[1]=static_cast<unsigned char>(payload.size());
  std::copy(payload.begin(),payload.end(),out.begin()+2);
  if(pad && RAND_bytes(out.data()+2+payload.size(),static_cast<int>(pad))!=1)throw std::runtime_error("padding RNG failed");
  return encode_record_v5(key,seq,out,RECORD_PADDED);
}
std::vector<unsigned char> encode_envelope_record_v5(std::span<const unsigned char> key,uint64_t seq,std::span<const unsigned char> payload,uint8_t flags,int max_padding){
  if(flags!=0&&flags!=RECORD_KEEPALIVE&&flags!=RECORD_PING&&flags!=RECORD_PONG)throw std::runtime_error("invalid envelope flags");
  if(max_padding<0||max_padding>1024||payload.size()+3+max_padding>65535)throw std::runtime_error("invalid envelope size");
  validate_record_shape(flags,static_cast<uint16_t>(payload.size()),"PTT5");
  unsigned char r[2];if(RAND_bytes(r,2)!=1)throw std::runtime_error("padding RNG failed");
  size_t pad=((static_cast<unsigned>(r[0])<<8)|r[1])%static_cast<unsigned>(max_padding+1);
  std::vector<unsigned char> out(3+payload.size()+pad);out[0]=flags;out[1]=static_cast<unsigned char>(payload.size()>>8);out[2]=static_cast<unsigned char>(payload.size());
  std::copy(payload.begin(),payload.end(),out.begin()+3);
  if(pad&&RAND_bytes(out.data()+3+payload.size(),static_cast<int>(pad))!=1)throw std::runtime_error("padding RNG failed");
  return encode_record_v5(key,seq,out,RECORD_ENVELOPE);
}
RecordDecoderV5::RecordDecoderV5(std::span<const unsigned char>key,std::size_t max):key_(key.begin(),key.end()),max_buffer_bytes_(max){}
bool RecordDecoderV5::feed(std::span<const unsigned char>bytes,const Callback&cb,std::string&error){return feed_aead(buffer_,key_,max_buffer_bytes_,have_seq_,highest_seq_,replay_drops_,sequence_gaps_,bytes,cb,error,'5',5,"pacetun-v5-nonce");}
}
