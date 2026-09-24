#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Linux ]] || { echo 'ERROR: Linux TUN backend only' >&2; exit 2; }
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo 'ERROR: only native Linux AMD64 and ARM64 builds are configured' >&2; exit 2 ;;
esac
mkdir -p bin
g++ -std=c++20 -O2 -pthread -static -Iinclude \
  src/main.cpp src/config.cpp src/platform/linux/tun_linux.cpp src/record.cpp \
  src/runtime.cpp src/websocket.cpp src/carrier.cpp src/admission.cpp \
  -lssl -lcrypto -lz -lzstd -ldl -o "bin/pacetun-cdn-linux-$arch"
file "bin/pacetun-cdn-linux-$arch"
"bin/pacetun-cdn-linux-$arch" --version
printf '%s\n' 'WARNING: Static glibc/OpenSSL can require compatible runtime NSS modules for DNS; verify on your target OS.'
