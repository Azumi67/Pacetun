#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root/adapter"
GOTOOLCHAIN=local go test -mod=vendor -count=1 ./...
GOTOOLCHAIN=local go test -mod=vendor -race -count=1 ./...
output="${PACETUN_BRIDGE_OUTPUT:-$root/../../pacetun-utls-bridge-rebuilt}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local go build -mod=vendor -trimpath -buildvcs=false -ldflags='-s -w' -o "$output" .
"$output" -version
printf 'Built candidate: %s\n' "$output"
