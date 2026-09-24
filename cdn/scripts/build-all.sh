#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
build_dir="${PACETUN_BUILD_DIR:-$root/../../pacetun-build56}"
cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" -j "${BUILD_JOBS:-2}"
ctest --test-dir "$build_dir" --output-on-failure
python3 "$root/tests/install56_test.py"
(cd "$root/adapter" && GOTOOLCHAIN=local go test -mod=vendor -race -count=1 ./...)
echo 'Tests passed. Build release executables separately; do not mistake local tests for Arvan validation.'
