#!/usr/bin/env bash
# Build port-scan as wasm32-wasip2 and emit out/<sha256>.wasm; print the digest.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${HERE}/out}"
mkdir -p "${OUT_DIR}"
pushd "${HERE}" >/dev/null
cargo build --release --target wasm32-wasip2
popd >/dev/null
src="${HERE}/target/wasm32-wasip2/release/port-scan.wasm"
hash="$(shasum -a 256 "${src}" | awk '{print $1}')"
cp "${src}" "${OUT_DIR}/${hash}.wasm"
echo "${hash}"
