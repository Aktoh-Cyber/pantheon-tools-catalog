#!/usr/bin/env bash
# Build fs-list as a wasm32-wasip2 component and emit a digest-named copy at
# `out/<sha256>.wasm`. The hash is printed to stdout so the publish workflow
# can capture it for the OCI tag.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${HERE}/out}"

mkdir -p "${OUT_DIR}"

pushd "${HERE}" >/dev/null
cargo build --release --target wasm32-wasip2
popd >/dev/null

src="${HERE}/target/wasm32-wasip2/release/package-inventory.wasm"
hash="$(shasum -a 256 "${src}" | awk '{print $1}')"
cp "${src}" "${OUT_DIR}/${hash}.wasm"

echo "${hash}"
