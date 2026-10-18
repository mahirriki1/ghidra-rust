#!/usr/bin/env bash
# Build, check and package on native Linux x64. Does not install or publish.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
    echo 'Run this script natively on GNU/Linux x64.' >&2
    exit 1
fi
if [[ "${CARGO_BUILD_TARGET:-x86_64-unknown-linux-gnu}" != x86_64-unknown-linux-gnu ]]; then
    echo 'Use the native x86_64-unknown-linux-gnu build target.' >&2
    exit 1
fi
for tool in cargo rustc gcc pkg-config strip readelf python3 bwrap; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required build/test tool is missing: $tool (see docs/releases.md)." >&2
        exit 1
    fi
done
if ! rustc -vV | grep -x 'host: x86_64-unknown-linux-gnu' >/dev/null; then
    echo 'Select a native x86_64-unknown-linux-gnu Rust toolchain.' >&2
    exit 1
fi

cargo fmt --all --check
cargo test --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked
# Exercise the actual optimized worker and persisted project round trip.
cargo test --release --locked --test worker_process
cargo test --release --locked --test linux_worker
cargo test --release --locked --test aarch64
python3 scripts/package-linux.py
