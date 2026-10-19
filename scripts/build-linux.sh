#!/usr/bin/env bash
# Build, check and package on native Linux x64. Does not install or publish.
# Tests run by default; run them locally before pushing. GitHub CI passes
# --skip-tests and only builds, lints, and packages.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

run_tests=1
for argument in "$@"; do
    case "$argument" in
        --skip-tests) run_tests=0 ;;
        *)
            echo "Usage: $0 [--skip-tests]" >&2
            exit 2
            ;;
    esac
done

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
    echo 'Run this script natively on GNU/Linux x64.' >&2
    exit 1
fi
if [[ "${CARGO_BUILD_TARGET:-x86_64-unknown-linux-gnu}" != x86_64-unknown-linux-gnu ]]; then
    echo 'Use the native x86_64-unknown-linux-gnu build target.' >&2
    exit 1
fi
tools=(cargo rustc pkg-config strip readelf python3)
if ((run_tests)); then
    tools+=(gcc objdump bwrap)
fi
for tool in "${tools[@]}"; do
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
if ((run_tests)); then
    python3 -m unittest discover -s scripts -p 'test_*.py'
    cargo test --locked
fi
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked
if ((run_tests)); then
    # Exercise the actual optimized worker and persisted project round trip.
    cargo test --release --locked --test worker_process
    cargo test --release --locked --test linux_worker
    cargo test --release --locked --test aarch64
fi
python3 scripts/package-linux.py
