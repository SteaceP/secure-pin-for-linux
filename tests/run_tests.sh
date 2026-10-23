#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "=== Building Secure PIN for Linux ==="
if [ -f build/CMakeCache.txt ]; then
    if ! grep -q "CMAKE_CACHEFILE_DIR:INTERNAL=$DIR/build" build/CMakeCache.txt 2>/dev/null; then
        echo "Stale CMake cache detected, clearing build cache..."
        rm -rf build/CMakeCache.txt build/CMakeFiles
    fi
fi
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build

echo ""
echo "=== Checking Python GTK4 / Libadwaita Settings App ==="
python3 -m py_compile gui/tpm-pin-settings
echo "Python syntax check: PASSED"

echo ""
echo "=== Running Automated Tests ==="
SWTPM_PID=""
SWTPM_DIR=""

# Check if /dev/tpmrm0 is accessible; if not, spin up swtpm
if [ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ]; then
    echo "Using hardware TPM: /dev/tpmrm0"
elif which swtpm >/dev/null 2>&1; then
    SWTPM_DIR=$(mktemp -d /tmp/swtpm_test.XXXXXX)
    echo "Starting isolated swtpm in $SWTPM_DIR ..."
    swtpm_setup --tpm2 --tpm-state "$SWTPM_DIR" --createek 2>/dev/null || true
    swtpm socket --tpm2 \
        --tpmstate dir="$SWTPM_DIR" \
        --ctrl type=tcp,port=2322 \
        --server type=tcp,port=2321 \
        --flags not-need-init,startup-clear &
    SWTPM_PID=$!
    sleep 0.8
    export TCTI="swtpm:host=127.0.0.1,port=2321"
    echo "swtpm running (PID $SWTPM_PID, TCTI=$TCTI)"
fi

cleanup() {
    if [ -n "$SWTPM_PID" ]; then
        kill "$SWTPM_PID" 2>/dev/null || true
    fi
    if [ -n "$SWTPM_DIR" ] && [ -d "$SWTPM_DIR" ]; then
        rm -rf "$SWTPM_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

./build/test_pam_harness

echo ""
echo "=== CLI Status Smoke Test ==="
./build/tpm-pin-ctl status || true
echo ""
./build/tpm-pin-ctl status --json || true

echo ""
echo "=== All Tests Completed Successfully! ==="
