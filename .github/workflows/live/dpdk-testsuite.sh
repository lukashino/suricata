#!/bin/bash
#
# DPDK mempool/cache sizing test suite.
#
# Runs dpdk-checklog.sh for every combination of mempool-size,
# mempool-cache-size, thread count, and interface type (single / bond).
# Exits non-zero on the first failure.
#
# Usage:
#   dpdk-testsuite.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKLOG="${SCRIPT_DIR}/dpdk-checklog.sh"
DPDK_DIR="$(cd "${SCRIPT_DIR}/../dpdk" && pwd)"

IDS_YAML="${DPDK_DIR}/suricata-null-ids.yaml"
BOND_YAML="${DPDK_DIR}/suricata-null-bond.yaml"

PASS=0
FAIL=0

run_test() {
    local description="$1"; shift
    echo ""
    echo "=== TEST: ${description} ==="
    local t0=$SECONDS
    if "$CHECKLOG" "$@"; then
        echo "  (${description}: $((SECONDS - t0))s)"
        PASS=$((PASS + 1))
    else
        echo "  (${description}: $((SECONDS - t0))s)"
        FAIL=$((FAIL + 1))
        echo "^^^ FAILED: ${description}"
        exit 1
    fi
}

# ── IDS (single interface: net_null0, 16 rx/tx descriptors) ───────

run_test "IDS: auto mempool, auto cache (1 thread)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=1 \
    --cfg-set net_null0.mempool-size=auto \
    --cfg-set net_null0.mempool-cache-size=auto \
    --suricata-logs-check "1 packet mempools of size 31, cache size 1" \
    --expect-start

run_test "IDS: auto mempool, auto cache (2 threads)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=2 \
    --cfg-set net_null0.mempool-size=auto \
    --cfg-set net_null0.mempool-cache-size=auto \
    --suricata-logs-check "2 packet mempools of size 31, cache size 1" \
    --expect-start

run_test "IDS: auto mempool, static cache=1 (1 thread)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=1 \
    --cfg-set net_null0.mempool-size=auto \
    --cfg-set net_null0.mempool-cache-size=1 \
    --suricata-logs-check "1 packet mempools of size 31, cache size 1" \
    --expect-start

run_test "IDS: auto mempool, static cache=1 (2 threads)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=2 \
    --cfg-set net_null0.mempool-size=auto \
    --cfg-set net_null0.mempool-cache-size=1 \
    --suricata-logs-check "2 packet mempools of size 31, cache size 1" \
    --expect-start

run_test "IDS: auto mempool, oversized cache=1024 (fail)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=1 \
    --cfg-set net_null0.mempool-size=auto \
    --cfg-set net_null0.mempool-cache-size=1024 \
    --suricata-logs-check "mempool cache size requires a positive number" \
    --expect-fail

run_test "IDS: static mempool=1023, auto cache (1 thread)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=1 \
    --cfg-set net_null0.mempool-size=1023 \
    --cfg-set net_null0.mempool-cache-size=auto \
    --suricata-logs-check "1 packet mempools of size 1022, cache size 511" \
    --expect-start

run_test "IDS: static mempool=1023, auto cache (2 threads)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=2 \
    --cfg-set net_null0.mempool-size=1023 \
    --cfg-set net_null0.mempool-cache-size=auto \
    --suricata-logs-check "2 packet mempools of size 511, cache size 73" \
    --expect-start

run_test "IDS: mempool too small (fail)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=1 \
    --cfg-set net_null0.mempool-size=15 \
    --suricata-logs-check "mempool size is likely too small" \
    --expect-fail

run_test "IDS: auto descriptors, auto mempool (OOM expected)" \
    "$IDS_YAML" \
    --cfg-set net_null0.threads=1 \
    --cfg-set net_null0.mempool-size=auto \
    --cfg-set net_null0.mempool-cache-size=auto \
    --cfg-set net_null0.rx-descriptors=auto \
    --cfg-set net_null0.tx-descriptors=auto \
    --suricata-logs-check "1 packet mempools of size 65535, cache size 257" \
    --expect-fail

# ── Bond (net_bonding0, 2 members, 16 rx/tx descriptors) ─────────

run_test "Bond: auto mempool, auto cache (1 thread)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=1 \
    --cfg-set net_bonding0.mempool-size=auto \
    --cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-logs-check "1 packet mempools of size 63, cache size 21" \
    --expect-start

run_test "Bond: auto mempool, auto cache (2 threads)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=2 \
    --cfg-set net_bonding0.mempool-size=auto \
    --cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-logs-check "2 packet mempools of size 63, cache size 21" \
    --expect-start

run_test "Bond: auto mempool, static cache=7 (1 thread)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=1 \
    --cfg-set net_bonding0.mempool-size=auto \
    --cfg-set net_bonding0.mempool-cache-size=7 \
    --suricata-logs-check "1 packet mempools of size 63, cache size 7" \
    --expect-start

run_test "Bond: auto mempool, static cache=7 (2 threads)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=2 \
    --cfg-set net_bonding0.mempool-size=auto \
    --cfg-set net_bonding0.mempool-cache-size=7 \
    --suricata-logs-check "2 packet mempools of size 63, cache size 7" \
    --expect-start

run_test "Bond: auto mempool, oversized cache=1024 (fail)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=1 \
    --cfg-set net_bonding0.mempool-size=auto \
    --cfg-set net_bonding0.mempool-cache-size=1024 \
    --suricata-logs-check "mempool cache size requires a positive number" \
    --expect-fail

run_test "Bond: static mempool=1023, auto cache (1 thread)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=1 \
    --cfg-set net_bonding0.mempool-size=1023 \
    --cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-logs-check "1 packet mempools of size 1022, cache size 511" \
    --expect-start

run_test "Bond: static mempool=1023, auto cache (2 threads)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=2 \
    --cfg-set net_bonding0.mempool-size=1023 \
    --cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-logs-check "2 packet mempools of size 511, cache size 73" \
    --expect-start

run_test "Bond: mempool too small (fail)" \
    "$BOND_YAML" \
    --cfg-set net_bonding0.threads=1 \
    --cfg-set net_bonding0.mempool-size=15 \
    --suricata-logs-check "mempool size is likely too small" \
    --expect-fail

# ── Summary ───────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "  DPDK test suite: ${PASS} passed, ${FAIL} failed"
echo "=========================================="
exit $FAIL
