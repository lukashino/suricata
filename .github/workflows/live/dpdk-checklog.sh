#!/bin/bash
#
# DPDK configuration check script.
#
# Starts Suricata with a DPDK config, optionally overriding per-interface
# settings, and verifies expected log output. Supports both positive tests
# (Suricata starts) and negative tests (Suricata fails with expected error).
#
# Usage:
#   dpdk-checklog.sh <yaml> [OPTIONS]
#
# Options:
#   --cfg-set <iface>.<key>=<value>   Override a DPDK interface setting.
#                                     Resolved to --set dpdk.interfaces.<N>.<key>=<value>
#                                     where <N> is the YAML index of <iface>.
#   --suricata-logs-check <regex>     Verify regex is found in Suricata log (repeatable).
#   --expect-start                    Expect Suricata to start successfully (default).
#   --expect-fail                     Expect Suricata to fail during startup.
#
# Examples:
#   dpdk-checklog.sh suricata-null-ids.yaml \
#       --cfg-set net_null0.mempool-size=auto \
#       --cfg-set net_null0.mempool-cache-size=auto \
#       --suricata-logs-check "mempools of size 31, cache size 1" \
#       --expect-start
#
#   dpdk-checklog.sh suricata-null-ids.yaml \
#       --cfg-set net_null0.mempool-size=15 \
#       --suricata-logs-check "mempool size is likely too small" \
#       --expect-fail

set -o pipefail

# ── Argument parsing ────────────────────────────────────────────────
YAML=""
EXPECT="start"   # "start" or "fail"
declare -a CFG_SETS=()
declare -a LOG_CHECKS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --cfg-set)
            CFG_SETS+=("$2"); shift 2 ;;
        --suricata-logs-check)
            LOG_CHECKS+=("$2"); shift 2 ;;
        --expect-start)
            EXPECT="start"; shift ;;
        --expect-fail)
            EXPECT="fail"; shift ;;
        -*)
            echo "ERROR: unknown option: $1"; exit 1 ;;
        *)
            if [ -z "$YAML" ]; then YAML="$1"; else
                echo "ERROR: unexpected argument: $1"; exit 1
            fi
            shift ;;
    esac
done

if [ -z "$YAML" ]; then
    echo "ERROR: call with: dpdk-checklog.sh <yaml> [OPTIONS]"
    exit 1
fi

# ── DPDK version compatibility (member= / slave=) ──────────────────
DPDK_YAML="$YAML"
if grep -q "net_bonding" "$YAML"; then
    DPDK_VER=$(pkg-config --modversion libdpdk 2>/dev/null || echo "0.0")
    DPDK_MAJOR=$(echo "$DPDK_VER" | cut -d. -f1)
    DPDK_MINOR=$(echo "$DPDK_VER" | cut -d. -f2)

    DPDK_YAML=$(mktemp /tmp/dpdk-checklog-XXXXXX.yaml)
    trap "rm -f '$DPDK_YAML'" EXIT

    if [ "$DPDK_MAJOR" -lt 22 ] || { [ "$DPDK_MAJOR" -eq 22 ] && [ "$DPDK_MINOR" -lt 11 ]; }; then
        sed 's/member=/slave=/g' "$YAML" > "$DPDK_YAML"
    else
        cp "$YAML" "$DPDK_YAML"
    fi
fi

# ── Resolve --cfg-set to Suricata --set arguments ──────────────────
# Build a map: interface-name -> YAML index (0-based).
# Parses lines like "    - interface: net_null0" from the YAML.
declare -A IFACE_INDEX=()
idx=0
while IFS= read -r iface_name; do
    IFACE_INDEX["$iface_name"]=$idx
    idx=$((idx + 1))
done < <(grep -E '^\s*-\s*interface:' "$YAML" | sed 's/.*interface:\s*//' | awk '{print $1}')

SURI_SET_ARGS=()
for entry in "${CFG_SETS[@]}"; do
    # entry format: <iface>.<key>=<value>
    iface="${entry%%.*}"
    key_value="${entry#*.}"

    if [ -z "${IFACE_INDEX[$iface]+x}" ]; then
        echo "ERROR: interface '$iface' not found in $YAML"
        echo "  Available interfaces: ${!IFACE_INDEX[*]}"
        exit 1
    fi

    suri_idx="${IFACE_INDEX[$iface]}"
    SURI_SET_ARGS+=(--set "dpdk.interfaces.${suri_idx}.${key_value}")
done

# ── Run Suricata ────────────────────────────────────────────────────
SURILOG=$(mktemp /tmp/dpdk-checklog-log-XXXXXX.log)
trap "rm -f '$DPDK_YAML' '$SURILOG'" EXIT

TIMEOUT_SEC=20

timeout --preserve-status "$TIMEOUT_SEC" \
    ./src/suricata -c "$DPDK_YAML" -S /dev/null -l ./ --dpdk \
    "${SURI_SET_ARGS[@]}" > "$SURILOG" 2>&1
SURI_EXIT=$?

# ── Evaluate results ───────────────────────────────────────────────
RES=0
ENGINE_STARTED=false
if grep -q "Engine started" "$SURILOG"; then
    ENGINE_STARTED=true
fi

echo "=========================================="
echo "  DPDK checklog: $(basename "$YAML")"
echo "  expect=$EXPECT  exit=$SURI_EXIT  engine_started=$ENGINE_STARTED"
echo "=========================================="

# Check startup expectation
if [ "$EXPECT" = "start" ]; then
    if [ "$ENGINE_STARTED" = true ]; then
        echo "  PASS  Engine started as expected"
    else
        echo "  FAIL  Engine did NOT start (expected start)"
        RES=1
    fi
elif [ "$EXPECT" = "fail" ]; then
    if [ "$ENGINE_STARTED" = false ] && [ "$SURI_EXIT" -ne 0 ]; then
        echo "  PASS  Engine failed as expected (exit=$SURI_EXIT)"
    else
        echo "  FAIL  Engine did not fail as expected (exit=$SURI_EXIT, started=$ENGINE_STARTED)"
        RES=1
    fi
fi

# Check log patterns
for pattern in "${LOG_CHECKS[@]}"; do
    if grep -qE "$pattern" "$SURILOG"; then
        echo "  PASS  log-check: $pattern"
    else
        echo "  FAIL  log-check: $pattern"
        RES=1
    fi
done

echo "=========================================="

# Dump log on failure for debugging
if [ "$RES" -ne 0 ]; then
    echo ""
    echo "--- Suricata log (failure) ---"
    cat "$SURILOG"
    echo "--- end log ---"
fi

exit $RES
