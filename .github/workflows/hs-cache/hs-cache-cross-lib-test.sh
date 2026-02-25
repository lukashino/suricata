#!/usr/bin/env bash
# Cross-library Hyperscan/Vectorscan cache compatibility test
#
# Tests that caches created by one HS-compatible library are properly
# rejected (or accepted) when the library is swapped, and that new
# caches are then created and loadable.
#
# Called from CI in phases (library swap + rebuild happens between phases):
#   setup      - Generate test YAML, rules, shared cache directory
#   hs-create  - Create caches with library A (expects newly_cached > 0)
#   hs-load    - Reload with library A   (expects loaded > 0)
#   crossload  - After swap to library B  (expects recompile OR load)
#   reload     - Reload with library B    (expects loaded > 0)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

SURICATA_BIN="${SURICATA_BIN:-$REPO_ROOT/src/suricata}"
CLASS_FILE="$REPO_ROOT/etc/classification.config"
REF_FILE="$REPO_ROOT/etc/reference.config"

# Persistent state directory shared across phases
TEST_DIR="/tmp/hs-cross-lib-test"
CACHE_DIR="$TEST_DIR/cache"
RULES_FILE="$TEST_DIR/rules/test.rules"
YAML_FILE="$TEST_DIR/suricata.yaml"

PHASE="${1:?Usage: $0 <setup|hs-create|hs-load|crossload|reload>}"

# ── TAP-like output ──────────────────────────────────────────────────────────

TEST_NUM=0
PASS_COUNT=0
FAIL_COUNT=0

pass() {
    TEST_NUM=$((TEST_NUM + 1))
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "ok $TEST_NUM - $1"
}

fail() {
    TEST_NUM=$((TEST_NUM + 1))
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "not ok $TEST_NUM - $1"
    if [[ -n "${2:-}" ]]; then
        echo "#   $2"
    fi
}

# ── Helpers ──────────────────────────────────────────────────────────────────

extract_stat() {
    local field="$1" logfile="$2"
    local line val
    line=$(grep -E "Rule group caching - loaded:" "$logfile" 2>/dev/null | tail -1) || true
    case "$field" in
        loaded)
            val=$(echo "$line" | sed -n 's/.*loaded: *\([0-9][0-9]*\).*/\1/p') ;;
        newly_cached)
            val=$(echo "$line" | sed -n 's/.*newly cached: *\([0-9][0-9]*\).*/\1/p') ;;
        total_cacheable)
            val=$(echo "$line" | sed -n 's/.*total cacheable: *\([0-9][0-9]*\).*/\1/p') ;;
    esac
    echo "${val:-0}"
}

run_phase() {
    local logdir="$TEST_DIR/log-$PHASE"
    rm -rf "$logdir"
    mkdir -p "$logdir"
    local rc=0
    "$SURICATA_BIN" -T -c "$YAML_FILE" -S "$RULES_FILE" -l "$logdir" \
        --set "classification-file=$CLASS_FILE" \
        --set "reference-config-file=$REF_FILE" \
        > "$logdir/output.txt" 2>&1 || rc=$?

    if [[ "$rc" -eq 0 ]]; then
        pass "$PHASE: suricata -T exits 0"
    else
        fail "$PHASE: suricata -T exits 0" "got exit code $rc"
        echo "# --- suricata output ---"
        tail -20 "$logdir/output.txt" | sed 's/^/#   /'
        echo "# ---"
    fi

    LOGFILE="$logdir/suricata.log"
}

# ── Phases ───────────────────────────────────────────────────────────────────

phase_setup() {
    echo "# Phase: setup - Creating test environment at $TEST_DIR"
    rm -rf "$TEST_DIR"
    mkdir -p "$CACHE_DIR" "$TEST_DIR/rules"

    cat > "$RULES_FILE" <<'RULES'
alert udp any any -> any any (msg:"XLib test 1"; content:"crosslib_alpha"; sid:5000001; rev:1;)
alert udp any any -> any any (msg:"XLib test 2"; content:"crosslib_bravo"; sid:5000002; rev:1;)
alert udp any any -> any any (msg:"XLib test 3"; content:"crosslib_charlie"; sid:5000003; rev:1;)
RULES

    cat > "$YAML_FILE" <<YAML
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
    SIP_PORTS: "[5060, 5061]"

mpm-algo: hs

detect:
    profile: medium
    sgh-mpm-context: auto
    sgh-mpm-caching: yes
    sgh-mpm-caching-path: $CACHE_DIR

app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes

logging:
  default-log-level: info
  outputs:
  - file:
      enabled: yes
      level: info
      filename: suricata.log
YAML

    echo "# Setup complete"
    echo "#   Cache dir:  $CACHE_DIR"
    echo "#   Rules file: $RULES_FILE"
    echo "#   YAML file:  $YAML_FILE"
}

phase_hs_create() {
    echo "# Phase: hs-create - Creating caches with current library"
    echo "#   $("$SURICATA_BIN" --build-info 2>&1 | grep -i hyperscan || echo 'N/A')"

    run_phase

    local cached loaded count
    cached=$(extract_stat newly_cached "$LOGFILE")
    loaded=$(extract_stat loaded "$LOGFILE")

    if [[ "$cached" -gt 0 ]]; then
        pass "hs-create: newly_cached > 0 ($cached)"
    else
        fail "hs-create: newly_cached > 0" "got $cached"
    fi

    if [[ "$loaded" -eq 0 ]]; then
        pass "hs-create: loaded == 0"
    else
        fail "hs-create: loaded == 0" "got $loaded"
    fi

    count=$(find "$CACHE_DIR" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    count=$(echo "$count" | tr -d ' ')
    if [[ "$count" -gt 0 ]]; then
        pass "hs-create: cache files exist ($count)"
    else
        fail "hs-create: cache files exist" "found 0"
    fi
}

phase_hs_load() {
    echo "# Phase: hs-load - Loading caches with same library"

    run_phase

    local loaded cached
    loaded=$(extract_stat loaded "$LOGFILE")
    cached=$(extract_stat newly_cached "$LOGFILE")

    if [[ "$loaded" -gt 0 ]]; then
        pass "hs-load: loaded > 0 ($loaded)"
    else
        fail "hs-load: loaded > 0" "got $loaded"
    fi

    if [[ "$cached" -eq 0 ]]; then
        pass "hs-load: newly_cached == 0"
    else
        fail "hs-load: newly_cached == 0" "got $cached"
    fi
}

phase_crossload() {
    echo "# Phase: crossload - After library swap, testing cache compatibility"
    echo "#   $("$SURICATA_BIN" --build-info 2>&1 | grep -i hyperscan || echo 'N/A')"

    run_phase

    local loaded cached total
    loaded=$(extract_stat loaded "$LOGFILE")
    cached=$(extract_stat newly_cached "$LOGFILE")
    total=$(extract_stat total_cacheable "$LOGFILE")

    # Two valid outcomes:
    #   A) Versions match:   loaded > 0, newly_cached == 0 (old caches reused)
    #   B) Versions differ:  loaded == 0, newly_cached > 0  (old caches rejected)
    if [[ "$loaded" -gt 0 && "$cached" -eq 0 ]]; then
        echo "# Result: Library versions MATCH - old caches reused"
        pass "crossload: caches loaded (same library version)"
    elif [[ "$loaded" -eq 0 && "$cached" -gt 0 ]]; then
        echo "# Result: Library versions DIFFER - old caches rejected, new ones created"
        pass "crossload: caches rejected and recompiled (different library version)"
    else
        fail "crossload: consistent cache behavior" \
             "loaded=$loaded newly_cached=$cached (expected all-load or all-recompile)"
    fi

    local sum=$((loaded + cached))
    if [[ "$sum" -eq "$total" ]]; then
        pass "crossload: loaded + newly_cached == total_cacheable ($sum == $total)"
    else
        fail "crossload: loaded + newly_cached == total_cacheable" "$sum != $total"
    fi
}

phase_reload() {
    echo "# Phase: reload - Verifying caches from current library load correctly"

    run_phase

    local loaded cached
    loaded=$(extract_stat loaded "$LOGFILE")
    cached=$(extract_stat newly_cached "$LOGFILE")

    if [[ "$loaded" -gt 0 ]]; then
        pass "reload: loaded > 0 ($loaded)"
    else
        fail "reload: loaded > 0" "got $loaded"
    fi

    if [[ "$cached" -eq 0 ]]; then
        pass "reload: newly_cached == 0"
    else
        fail "reload: newly_cached == 0" "got $cached"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

echo "# Cross-library Hyperscan/Vectorscan cache test - phase: $PHASE"

case "$PHASE" in
    setup)      phase_setup ;;
    hs-create)  phase_hs_create ;;
    hs-load)    phase_hs_load ;;
    crossload)  phase_crossload ;;
    reload)     phase_reload ;;
    *)
        echo "BAIL OUT! Unknown phase: $PHASE"
        exit 1
        ;;
esac

echo ""
echo "# Phase '$PHASE': $PASS_COUNT passed, $FAIL_COUNT failed (of $TEST_NUM)"
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
