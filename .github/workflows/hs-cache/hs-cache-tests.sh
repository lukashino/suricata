#!/usr/bin/env bash
# Hyperscan Cache Test Suite for Suricata
#
# Tests every code path in util-mpm-hs-cache.c and util-mpm-hs.c caching logic.
# Produces TAP-like output.
#
# Usage:
#   bash .github/workflows/hs-cache/hs-cache-tests.sh                  # Run all tests
#   bash .github/workflows/hs-cache/hs-cache-tests.sh cache_loading     # Run only tests matching filter
#
set -euo pipefail

# ─── Section 1: Configuration & Constants ────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

SURICATA_BIN="${SURICATA_BIN:-$REPO_ROOT/src/suricata}"
CLASS_FILE="${CLASS_FILE:-$REPO_ROOT/etc/classification.config}"
REF_FILE="${REF_FILE:-$REPO_ROOT/etc/reference.config}"

# TAP counters
TEST_NUM=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FILTER="${1:-}"
IS_ROOT=0
if [[ "$(id -u)" -eq 0 ]]; then
    IS_ROOT=1
fi

# Global temp directory - cleaned on EXIT
TMPBASE="$(mktemp -d /tmp/hs-cache-tests.XXXXXX)"
trap 'rm -rf "$TMPBASE"' EXIT

# ─── Section 2: Framework ────────────────────────────────────────────────────

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

skip() {
    TEST_NUM=$((TEST_NUM + 1))
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo "ok $TEST_NUM - SKIP $1"
}

assert_equals() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$desc"
    else
        fail "$desc" "expected '$expected', got '$actual'"
    fi
}

assert_not_equals() {
    local desc="$1" not_expected="$2" actual="$3"
    if [[ "$not_expected" != "$actual" ]]; then
        pass "$desc"
    else
        fail "$desc" "expected NOT '$not_expected', but got it"
    fi
}

assert_grep() {
    local desc="$1" pattern="$2" file="$3"
    if grep -qE "$pattern" "$file" 2>/dev/null; then
        pass "$desc"
    else
        fail "$desc" "pattern '$pattern' not found in $file"
    fi
}

assert_not_grep() {
    local desc="$1" pattern="$2" file="$3"
    if ! grep -qE "$pattern" "$file" 2>/dev/null; then
        pass "$desc"
    else
        fail "$desc" "pattern '$pattern' unexpectedly found in $file"
    fi
}

assert_cache_count() {
    local desc="$1" expected="$2" dir="$3"
    local actual
    actual=$(find "$dir" -maxdepth 1 -name '*_v2.hs' -type f 2>/dev/null | wc -l)
    actual=$(echo "$actual" | tr -d ' ')
    if [[ "$actual" -eq "$expected" ]]; then
        pass "$desc"
    else
        fail "$desc" "expected $expected cache files, found $actual"
    fi
}

assert_cache_count_ge() {
    local desc="$1" min="$2" dir="$3"
    local actual
    actual=$(find "$dir" -maxdepth 1 -name '*_v2.hs' -type f 2>/dev/null | wc -l)
    actual=$(echo "$actual" | tr -d ' ')
    if [[ "$actual" -ge "$min" ]]; then
        pass "$desc"
    else
        fail "$desc" "expected >= $min cache files, found $actual"
    fi
}

assert_gt() {
    local desc="$1" val="$2" threshold="$3"
    if [[ "$val" -gt "$threshold" ]]; then
        pass "$desc"
    else
        fail "$desc" "expected > $threshold, got $val"
    fi
}

assert_eq_num() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" -eq "$expected" ]]; then
        pass "$desc"
    else
        fail "$desc" "expected $expected, got $actual"
    fi
}

assert_ge() {
    local desc="$1" val="$2" threshold="$3"
    if [[ "$val" -ge "$threshold" ]]; then
        pass "$desc"
    else
        fail "$desc" "expected >= $threshold, got $val"
    fi
}

assert_file_exists() {
    local desc="$1" path="$2"
    if [[ -e "$path" ]]; then
        pass "$desc"
    else
        fail "$desc" "file '$path' does not exist"
    fi
}

assert_file_not_exists() {
    local desc="$1" path="$2"
    if [[ ! -e "$path" ]]; then
        pass "$desc"
    else
        fail "$desc" "file '$path' unexpectedly exists"
    fi
}

assert_dir_exists() {
    local desc="$1" path="$2"
    if [[ -d "$path" ]]; then
        pass "$desc"
    else
        fail "$desc" "directory '$path' does not exist"
    fi
}

# Extract a numeric stat from suricata.log cache line.
# Usage: extract_stat "loaded" logfile
#   From: "Rule group caching - loaded: X newly cached: Y total cacheable: Z"
extract_stat() {
    local field="$1" logfile="$2"
    local line val
    line=$(grep -E "Rule group caching - loaded:" "$logfile" 2>/dev/null | tail -1) || true
    case "$field" in
        loaded)
            val=$(echo "$line" | sed -n 's/.*loaded: *\([0-9][0-9]*\).*/\1/p')
            ;;
        newly_cached)
            val=$(echo "$line" | sed -n 's/.*newly cached: *\([0-9][0-9]*\).*/\1/p')
            ;;
        total_cacheable)
            val=$(echo "$line" | sed -n 's/.*total cacheable: *\([0-9][0-9]*\).*/\1/p')
            ;;
        pruned)
            local prune_line
            prune_line=$(grep -E "Rule group cache pruning removed" "$logfile" 2>/dev/null | tail -1) || true
            val=$(echo "$prune_line" | sed -n 's/.*removed \([0-9][0-9]*\)\/.*/\1/p')
            ;;
        pruned_considered)
            local prune_line2
            prune_line2=$(grep -E "Rule group cache pruning removed" "$logfile" 2>/dev/null | tail -1) || true
            val=$(echo "$prune_line2" | sed -n 's/.*removed [0-9][0-9]*\/\([0-9][0-9]*\).*/\1/p')
            ;;
    esac
    echo "${val:-0}"
}

# Create per-test isolated directories.
# Sets: T_CACHE, T_LOG, T_RULES_DIR, T_YAML
setup_test_env() {
    local name="$1"
    local tdir="$TMPBASE/$name"
    mkdir -p "$tdir/cache" "$tdir/log" "$tdir/rules"
    T_CACHE="$tdir/cache"
    T_LOG="$tdir/log"
    T_RULES_DIR="$tdir/rules"
    T_DIR="$tdir"
}

teardown_test_env() {
    : # global EXIT trap handles cleanup
}

# Generate a minimal suricata.yaml with cache settings.
# Usage: generate_yaml ENABLED CACHE_PATH [MAX_AGE]
# Writes to $T_DIR/suricata.yaml and sets T_YAML
generate_yaml() {
    local enabled="${1:-yes}"
    local cache_path="${2:-$T_CACHE}"
    local max_age="${3:-}"
    local yaml_path="$T_DIR/suricata.yaml"

    local max_age_line=""
    if [[ -n "$max_age" ]]; then
        max_age_line="    sgh-mpm-caching-max-age: $max_age"
    fi

    cat > "$yaml_path" <<YAML
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
    sgh-mpm-caching: $enabled
    sgh-mpm-caching-path: $cache_path
$max_age_line

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

    T_YAML="$yaml_path"
}

# Generate rules file with content keywords.
# Usage: generate_rules FILE "content1" "content2" ...
generate_rules() {
    local file="$1"
    shift
    local sid=1000001
    > "$file"
    for pat in "$@"; do
        echo "alert udp any any -> any any (msg:\"Test rule $sid\"; content:\"$pat\"; sid:$sid; rev:1;)" >> "$file"
        sid=$((sid + 1))
    done
}

# Generate a large number of rules.
# Usage: generate_many_rules FILE COUNT
generate_many_rules() {
    local file="$1"
    local count="$2"
    > "$file"
    for i in $(seq 1 "$count"); do
        local sid=$((2000000 + i))
        # Use unique patterns so each rule gets different content
        printf 'alert udp any any -> any any (msg:"Large rule %d"; content:"%08x"; sid:%d; rev:1;)\n' \
            "$i" "$i" "$sid" >> "$file"
    done
}

# Generate a multi-tenant configuration.
# Usage: generate_multitenant_yaml CACHE_PATH TENANT1_RULES TENANT2_RULES
# Writes main yaml and per-tenant yamls.
generate_multitenant_yaml() {
    local cache_path="$1"
    local tenant1_rules="$2"
    local tenant2_rules="$3"

    # Tenant 1 yaml
    cat > "$T_DIR/tenant-1.yaml" <<YAML
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

default-rule-path: $T_RULES_DIR

rule-files:
  - $(basename "$tenant1_rules")

classification-file: $CLASS_FILE
reference-config-file: $REF_FILE
YAML

    # Tenant 2 yaml
    cat > "$T_DIR/tenant-2.yaml" <<YAML
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

default-rule-path: $T_RULES_DIR

rule-files:
  - $(basename "$tenant2_rules")

classification-file: $CLASS_FILE
reference-config-file: $REF_FILE
YAML

    # Main yaml with multi-detect
    cat > "$T_DIR/suricata.yaml" <<YAML
%YAML 1.1
---

multi-detect:
  enabled: yes
  selector: vlan
  loaders: 1
  tenants:
  - id: 1
    yaml: $T_DIR/tenant-1.yaml
  - id: 2
    yaml: $T_DIR/tenant-2.yaml
  mappings:
  - vlan-id: 1000
    tenant-id: 1
  - vlan-id: 2000
    tenant-id: 2

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
    sgh-mpm-caching-path: $cache_path

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

    T_YAML="$T_DIR/suricata.yaml"
}

# Run suricata in config-test mode.
# Usage: run_suricata [yaml] [rules] [logdir]
# Returns the exit code; stdout/stderr captured in $T_LOG/suricata-output.txt
run_suricata() {
    local yaml="${1:-$T_YAML}"
    local rules="${2:-$T_RULES_DIR/test.rules}"
    local logdir="${3:-$T_LOG}"
    local rc=0

    "$SURICATA_BIN" -T -c "$yaml" -S "$rules" -l "$logdir" \
        --set "classification-file=$CLASS_FILE" \
        --set "reference-config-file=$REF_FILE" \
        > "$logdir/suricata-output.txt" 2>&1 || rc=$?

    return $rc
}

# Run suricata in config-test mode for multi-tenant (no -S flag).
# Usage: run_suricata_mt [yaml] [logdir]
run_suricata_mt() {
    local yaml="${1:-$T_YAML}"
    local logdir="${2:-$T_LOG}"
    local rc=0

    "$SURICATA_BIN" -T -c "$yaml" -l "$logdir" \
        --set "classification-file=$CLASS_FILE" \
        --set "reference-config-file=$REF_FILE" \
        > "$logdir/suricata-output.txt" 2>&1 || rc=$?

    return $rc
}

# ─── Section 3: Test Functions ───────────────────────────────────────────────

# ── Category 1: Basic Cache Operations ──

test_cache_creation_on_first_run() {
    setup_test_env "cache_creation"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "abc123" "def456" "ghi789"

    run_suricata
    assert_equals "first run exits 0" "0" "$?"
    assert_cache_count_ge "first run creates cache files" 1 "$T_CACHE"

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_gt "first run newly_cached > 0" "$newly_cached" 0

    local loaded
    loaded=$(extract_stat "loaded" "$T_LOG/suricata.log")
    assert_eq_num "first run loaded == 0" 0 "$loaded"
}

test_cache_loading_on_second_run() {
    setup_test_env "cache_loading"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "abc123" "def456" "ghi789"

    # First run - populates cache
    run_suricata
    assert_equals "first run exits 0" "0" "$?"

    # Second run - should load from cache
    rm -rf "$T_LOG"/*
    run_suricata
    assert_equals "second run exits 0" "0" "$?"

    local loaded
    loaded=$(extract_stat "loaded" "$T_LOG/suricata.log")
    assert_gt "second run loaded > 0" "$loaded" 0

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_eq_num "second run newly_cached == 0" 0 "$newly_cached"
}

test_cache_disabled() {
    setup_test_env "cache_disabled"
    generate_yaml "no" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "abc123" "def456"

    run_suricata
    assert_equals "disabled run exits 0" "0" "$?"
    assert_cache_count "disabled produces 0 cache files" 0 "$T_CACHE"
    assert_not_grep "no cache stats logged" "Rule group caching" "$T_LOG/suricata.log"
}

test_cache_stats_accuracy() {
    setup_test_env "cache_stats_accuracy"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "stat_a" "stat_b" "stat_c" "stat_d"

    # First run
    run_suricata
    local loaded1 cached1 total1
    loaded1=$(extract_stat "loaded" "$T_LOG/suricata.log")
    cached1=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    total1=$(extract_stat "total_cacheable" "$T_LOG/suricata.log")
    local sum1=$((loaded1 + cached1))
    assert_eq_num "run1: loaded + newly_cached == total_cacheable" "$total1" "$sum1"

    # Second run
    rm -rf "$T_LOG"/*
    run_suricata
    local loaded2 cached2 total2
    loaded2=$(extract_stat "loaded" "$T_LOG/suricata.log")
    cached2=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    total2=$(extract_stat "total_cacheable" "$T_LOG/suricata.log")
    local sum2=$((loaded2 + cached2))
    assert_eq_num "run2: loaded + newly_cached == total_cacheable" "$total2" "$sum2"
}

# ── Category 2: Corrupted / Invalid Cache Files ──

test_corrupted_cache_file() {
    setup_test_env "corrupted_cache"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "corrupt_test_a" "corrupt_test_b"

    # First run - create cache
    run_suricata

    # Corrupt all cache files
    for f in "$T_CACHE"/*_v2.hs; do
        [[ -f "$f" ]] || continue
        dd if=/dev/urandom of="$f" bs=1 count=64 conv=notrunc 2>/dev/null
    done

    # Second run - should gracefully recompile
    rm -rf "$T_LOG"/*
    run_suricata
    local rc=$?
    assert_equals "corrupted cache: exits 0" "0" "$rc"

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_gt "corrupted cache: recompiled > 0" "$newly_cached" 0
}

test_empty_cache_file() {
    setup_test_env "empty_cache"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "empty_test_a" "empty_test_b"

    # First run
    run_suricata

    # Truncate all cache files to 0
    for f in "$T_CACHE"/*_v2.hs; do
        [[ -f "$f" ]] || continue
        : > "$f"
    done

    # Second run
    rm -rf "$T_LOG"/*
    run_suricata
    local rc=$?
    assert_equals "empty cache: exits 0" "0" "$rc"

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_gt "empty cache: recompiled > 0" "$newly_cached" 0
}

test_truncated_cache_file() {
    setup_test_env "truncated_cache"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "trunc_test_a" "trunc_test_b"

    # First run
    run_suricata

    # Cut each cache file in half
    for f in "$T_CACHE"/*_v2.hs; do
        [[ -f "$f" ]] || continue
        local sz
        sz=$(stat -c%s "$f")
        local half=$((sz / 2))
        truncate -s "$half" "$f"
    done

    # Second run
    rm -rf "$T_LOG"/*
    run_suricata
    local rc=$?
    assert_equals "truncated cache: exits 0" "0" "$rc"

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_gt "truncated cache: recompiled > 0" "$newly_cached" 0
}

test_simulated_platform_mismatch() {
    setup_test_env "platform_mismatch"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "platform_a" "platform_b"

    # First run
    run_suricata

    # Flip bytes in the HS header area (offset 16-32) of each file
    for f in "$T_CACHE"/*_v2.hs; do
        [[ -f "$f" ]] || continue
        dd if=/dev/urandom of="$f" bs=1 count=16 seek=16 conv=notrunc 2>/dev/null
    done

    # Second run
    rm -rf "$T_LOG"/*
    run_suricata
    local rc=$?
    assert_equals "platform mismatch: exits 0" "0" "$rc"

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_gt "platform mismatch: recompiled > 0" "$newly_cached" 0
}

# ── Category 3: Cache Pruning ──

test_wrong_version_suffix_pruned() {
    setup_test_env "wrong_version"
    generate_yaml "yes" "$T_CACHE" "1s"
    generate_rules "$T_RULES_DIR/test.rules" "version_a" "version_b"

    # Create a decoy _v1.hs file (wrong version)
    echo "fake old cache" > "$T_CACHE/deadbeef_v1.hs"
    # Set mtime to the past so age-based pruning also applies
    touch -t 202001010000 "$T_CACHE/deadbeef_v1.hs"

    # Run suricata (creates v2 caches, prunes v1)
    run_suricata
    assert_equals "wrong version run exits 0" "0" "$?"

    assert_file_not_exists "v1 cache file pruned" "$T_CACHE/deadbeef_v1.hs"
}

test_age_based_pruning() {
    setup_test_env "age_pruning"
    generate_yaml "yes" "$T_CACHE" "1s"
    generate_rules "$T_RULES_DIR/test.rules" "age_a" "age_b"

    # Create an old decoy v2 file with ancient mtime
    echo "old cache data" > "$T_CACHE/oldcache0000_v2.hs"
    touch -t 202001010000 "$T_CACHE/oldcache0000_v2.hs"

    # Sleep to ensure the 1s max-age window passes
    sleep 3

    run_suricata
    assert_equals "age pruning run exits 0" "0" "$?"

    assert_file_not_exists "old v2 cache file pruned" "$T_CACHE/oldcache0000_v2.hs"

    local pruned
    pruned=$(extract_stat "pruned" "$T_LOG/suricata.log")
    assert_ge "at least 1 file pruned" "$pruned" 1
}

test_inuse_cache_survives_pruning() {
    setup_test_env "inuse_survives"
    generate_yaml "yes" "$T_CACHE" "1s"
    generate_rules "$T_RULES_DIR/test.rules" "inuse_a" "inuse_b"

    # First run - create valid cache
    run_suricata
    assert_equals "first run exits 0" "0" "$?"

    # Count cache files from first run
    local count_before
    count_before=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    count_before=$(echo "$count_before" | tr -d ' ')

    # Wait for the max-age window to pass
    sleep 3

    # Second run - caches are in-use, must not be pruned
    rm -rf "$T_LOG"/*
    run_suricata
    assert_equals "second run exits 0" "0" "$?"

    local count_after
    count_after=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    count_after=$(echo "$count_after" | tr -d ' ')

    assert_eq_num "in-use caches survive pruning" "$count_before" "$count_after"
}

test_no_hs_suffix_ignored() {
    setup_test_env "no_hs_suffix"
    generate_yaml "yes" "$T_CACHE" "1s"
    generate_rules "$T_RULES_DIR/test.rules" "suffix_a" "suffix_b"

    # Create non-.hs files in cache dir
    echo "not a cache" > "$T_CACHE/readme.txt"
    echo "some data" > "$T_CACHE/data.bin"
    touch -t 202001010000 "$T_CACHE/readme.txt" "$T_CACHE/data.bin"

    sleep 3
    run_suricata
    assert_equals "run exits 0" "0" "$?"

    assert_file_exists "readme.txt untouched" "$T_CACHE/readme.txt"
    assert_file_exists "data.bin untouched" "$T_CACHE/data.bin"
}

# ── Category 4: Rule Changes & Cache Invalidation ──

test_rule_change_new_cache() {
    setup_test_env "rule_change"
    generate_yaml "yes" "$T_CACHE"

    # First ruleset
    generate_rules "$T_RULES_DIR/test.rules" "ruleA1" "ruleA2"
    run_suricata

    # Snapshot first run's cache files
    local files1
    files1=$(ls "$T_CACHE"/*_v2.hs 2>/dev/null | sort)

    # Change rules
    generate_rules "$T_RULES_DIR/test.rules" "ruleB1" "ruleB2" "ruleB3"
    rm -rf "$T_LOG"/*
    run_suricata

    # Second run should create different cache files
    local files2
    files2=$(ls "$T_CACHE"/*_v2.hs 2>/dev/null | sort)

    assert_not_equals "different rules -> different cache files" "$files1" "$files2"
}

test_identical_rules_same_cache() {
    setup_test_env "identical_rules"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "same1" "same2"

    # First run
    run_suricata
    local count1
    count1=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    count1=$(echo "$count1" | tr -d ' ')

    # Second run with identical rules
    rm -rf "$T_LOG"/*
    run_suricata

    local count2
    count2=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    count2=$(echo "$count2" | tr -d ' ')
    assert_eq_num "identical rules -> same cache count" "$count1" "$count2"

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_eq_num "no new caches on second run" 0 "$newly_cached"
}

test_large_ruleset() {
    setup_test_env "large_ruleset"
    generate_yaml "yes" "$T_CACHE"
    generate_many_rules "$T_RULES_DIR/test.rules" 120

    # First run - compile and cache
    run_suricata
    assert_equals "large ruleset first run exits 0" "0" "$?"
    assert_cache_count_ge "large ruleset creates cache files" 1 "$T_CACHE"

    local newly_cached
    newly_cached=$(extract_stat "newly_cached" "$T_LOG/suricata.log")
    assert_gt "large ruleset newly_cached > 0" "$newly_cached" 0

    # Second run - load from cache
    rm -rf "$T_LOG"/*
    run_suricata
    assert_equals "large ruleset second run exits 0" "0" "$?"

    local loaded
    loaded=$(extract_stat "loaded" "$T_LOG/suricata.log")
    assert_gt "large ruleset loaded > 0" "$loaded" 0
}

# ── Category 5: Directory & Permission Edge Cases ──

test_cache_dir_auto_created() {
    setup_test_env "auto_create"
    local deep_path="$T_DIR/deep/nested/cache/dir"
    generate_yaml "yes" "$deep_path"
    generate_rules "$T_RULES_DIR/test.rules" "autodir_a" "autodir_b"

    run_suricata
    assert_equals "auto-create run exits 0" "0" "$?"
    assert_dir_exists "deep cache dir auto-created" "$deep_path"
    assert_cache_count_ge "caches created in deep dir" 1 "$deep_path"
}

test_cache_dir_not_writable() {
    # Root bypasses Unix file permissions, so this test cannot work in
    # CI containers where everything runs as uid 0.
    if [[ "$IS_ROOT" -eq 1 ]]; then
        skip "read-only dir (skipped: running as root)"
        skip "read-only dir: no cache files (skipped: running as root)"
        return
    fi

    setup_test_env "not_writable"
    local ro_dir="$T_DIR/readonly_cache"
    mkdir -p "$ro_dir"
    chmod 555 "$ro_dir"
    generate_yaml "yes" "$ro_dir"
    generate_rules "$T_RULES_DIR/test.rules" "nowrite_a" "nowrite_b"

    run_suricata
    local rc=$?
    # Restore permissions so cleanup works
    chmod 755 "$ro_dir"
    assert_equals "read-only dir: exits 0" "0" "$rc"
    assert_cache_count "read-only dir: no cache files" 0 "$ro_dir"
}

test_cache_file_permissions() {
    setup_test_env "file_perms"
    generate_yaml "yes" "$T_CACHE"
    generate_rules "$T_RULES_DIR/test.rules" "perm_a" "perm_b"

    run_suricata
    assert_equals "permissions run exits 0" "0" "$?"

    local bad_perms=0
    for f in "$T_CACHE"/*_v2.hs; do
        [[ -f "$f" ]] || continue
        local mode
        mode=$(stat -c%a "$f")
        # Owner should have rw (6xx). Group/other may vary by umask.
        if [[ "${mode:0:1}" -lt 6 ]]; then
            bad_perms=1
        fi
    done
    assert_eq_num "cache files have owner rw" 0 "$bad_perms"
}

# ── Category 6: Multi-Tenant Scenarios ──

test_multitenant_shared_cache_dir() {
    setup_test_env "mt_shared"

    # Tenant 1 rules
    generate_rules "$T_RULES_DIR/tenant1.rules" "mt_share_a" "mt_share_b"
    # Tenant 2 rules (different)
    generate_rules "$T_RULES_DIR/tenant2.rules" "mt_share_c" "mt_share_d" "mt_share_e"

    generate_multitenant_yaml "$T_CACHE" "$T_RULES_DIR/tenant1.rules" "$T_RULES_DIR/tenant2.rules"

    run_suricata_mt
    assert_equals "multi-tenant shared cache exits 0" "0" "$?"
    assert_cache_count_ge "multi-tenant creates cache files" 1 "$T_CACHE"
}

test_multitenant_identical_rules_dedup() {
    setup_test_env "mt_dedup"

    # Both tenants use identical rules
    generate_rules "$T_RULES_DIR/tenant1.rules" "dedup_x" "dedup_y"
    cp "$T_RULES_DIR/tenant1.rules" "$T_RULES_DIR/tenant2.rules"

    generate_multitenant_yaml "$T_CACHE" "$T_RULES_DIR/tenant1.rules" "$T_RULES_DIR/tenant2.rules"

    run_suricata_mt
    assert_equals "dedup run exits 0" "0" "$?"

    # Count total cache files - identical rules = same hash = no extra files
    local cache_count
    cache_count=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    cache_count=$(echo "$cache_count" | tr -d ' ')

    # Now run with single tenant to get baseline count
    setup_test_env "mt_dedup_baseline"
    generate_rules "$T_RULES_DIR/test.rules" "dedup_x" "dedup_y"
    generate_yaml "yes" "$T_CACHE"
    run_suricata

    local baseline_count
    baseline_count=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    baseline_count=$(echo "$baseline_count" | tr -d ' ')

    assert_eq_num "identical rules -> no extra cache files" "$baseline_count" "$cache_count"
}

test_multitenant_different_rules_separate_caches() {
    setup_test_env "mt_different"

    # Tenant 1 rules
    generate_rules "$T_RULES_DIR/tenant1.rules" "diff_mt_a" "diff_mt_b"
    # Tenant 2 rules (completely different)
    generate_rules "$T_RULES_DIR/tenant2.rules" "diff_mt_x" "diff_mt_y" "diff_mt_z"

    generate_multitenant_yaml "$T_CACHE" "$T_RULES_DIR/tenant1.rules" "$T_RULES_DIR/tenant2.rules"

    run_suricata_mt
    assert_equals "different tenants run exits 0" "0" "$?"

    # There should be more cache files than a single tenant would produce
    local mt_count
    mt_count=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    mt_count=$(echo "$mt_count" | tr -d ' ')

    # Single tenant baseline with tenant1 rules only
    setup_test_env "mt_different_baseline"
    generate_rules "$T_RULES_DIR/test.rules" "diff_mt_a" "diff_mt_b"
    generate_yaml "yes" "$T_CACHE"
    run_suricata

    local single_count
    single_count=$(find "$T_CACHE" -maxdepth 1 -name '*_v2.hs' -type f | wc -l)
    single_count=$(echo "$single_count" | tr -d ' ')

    assert_gt "different tenants -> more cache files than single" "$mt_count" "$single_count"
}

# ─── Section 4: Runner ──────────────────────────────────────────────────────

main() {
    # Pre-flight checks
    if [[ ! -x "$SURICATA_BIN" ]]; then
        echo "BAIL OUT! Suricata binary not found or not executable: $SURICATA_BIN"
        exit 1
    fi
    if [[ ! -f "$CLASS_FILE" ]]; then
        echo "BAIL OUT! Classification file not found: $CLASS_FILE"
        exit 1
    fi
    if [[ ! -f "$REF_FILE" ]]; then
        echo "BAIL OUT! Reference config not found: $REF_FILE"
        exit 1
    fi

    # Check Hyperscan support
    if ! "$SURICATA_BIN" --build-info 2>&1 | grep -q "Hyperscan support:.*yes"; then
        echo "BAIL OUT! Suricata not built with Hyperscan support"
        exit 1
    fi

    # Discover test functions
    local tests=()
    while IFS= read -r fn; do
        tests+=("$fn")
    done < <(declare -F | awk '{print $3}' | grep '^test_' | sort)

    # Apply filter
    local filtered=()
    for t in "${tests[@]}"; do
        if [[ -z "$FILTER" ]] || [[ "$t" == *"$FILTER"* ]]; then
            filtered+=("$t")
        fi
    done

    if [[ ${#filtered[@]} -eq 0 ]]; then
        echo "BAIL OUT! No tests matched filter: $FILTER"
        exit 1
    fi

    echo "# Hyperscan Cache Test Suite"
    echo "# Running ${#filtered[@]} tests (temp dir: $TMPBASE)"
    echo "# Suricata: $SURICATA_BIN"
    echo "# Running as: $(id)"
    echo "#"
    echo "# Build info (Hyperscan line):"
    echo "#   $("$SURICATA_BIN" --build-info 2>&1 | grep -i hyperscan || echo 'N/A')"
    echo ""

    # Disable exit-on-error so one test failure doesn't abort the suite
    set +e

    for t in "${filtered[@]}"; do
        echo "# --- $t ---"
        "$t"
    done

    set -e

    echo ""
    echo "# ────────────────────────────────────"
    echo "# Results: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped (of $TEST_NUM)"

    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main
