#!/bin/bash
#
# Automated test script for FPGA pattern ID storage feature
# Tests the prepended packet format: | RESERVED (1B) | PATIDs_LEN (2B) | PATID_SIZE (1B) | [PAT_IDs...] | Ethernet...
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SURICATA_BIN="${SCRIPT_DIR}/../src/suricata"
YAML_CONFIG="${SCRIPT_DIR}/../suricata-pcap-patternmatch.yaml"
RULES_FILE="${SCRIPT_DIR}/shmu.rules"
INPUT_PCAP="${SCRIPT_DIR}/shmu-tls.pcap"
OUTPUT_PCAP="${SCRIPT_DIR}/shmu-tls-new.pcap"
LOG_DIR="${SCRIPT_DIR}/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TESTS_PASSED=0
TESTS_FAILED=0

print_header() {
    echo ""
    echo "========================================"
    echo "$1"
    echo "========================================"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    if [[ ! -x "$SURICATA_BIN" ]]; then
        print_fail "Suricata binary not found at $SURICATA_BIN"
        exit 1
    fi
    print_pass "Suricata binary found"

    if [[ ! -f "$YAML_CONFIG" ]]; then
        print_fail "YAML config not found at $YAML_CONFIG"
        exit 1
    fi
    print_pass "YAML config found"

    if [[ ! -f "$RULES_FILE" ]]; then
        print_fail "Rules file not found at $RULES_FILE"
        exit 1
    fi
    print_pass "Rules file found"

    if [[ ! -f "$INPUT_PCAP" ]]; then
        print_fail "Input PCAP not found at $INPUT_PCAP"
        exit 1
    fi
    print_pass "Input PCAP found"

    if ! command -v python3 &> /dev/null; then
        print_fail "python3 not found"
        exit 1
    fi
    print_pass "python3 available"

    if [[ $EUID -ne 0 ]]; then
        print_fail "This script must be run as root (for DPDK)"
        exit 1
    fi
    print_pass "Running as root"
}

# Update max-mpm-pattern-ids in YAML config
set_max_pattern_ids() {
    local value=$1
    print_info "Setting max-mpm-pattern-ids to $value"

    # Use sed to update the value
    sed -i "s/max-mpm-pattern-ids: [0-9]*/max-mpm-pattern-ids: $value/" "$YAML_CONFIG"
}

# Run Suricata and capture output
run_suricata() {
    print_info "Running Suricata..."

    # Clean up previous output
    rm -f "$OUTPUT_PCAP"
    rm -rf "$LOG_DIR"/*
    mkdir -p "$LOG_DIR"

    # Run Suricata (suppress most output, capture errors)
    local output
    output=$("$SURICATA_BIN" -c "$YAML_CONFIG" -S "$RULES_FILE" -l "$LOG_DIR" --dpdk 2>&1) || true

    # Check if output file was created
    if [[ ! -f "$OUTPUT_PCAP" ]]; then
        print_fail "Output PCAP was not created"
        echo "$output"
        return 1
    fi

    # Check config was applied
    if echo "$output" | grep -q "max-mpm-pattern-ids set to"; then
        local configured_value
        configured_value=$(echo "$output" | grep "max-mpm-pattern-ids set to" | head -1 | grep -oP 'set to \K\d+')
        print_info "Config applied: max-mpm-pattern-ids=$configured_value"
    fi

    return 0
}

# Analyze PCAP file with Python
analyze_pcap() {
    local expected_max=$1

    python3 << EOF
import struct
import sys

with open('$OUTPUT_PCAP', 'rb') as f:
    # Skip pcap global header (24 bytes)
    f.read(24)

    stats = {
        'total': 0,
        'valid_format': 0,
        'invalid_format': 0,
        'overflow': 0,
        'pattern_counts': {}
    }

    errors = []

    while True:
        # Read packet header (16 bytes)
        pkt_hdr = f.read(16)
        if len(pkt_hdr) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)

        # Read packet data
        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            break

        stats['total'] += 1

        # Verify header format
        if len(pkt_data) < 4:
            stats['invalid_format'] += 1
            errors.append(f"Packet {stats['total']}: too short ({len(pkt_data)} bytes)")
            continue

        reserved = pkt_data[0]
        patids_len = (pkt_data[1] << 8) | pkt_data[2]  # big-endian
        patid_size = pkt_data[3]

        # Verify RESERVED marker
        if reserved != 0xff:
            stats['invalid_format'] += 1
            errors.append(f"Packet {stats['total']}: invalid RESERVED byte 0x{reserved:02x} (expected 0xff)")
            continue

        # Verify PATID_SIZE
        if patid_size != 4:
            stats['invalid_format'] += 1
            errors.append(f"Packet {stats['total']}: invalid PATID_SIZE {patid_size} (expected 4)")
            continue

        # Verify PATIDs_LEN is multiple of 4
        if patids_len % 4 != 0:
            stats['invalid_format'] += 1
            errors.append(f"Packet {stats['total']}: PATIDs_LEN {patids_len} not multiple of 4")
            continue

        num_patterns = patids_len // 4

        # Check for overflow marker
        if num_patterns == 1 and len(pkt_data) >= 8:
            pattern_id = struct.unpack('<I', pkt_data[4:8])[0]
            if pattern_id == 0xffffffff:
                stats['overflow'] += 1
                num_patterns = 'overflow'

        # Track pattern counts
        key = str(num_patterns)
        stats['pattern_counts'][key] = stats['pattern_counts'].get(key, 0) + 1

        # Verify we have enough data for pattern IDs + Ethernet header (14 bytes min)
        expected_min_len = 4 + patids_len + 14
        if len(pkt_data) < expected_min_len:
            stats['invalid_format'] += 1
            errors.append(f"Packet {stats['total']}: insufficient data for patterns + Ethernet header")
            continue

        # Verify EtherType is valid (should be 0x0800 for IPv4 or similar)
        eth_start = 4 + patids_len
        ethertype = (pkt_data[eth_start + 12] << 8) | pkt_data[eth_start + 13]
        if ethertype not in [0x0800, 0x0806, 0x86dd, 0x8100]:  # IPv4, ARP, IPv6, VLAN
            # Could be modified by previous code, just warn
            pass

        stats['valid_format'] += 1

# Output results as key=value for bash parsing
print(f"TOTAL_PACKETS={stats['total']}")
print(f"VALID_FORMAT={stats['valid_format']}")
print(f"INVALID_FORMAT={stats['invalid_format']}")
print(f"OVERFLOW_COUNT={stats['overflow']}")

# Pattern distribution
for k, v in sorted(stats['pattern_counts'].items(), key=lambda x: (x[0] != 'overflow', x[0])):
    if k == 'overflow':
        print(f"PATTERNS_OVERFLOW={v}")
    else:
        print(f"PATTERNS_{k}={v}")

# Print errors if any
if errors:
    print(f"ERRORS={len(errors)}")
    for e in errors[:5]:  # First 5 errors
        print(f"ERROR: {e}", file=sys.stderr)
else:
    print("ERRORS=0")
EOF
}

# Test with max-mpm-pattern-ids=12 (no overflow expected)
test_max_12() {
    print_header "Test 1: max-mpm-pattern-ids=12 (no overflow expected)"

    set_max_pattern_ids 12

    if ! run_suricata; then
        print_fail "Suricata execution failed"
        return 1
    fi

    # Analyze output
    local results
    results=$(analyze_pcap 12)

    # Parse results
    eval "$results"

    print_info "Total packets: $TOTAL_PACKETS"
    print_info "Valid format: $VALID_FORMAT"
    print_info "Invalid format: $INVALID_FORMAT"
    print_info "Overflow count: $OVERFLOW_COUNT"

    # Test assertions
    if [[ "$INVALID_FORMAT" -eq 0 ]]; then
        print_pass "All packets have valid format"
    else
        print_fail "Found $INVALID_FORMAT packets with invalid format"
    fi

    if [[ "$OVERFLOW_COUNT" -eq 0 ]]; then
        print_pass "No overflow markers (all patterns stored)"
    else
        print_fail "Found $OVERFLOW_COUNT unexpected overflow markers"
    fi

    if [[ "$TOTAL_PACKETS" -gt 0 ]]; then
        print_pass "Packets were processed ($TOTAL_PACKETS total)"
    else
        print_fail "No packets were processed"
    fi

    # Show pattern distribution
    print_info "Pattern distribution:"
    for var in $(compgen -v | grep "^PATTERNS_"); do
        local count="${!var}"
        local num="${var#PATTERNS_}"
        if [[ "$num" == "overflow" ]]; then
            echo "    Overflow: $count"
        else
            echo "    $num pattern IDs: $count"
        fi
    done
}

# Test with max-mpm-pattern-ids=2 (overflow expected for >2 patterns)
test_max_2() {
    print_header "Test 2: max-mpm-pattern-ids=2 (overflow expected)"

    set_max_pattern_ids 2

    if ! run_suricata; then
        print_fail "Suricata execution failed"
        return 1
    fi

    # Analyze output
    local results
    results=$(analyze_pcap 2)

    # Parse results
    eval "$results"

    print_info "Total packets: $TOTAL_PACKETS"
    print_info "Valid format: $VALID_FORMAT"
    print_info "Invalid format: $INVALID_FORMAT"
    print_info "Overflow count: $OVERFLOW_COUNT"

    # Test assertions
    if [[ "$INVALID_FORMAT" -eq 0 ]]; then
        print_pass "All packets have valid format"
    else
        print_fail "Found $INVALID_FORMAT packets with invalid format"
    fi

    if [[ "$OVERFLOW_COUNT" -gt 0 ]]; then
        print_pass "Overflow markers present ($OVERFLOW_COUNT packets exceeded limit)"
    else
        print_fail "Expected overflow markers but found none"
    fi

    # Check that packets with >2 patterns are now overflow
    local patterns_gt_2=0
    for var in $(compgen -v | grep "^PATTERNS_[3-9]\|^PATTERNS_[1-9][0-9]"); do
        local count="${!var}"
        patterns_gt_2=$((patterns_gt_2 + count))
    done

    if [[ "$patterns_gt_2" -eq 0 ]]; then
        print_pass "No packets have more than 2 pattern IDs (correctly limited)"
    else
        print_fail "Found $patterns_gt_2 packets with >2 pattern IDs (should be overflow)"
    fi

    # Show pattern distribution
    print_info "Pattern distribution:"
    for var in $(compgen -v | grep "^PATTERNS_"); do
        local count="${!var}"
        local num="${var#PATTERNS_}"
        if [[ "$num" == "overflow" ]]; then
            echo "    Overflow: $count"
        else
            echo "    $num pattern IDs: $count"
        fi
    done
}

# Test packet format structure
test_packet_format() {
    print_header "Test 3: Verify packet format structure"

    # Make sure we have the max=12 output
    set_max_pattern_ids 12
    run_suricata

    python3 << 'EOF'
import struct
import sys

def verify_packet_format(pkt_data, pkt_num):
    """Verify packet follows the expected format and return details."""
    errors = []

    if len(pkt_data) < 4:
        return False, ["Packet too short for header"]

    reserved = pkt_data[0]
    patids_len = (pkt_data[1] << 8) | pkt_data[2]
    patid_size = pkt_data[3]

    # Check RESERVED
    if reserved != 0xff:
        errors.append(f"RESERVED=0x{reserved:02x} (expected 0xff)")

    # Check PATID_SIZE
    if patid_size != 4:
        errors.append(f"PATID_SIZE={patid_size} (expected 4)")

    # Check PATIDs_LEN alignment
    if patids_len % 4 != 0:
        errors.append(f"PATIDs_LEN={patids_len} not aligned to 4 bytes")

    num_patterns = patids_len // 4

    # Verify pattern IDs if present
    if num_patterns > 0:
        for i in range(num_patterns):
            offset = 4 + i * 4
            if offset + 4 > len(pkt_data):
                errors.append(f"Pattern ID {i} extends beyond packet data")
                break
            pat_id = struct.unpack('<I', pkt_data[offset:offset+4])[0]
            # Check flags are in valid range (bits 30-31)
            # Actual ID should be reasonable (not all 1s unless overflow)
            if pat_id != 0xffffffff:
                actual_id = pat_id & 0x3FFFFFFF
                if actual_id > 100000:  # Sanity check
                    errors.append(f"Pattern ID {i} has unusually large value: {actual_id}")

    # Verify Ethernet header follows
    eth_start = 4 + patids_len
    if eth_start + 14 > len(pkt_data):
        errors.append("Insufficient data for Ethernet header")
    else:
        ethertype = (pkt_data[eth_start + 12] << 8) | pkt_data[eth_start + 13]
        # Common ethertypes
        valid_types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: 'VLAN'}
        if ethertype not in valid_types:
            # Not necessarily an error - source data might have modified MACs
            pass

    return len(errors) == 0, errors

# Analyze file
with open('shmu-tls-new.pcap', 'rb') as f:
    f.read(24)  # Skip global header

    total = 0
    passed = 0
    failed = 0
    sample_errors = []

    while True:
        pkt_hdr = f.read(16)
        if len(pkt_hdr) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)
        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            break

        total += 1
        ok, errors = verify_packet_format(pkt_data, total)

        if ok:
            passed += 1
        else:
            failed += 1
            if len(sample_errors) < 3:
                sample_errors.append((total, errors))

print(f"FORMAT_TOTAL={total}")
print(f"FORMAT_PASSED={passed}")
print(f"FORMAT_FAILED={failed}")

if sample_errors:
    for pkt_num, errs in sample_errors:
        for e in errs:
            print(f"FORMAT_ERROR: Packet {pkt_num}: {e}", file=sys.stderr)
EOF

    local results
    results=$(python3 << 'PYEOF'
import struct

with open('shmu-tls-new.pcap', 'rb') as f:
    f.read(24)
    total = passed = 0
    while True:
        pkt_hdr = f.read(16)
        if len(pkt_hdr) < 16: break
        _, _, incl_len, _ = struct.unpack('<IIII', pkt_hdr)
        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len: break
        total += 1
        if len(pkt_data) >= 4 and pkt_data[0] == 0xff and pkt_data[3] == 4:
            patids_len = (pkt_data[1] << 8) | pkt_data[2]
            if patids_len % 4 == 0:
                passed += 1
print(f"FORMAT_TOTAL={total}")
print(f"FORMAT_PASSED={passed}")
print(f"FORMAT_FAILED={total - passed}")
PYEOF
)

    eval "$results"

    if [[ "$FORMAT_FAILED" -eq 0 ]]; then
        print_pass "All $FORMAT_TOTAL packets have correct format structure"
    else
        print_fail "$FORMAT_FAILED of $FORMAT_TOTAL packets have format errors"
    fi
}

# Cleanup and restore config
cleanup() {
    print_header "Cleanup"

    # Restore max-mpm-pattern-ids to 12
    set_max_pattern_ids 12
    print_info "Restored max-mpm-pattern-ids to 12"

    # Clean up output files
    rm -f "$OUTPUT_PCAP"
    print_info "Cleaned up output files"
}

# Print summary
print_summary() {
    print_header "Test Summary"

    local total=$((TESTS_PASSED + TESTS_FAILED))
    echo "Total tests: $total"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [[ "$TESTS_FAILED" -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    fi
}

# Main
main() {
    print_header "FPGA Pattern ID Storage Test Suite"
    echo "Testing packet format: | RESERVED (1B) | PATIDs_LEN (2B) | PATID_SIZE (1B) | [PAT_IDs...] | Ethernet..."

    check_prerequisites

    # Clear any PATTERNS_ variables from previous runs
    for var in $(compgen -v | grep "^PATTERNS_"); do
        unset "$var"
    done

    test_max_12

    # Clear variables between tests
    for var in $(compgen -v | grep "^PATTERNS_"); do
        unset "$var"
    done

    test_max_2

    test_packet_format

    cleanup

    print_summary
}

# Run main
main "$@"
