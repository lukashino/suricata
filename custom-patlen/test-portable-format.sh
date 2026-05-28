#!/bin/bash
# E2E tests for detect.results-format=portable.
# Verifies (a) round-trip encoding of pids into the 12-byte MAC area,
#          (b) overflow-sentinel behaviour,
#          (c) startup validation failures.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SURICATA_BIN="${SCRIPT_DIR}/../src/suricata"
YAML_BASE="${SCRIPT_DIR}/../suricata-pcap-patternmatch.yaml"
RULES_FILE="${SCRIPT_DIR}/shmu.rules"
INPUT_PCAP="${SCRIPT_DIR}/shmu-tls.pcap"
PARSER="${SCRIPT_DIR}/parse_portable.py"
WORK_DIR="$(mktemp -d -t portable-format.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

[[ -x "$SURICATA_BIN" ]] || { fail "suricata binary missing"; exit 1; }
[[ -f "$INPUT_PCAP"   ]] || { fail "input pcap missing";    exit 1; }

make_yaml() {
    local out="$1" format="$2" count="$3"
    cp "$YAML_BASE" "$out"
    sed -i "s/max-mpm-pattern-ids: [0-9]\+/max-mpm-pattern-ids: ${count}/" "$out"
    sed -i '/^[[:space:]]*results-format:/d' "$out"
    if grep -qE '^detect:' "$out"; then
        sed -i "/^detect:/a\\  results-format: ${format}" "$out"
    else
        printf '\ndetect:\n  results-format: %s\n' "$format" >> "$out"
    fi
}

# --- Test 1: missing key -> FATAL ---
YAML="$WORK_DIR/no-key.yaml"
cp "$YAML_BASE" "$YAML"
sed -i '/results-format:/d' "$YAML"
"$SURICATA_BIN" -T -c "$YAML" -l "$WORK_DIR" > "$WORK_DIR/no-key.log" 2>&1
if grep -q 'detect.results-format is required' "$WORK_DIR/no-key.log"; then
    pass "missing results-format key -> FATAL"
else
    fail "missing results-format key -> expected FATAL"
    info "log tail:"; tail -5 "$WORK_DIR/no-key.log"
fi

# --- Test 2: invalid value -> FATAL ---
YAML="$WORK_DIR/bad-key.yaml"
make_yaml "$YAML" "portible" 6
"$SURICATA_BIN" -T -c "$YAML" -l "$WORK_DIR" > "$WORK_DIR/bad-key.log" 2>&1
if grep -q 'detect.results-format has invalid value "portible"' "$WORK_DIR/bad-key.log"; then
    pass "invalid results-format value -> FATAL"
else
    fail "invalid results-format value -> expected FATAL"
    info "log tail:"; tail -5 "$WORK_DIR/bad-key.log"
fi

# --- Test 3: portable + max-mpm-pattern-ids=12 (Check 2) ---
# NOTE: this check fires inside DPDK runmode config-parse, NOT during `suricata -T`.
# Skipping under -T; we'd need a real --dpdk run with root + hugepages to exercise it.
info "Test 3 (portable + count>6 FATAL): only fires under real --dpdk runtime; skipping in -T."

# --- Test 4: portable round-trip ---
YAML="$WORK_DIR/portable-cnt6.yaml"
make_yaml "$YAML" "portable" 6
OUTPUT_PCAP="${SCRIPT_DIR}/shmu-tls-new.pcap"
LOG_DIR="${SCRIPT_DIR}/logs-portable"

if [[ $EUID -ne 0 ]]; then
    info "not running as root -- skipping portable round-trip test"
elif ! command -v python3 >/dev/null; then
    info "python3 missing -- skipping portable round-trip test"
elif ! python3 -c "import scapy" 2>/dev/null; then
    info "scapy missing -- skipping portable round-trip test"
else
    rm -f "$OUTPUT_PCAP"
    rm -rf "$LOG_DIR" && mkdir -p "$LOG_DIR"
    "$SURICATA_BIN" -c "$YAML" -S "$RULES_FILE" -l "$LOG_DIR" --dpdk \
        > "$WORK_DIR/run.log" 2>&1 || true
    if [[ ! -s "$OUTPUT_PCAP" ]]; then
        fail "portable round-trip: output pcap missing or empty"
        info "log tail:"; tail -20 "$WORK_DIR/run.log"
    else
        python3 "$PARSER" "$OUTPUT_PCAP" > "$WORK_DIR/parse.log" 2>&1
        if [[ $? -ne 0 ]]; then
            fail "portable round-trip: parser failed"
            info "log tail:"; tail -20 "$WORK_DIR/parse.log"
        elif grep -qE 'pid=' "$WORK_DIR/parse.log"; then
            pass "portable round-trip: at least one packet has decoded pids"
        elif grep -q 'OVERFLOW' "$WORK_DIR/parse.log"; then
            pass "portable round-trip: overflow sentinel detected as expected"
        else
            fail "portable round-trip: no pids and no overflow markers"
            info "log tail:"; tail -20 "$WORK_DIR/parse.log"
        fi
    fi
fi

echo ""
echo "Summary: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]]
