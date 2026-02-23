#!/bin/bash

# Script to test live IDS capabilities for DPDK using DPDK's null interface.
# Connects over unix socket. Issues a reload. Then shuts suricata down.
#
# Usage: dpdk.sh <yaml> [--expected-mempool-size <size>]
#   yaml                    - path to the Suricata YAML config
#   --expected-mempool-size - optional: expected per-queue mempool size to verify
#                             in the "creating ... packet mempools of size ..." log line

#set -e
set -x

YAML=""
EXPECTED_MP_SIZE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --expected-mempool-size)
            EXPECTED_MP_SIZE="$2"
            shift 2
            ;;
        *)
            if [ -z "$YAML" ]; then
                YAML="$1"
            else
                echo "ERROR unexpected argument: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$YAML" ]; then
    echo "ERROR call with: path-to-yaml [--expected-mempool-size <size>]"
    exit 1
fi

# dump some info
uname -a

# For bonding configs: DPDK <= 22.07 uses "slave=" while >= 22.11 uses "member="
# in the vdev bonding arguments. Patch the YAML at runtime to match installed DPDK.
DPDK_YAML="$YAML"
if grep -q "net_bonding" "$YAML"; then
    DPDK_VER=$(pkg-config --modversion libdpdk 2>/dev/null || echo "0.0")
    DPDK_MAJOR=$(echo "$DPDK_VER" | cut -d. -f1)
    DPDK_MINOR=$(echo "$DPDK_VER" | cut -d. -f2)
    echo "Detected DPDK version: $DPDK_VER (major=$DPDK_MAJOR minor=$DPDK_MINOR)"

    # Use a temporary patched YAML so we don't modify the original
    DPDK_YAML=$(mktemp /tmp/dpdk-bond-XXXXXX.yaml)
    if [ "$DPDK_MAJOR" -lt 22 ] || { [ "$DPDK_MAJOR" -eq 22 ] && [ "$DPDK_MINOR" -lt 11 ]; }; then
        echo "DPDK < 22.11: using slave= syntax for bonding"
        sed 's/member=/slave=/g' "$YAML" > "$DPDK_YAML"
    else
        echo "DPDK >= 22.11: using member= syntax for bonding"
        sed 's/slave=/member=/g' "$YAML" > "$DPDK_YAML"
    fi
fi

# remove eve.json from previous run
if [ -f eve.json ]; then
    rm eve.json
fi

# remove suricata log from previous run
SURILOG="suricata-dpdk.log"
if [ -f "$SURILOG" ]; then
    rm "$SURILOG"
fi

if [ -e ./rust/target/release/suricatasc ]; then
    SURICATASC=./rust/target/release/suricatasc
else
    SURICATASC=./rust/target/debug/suricatasc
fi

RES=0

# set first rule file
cp .github/workflows/live/icmp.rules suricata.rules

# Start Suricata, SIGINT after 120 secords. Will close it earlier through
# the unix socket. Redirect output to log file for mempool checks.
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c "$DPDK_YAML" -l ./ --dpdk -vvvv --set default-rule-path=. > "$SURILOG" 2>&1 &
SURIPID=$!

sleep 15

# check stats and alerts
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.packets > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi

echo "SURIPID $SURIPID"

# set second rule file for the reload
cp .github/workflows/live/icmp2.rules suricata.rules

# trigger the reload
${SURICATASC} -c "reload-rules" /var/run/suricata/suricata-command.socket

sleep 15

# check stats and alerts
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.packets > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi

${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID

# dump suricata log for debugging
cat "$SURILOG"

# clean up temporary YAML if we created one
if [ "$DPDK_YAML" != "$YAML" ]; then
    rm -f "$DPDK_YAML"
fi

# optional: verify expected per-queue mempool size
if [ -n "$EXPECTED_MP_SIZE" ]; then
    # SCLogInfo prints: "<iface>: creating <N> packet mempools of size <SIZE>, cache size ..."
    if grep -q "packet mempools of size ${EXPECTED_MP_SIZE}," "$SURILOG"; then
        echo "OK mempool size check passed (expected ${EXPECTED_MP_SIZE})"
    else
        echo "ERROR expected per-queue mempool size ${EXPECTED_MP_SIZE} not found in log"
        grep "packet mempools of size" "$SURILOG" || echo "  (no mempool size log line found)"
        RES=1
    fi
fi

echo "done: $RES"
exit $RES
