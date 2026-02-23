#!/bin/bash

# Script to test live IDS capabilities for DPDK using DPDK's null interface.
# Connects over unix socket. Issues a reload. Then shuts suricata down.
#
# Usage: dpdk.sh <yaml> [expected_mempool_size]
#   yaml                  - path to the Suricata YAML config
#   expected_mempool_size - optional: expected per-queue mempool size to verify
#                           in the "creating ... packet mempools of size ..." log line

#set -e
set -x

if [ $# -lt "1" ] || [ $# -gt "2" ]; then
    echo "ERROR call with 1-2 args: path to yaml to use [expected_mempool_size]"
    exit 1;
fi

YAML=$1
EXPECTED_MP_SIZE=${2:-}

# dump some info
uname -a

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
# the unix socket. Redirect output to log file for optional mempool checks.
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c $YAML -l ./ --dpdk -v --set default-rule-path=. > "$SURILOG" 2>&1 &
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
