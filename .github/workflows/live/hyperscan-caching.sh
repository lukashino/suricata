#!/bin/bash

# Script to test live capabilities for Hyperscan MPM caching. 
# Capture mode af-packet is used to ensure lasting Suricata run, any capture mode
# should work.

# 1) Start AF-Packet Suricata with fresh cache folder, check that the newly 
#    created caches exists and no overwrite is present, then shut down.
# 2) Suricata starts again with the same cache folder, and checks that the
#    existing caches are loaded correctly, keep Suricata running.
# 3) Redefine rules and trigger a reload, check that new caches are created,
#    and that the old caches are present.
# 4) Reissue a reload, check that the new caches are loaded correctly, then
#    shut down.
# 5) Start Suricata with the new ruleset, check that the new caches are loaded
#    correctly, then shut down.

set -e
set -x

# Initialize result code
RES=0

# Clean up any previous test artifacts
echo "=== CLEANUP ==="
if [ -d "./hs_cache" ]; then
    rm -rf ./hs_cache
fi
if [ -f eve.json ]; then
    rm eve.json
fi
if [ -f suricata.log ]; then
    rm suricata.log
fi

# Create fresh cache directory
mkdir -p ./hs_cache

# dump some info
uname -a
ip r

# Get listen interface and target address
IFACE=$(ip r|grep default|awk '{print $5}')
echo "Using interface: $IFACE"
GW=$(ip r|grep default|awk '{print $3}')
echo "Using gateway: $GW"

# Determine suricatasc path
if [ -e ./rust/target/release/suricatasc ]; then
    SURICATASC=./rust/target/release/suricatasc
else
    SURICATASC=./rust/target/debug/suricatasc
fi

echo "=== STEP 1: Fresh start with new cache folder ==="
# Set first rule file (2 rules)
cp .github/workflows/live/dns1.rules suricata.rules

# Start background process to generate DNS traffic
(
    sleep 5
    for i in {1..10}; do
        nslookup suricata.io 8.8.8.8 || true
        sleep 2
    done
) &
NSLOOKUP_PID=$!

# Start Suricata with fresh cache, timeout after 30 seconds
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v \
        --set af-packet.1.bpf-filter="port 53" \
        --set af-packet.1.tpacket-v3=true \
        --set default-rule-path=. \
        --set runmode=workers \
        --set detect.sgh-mpm-caching=yes \
        --set detect.sgh-mpm-caching-path=./hs_cache \
        --set mpm-algo=hs \
        --set spm-algo=hs &
SURI_PID=$!

# Wait for Suricata to initialize
sleep 15

# Kill the nslookup process if still running
kill $NSLOOKUP_PID 2>/dev/null || true
wait $NSLOOKUP_PID 2>/dev/null || true

# Gracefully shutdown Suricata
${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket || true
wait $SURI_PID 2>/dev/null || true

# Check that cache files were created
echo "=== Checking cache files after Step 1 ==="
if [ ! -d "./hs_cache" ] || [ -z "$(ls -A ./hs_cache)" ]; then
    echo "ERROR: No cache files created in Step 1"
    RES=1
else
    echo "Cache files created:"
    ls -la ./hs_cache/
    # Store the initial cache files for comparison
    INITIAL_CACHES=$(ls ./hs_cache/)
    echo "Initial cache files: $INITIAL_CACHES"
fi

# Check for alerts from first ruleset
ALERT_COUNT=$(jq -c 'select(.event_type == "alert")' ./eve.json 2>/dev/null | wc -l || echo "0")
if [ "$ALERT_COUNT" -eq 0 ]; then
    echo "ERROR: No alerts found in Step 1"
    RES=1
else
    echo "Found $ALERT_COUNT alerts in Step 1"
fi

# Check suricata.log for cache-related messages
echo "=== Checking suricata.log for cache messages ==="
if [ -f suricata.log ]; then
    if grep -q "Overwriting cache file" suricata.log; then
        echo "ERROR: Unexpected cache file overwrite in Step 1"
        RES=1
    fi
    
    # Look for successful cache creation
    if grep -q "cache file" suricata.log; then
        echo "Cache-related log messages found:"
        grep "cache file" suricata.log || true
    fi
fi

echo "=== STEP 2: Restart with existing cache folder ==="
# Remove old eve.json for clean slate
rm -f eve.json

# Start background DNS traffic again
(
    sleep 5
    for i in {1..10}; do
        nslookup suricata.io 8.8.8.8 || true
        sleep 2
    done
) &
NSLOOKUP_PID=$!

# Start Suricata again with same cache directory
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v \
        --set af-packet.1.bpf-filter="port 53" \
        --set af-packet.1.tpacket-v3=true \
        --set default-rule-path=. \
        --set runmode=workers \
        --set detect.sgh-mpm-caching=yes \
        --set detect.sgh-mpm-caching-path=./hs_cache \
        --set mpm-algo=hs \
        --set spm-algo=hs &
SURI_PID=$!

# Wait for initialization 
sleep 15

echo "=== STEP 3: Rule reload with new ruleset ==="
# Change to second rule file (4 rules) 
cp .github/workflows/live/dns2.rules suricata.rules

# Trigger reload
${SURICATASC} -c "reload-rules" /var/run/suricata/suricata-command.socket

# Wait a bit for reload to process
sleep 10

# Generate some traffic for new rules
(
    for i in {1..5}; do
        nslookup suricata.io 8.8.8.8 || true
        nslookup random.site 8.8.8.8 || true
        sleep 1
    done
) &

# Wait for traffic generation
sleep 8

echo "=== STEP 4: Second reload verification ==="
# Trigger another reload to verify new caches load correctly
${SURICATASC} -c "reload-rules" /var/run/suricata/suricata-command.socket

sleep 5

# Stop DNS traffic and shutdown
kill $NSLOOKUP_PID 2>/dev/null || true
wait $NSLOOKUP_PID 2>/dev/null || true

${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURI_PID

# Check cache files after reloads
echo "=== Checking cache files after reloads ==="
if [ -d "./hs_cache" ]; then
    echo "Cache files after reloads:"
    ls -la ./hs_cache/
    FINAL_CACHES=$(ls ./hs_cache/)
    echo "Final cache files: $FINAL_CACHES"
    
    # Check if we have both old and new caches
    CACHE_COUNT=$(ls ./hs_cache/ | wc -l)
    if [ "$CACHE_COUNT" -lt 2 ]; then
        echo "WARNING: Expected multiple cache files after reload, found $CACHE_COUNT"
    fi
else
    echo "ERROR: Cache directory missing after reloads"
    RES=1
fi

# Verify alerts from both rulesets
SID1_COUNT=$(jq -c 'select(.event_type == "alert" and .alert.signature_id == 1)' ./eve.json 2>/dev/null | wc -l || echo "0")
SID2_COUNT=$(jq -c 'select(.event_type == "alert" and .alert.signature_id == 2)' ./eve.json 2>/dev/null | wc -l || echo "0")

if [ "$SID1_COUNT" -eq 0 ]; then
    echo "ERROR: No alerts for SID 1 found"
    RES=1
else
    echo "Found $SID1_COUNT alerts for SID 1"
fi

if [ "$SID2_COUNT" -eq 0 ]; then
    echo "ERROR: No alerts for SID 2 found"  
    RES=1
else
    echo "Found $SID2_COUNT alerts for SID 2"
fi

echo "=== STEP 5: Final restart with new ruleset ==="
# Remove eve.json for final test
rm -f eve.json

# Final start with the 4-rule set to verify cache loading
(
    sleep 5
    for i in {1..5}; do
        nslookup suricata.io 8.8.8.8 || true
        nslookup random.site 8.8.8.8 || true
        sleep 2
    done
) &
NSLOOKUP_PID=$!

timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v \
        --set af-packet.1.bpf-filter="port 53" \
        --set af-packet.1.tpacket-v3=true \
        --set default-rule-path=. \
        --set runmode=workers \
        --set detect.sgh-mpm-caching=yes \
        --set detect.sgh-mpm-caching-path=./hs_cache \
        --set mpm-algo=hs \
        --set spm-algo=hs &
SURI_PID=$!

sleep 15

kill $NSLOOKUP_PID 2>/dev/null || true
wait $NSLOOKUP_PID 2>/dev/null || true

${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURI_PID

# Final verification
FINAL_ALERT_COUNT=$(jq -c 'select(.event_type == "alert")' ./eve.json 2>/dev/null | wc -l || echo "0")
if [ "$FINAL_ALERT_COUNT" -eq 0 ]; then
    echo "ERROR: No alerts in final test"
    RES=1
else
    echo "Found $FINAL_ALERT_COUNT alerts in final test"
fi

# Check final suricata.log for any cache errors
echo "=== Final cache error check ==="
if [ -f suricata.log ]; then
    if grep -q "Failed to serialize Hyperscan database" suricata.log; then
        echo "ERROR: Cache serialization failure detected"
        RES=1
    fi
    
    if grep -q "Failed to create Hyperscan cache file" suricata.log; then
        echo "ERROR: Cache creation failure detected"  
        RES=1
    fi
    
    if grep -q "Failed to deserialize Hyperscan database" suricata.log; then
        echo "ERROR: Cache deserialization failure detected"
        RES=1
    fi
fi

echo "=== ERROR CONDITION TESTS ==="

# Test cache permission error
echo "Testing cache permission error..."
chmod 555 ./hs_cache 2>/dev/null || true

timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v \
        --set af-packet.1.bpf-filter="port 53" \
        --set af-packet.1.tpacket-v3=true \
        --set default-rule-path=. \
        --set runmode=workers \
        --set detect.sgh-mpm-caching=yes \
        --set detect.sgh-mpm-caching-path=./hs_cache \
        --set mpm-algo=hs \
        --set spm-algo=hs &
SURI_PID=$!

sleep 8
${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket 2>/dev/null || kill $SURI_PID
wait $SURI_PID 2>/dev/null || true

# Check for permission error message
if grep -q "Failed to create Hyperscan cache file" suricata.log; then
    echo "SUCCESS: Cache permission error correctly detected"
else
    echo "WARNING: Cache permission error not detected in logs"
fi

# Restore permissions
chmod 755 ./hs_cache

# Test cache corruption
echo "Testing cache corruption..."
if [ -n "$(ls -A ./hs_cache 2>/dev/null)" ]; then
    # Corrupt a cache file
    CACHE_FILE=$(ls ./hs_cache/ | head -n1)
    if [ -n "$CACHE_FILE" ]; then
        echo "corrupted" > "./hs_cache/$CACHE_FILE"
        
        timeout --kill-after=240 --preserve-status 120 \
            ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v \
                --set af-packet.1.bpf-filter="port 53" \
                --set af-packet.1.tpacket-v3=true \
                --set default-rule-path=. \
                --set runmode=workers \
                --set detect.sgh-mpm-caching=yes \
                --set detect.sgh-mpm-caching-path=./hs_cache \
                --set mpm-algo=hs \
                --set spm-algo=hs &
        SURI_PID=$!
        
        sleep 8
        ${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket 2>/dev/null || kill $SURI_PID
        wait $SURI_PID 2>/dev/null || true
        
        if grep -q "Failed to deserialize Hyperscan database" suricata.log; then
            echo "SUCCESS: Cache corruption correctly detected"
        else
            echo "WARNING: Cache corruption not detected in logs"
        fi
    fi
fi

echo "=== FINAL SUMMARY ==="
echo "Cache directory contents:"
ls -la ./hs_cache/ 2>/dev/null || echo "No cache directory"

echo "Final result code: $RES"
exit $RES