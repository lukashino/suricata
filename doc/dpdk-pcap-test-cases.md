# DPDK net_pcap Auto-Exit Feature - Test Cases

This document describes the three test cases for validating the DPDK net_pcap auto-exit functionality.

## Overview

The DPDK net_pcap auto-exit feature automatically detects when a PCAP file has been fully read and gracefully stops the interface. This allows offline testing of DPDK capture methods without requiring timeout workarounds.

## Test Prerequisites

1. DPDK installed and configured
2. Sample PCAP files for testing
3. Suricata compiled with DPDK support (--enable-dpdk)
4. Sufficient system resources (hugepages, CPU cores)

## Test Case 1: Single PCAP File Interface

**Configuration File:** `.github/workflows/dpdk/suricata-pcap-single.yaml`

**Purpose:** Validate that a single net_pcap interface correctly detects EOF and exits.

**Setup:**
```yaml
dpdk:
  eal-params:
    vdev: 'net_pcap0,rx_pcap=/path/to/capture.pcap'
  interfaces:
    - interface: net_pcap0
      pcap-file-mode: true  # Optional, auto-detected
```

**Expected Behavior:**
1. Suricata starts and initializes the net_pcap0 interface
2. Packets are read from the PCAP file
3. After all packets are processed, the interface detects EOF (100 consecutive zero-packet polls)
4. Log message: "PCAP file mode: EOF detected (no packets received after 100 polls) - stopping interface..."
5. The receive loop exits gracefully
6. Suricata continues running but the interface stops processing

**Validation Points:**
- All packets from PCAP file are processed
- EOF detection occurs after approximately 100 zero-packet polls
- No errors or crashes occur
- Flow records and statistics are preserved
- Log messages indicate clean shutdown of the interface

**Test Command:**
```bash
# Replace /path/to/capture.pcap with actual PCAP file
suricata -c /path/to/suricata-pcap-single.yaml --dpdk
```

## Test Case 2: Multiple PCAP File Interfaces

**Configuration File:** `.github/workflows/dpdk/suricata-pcap-multiple.yaml`

**Purpose:** Validate that multiple net_pcap interfaces independently detect EOF and exit.

**Setup:**
```yaml
dpdk:
  eal-params:
    vdev: ['net_pcap0,rx_pcap=/path/to/capture1.pcap',
           'net_pcap1,rx_pcap=/path/to/capture2.pcap']
  interfaces:
    - interface: net_pcap0
      pcap-file-mode: true
    - interface: net_pcap1
      pcap-file-mode: true
```

**Expected Behavior:**
1. Suricata starts and initializes both net_pcap interfaces
2. Both interfaces independently read from their respective PCAP files
3. Each interface independently detects EOF when its PCAP file is exhausted
4. Log messages for each interface indicate EOF detection
5. Interfaces may exit at different times depending on PCAP file sizes
6. Suricata continues running until all interfaces complete
7. Flow records and state are preserved across interface shutdowns

**Validation Points:**
- Both PCAP files are fully processed
- Each interface independently detects EOF
- Interface 1 can finish before Interface 2 (or vice versa)
- No cross-interference between interfaces
- All flows are properly tracked and logged
- Statistics are correctly maintained for each interface

**Test Command:**
```bash
# Replace paths with actual PCAP files of different sizes
suricata -c /path/to/suricata-pcap-multiple.yaml --dpdk
```

**Test Variations:**
- Use PCAP files of different sizes to test independent EOF detection
- Use identical PCAP files to test synchronized shutdown
- Use one small and one large PCAP to test sequential shutdown

## Test Case 3: Mixed Interface Types

**Configuration File:** `.github/workflows/dpdk/suricata-pcap-mixed.yaml`

**Purpose:** Validate that net_pcap interfaces with PCAP file mode can coexist with regular DPDK interfaces.

**Setup:**
```yaml
dpdk:
  eal-params:
    vdev: ['net_pcap0,rx_pcap=/path/to/capture.pcap', 'net_null0']
  interfaces:
    - interface: net_pcap0
      pcap-file-mode: true    # PCAP file interface
    - interface: net_null0
      pcap-file-mode: false   # Regular interface
```

**Expected Behavior:**
1. Suricata starts and initializes both interfaces
2. net_pcap0 reads from PCAP file with auto-exit enabled
3. net_null0 continues polling normally without auto-exit
4. net_pcap0 detects EOF and exits after 100 zero-packet polls
5. net_null0 continues running indefinitely (or until manual stop)
6. Suricata process remains running with net_null0 active
7. Flow records and statistics are maintained

**Validation Points:**
- PCAP interface exits after EOF detection
- Regular interface continues polling without exit
- No interference between different interface types
- Correct behavior for pcap-file-mode: true vs false
- Auto-detection works correctly (net_pcap detected, null interface not)
- Manual stop (Ctrl+C or signal) properly shuts down remaining interfaces

**Test Command:**
```bash
suricata -c /path/to/suricata-pcap-mixed.yaml --dpdk
# Manually stop after PCAP interface exits to verify net_null0 continues
```

**Test Variations:**
- Mix net_pcap with physical NICs (if available)
- Mix multiple net_pcap interfaces with net_null
- Test with pcap-file-mode explicitly set vs auto-detected

## Common Validation Steps

For all test cases, verify:

1. **Startup:**
   - Clean initialization of all interfaces
   - Correct driver detection (net_pcap identified)
   - PCAP file mode enabled message in logs

2. **Processing:**
   - All packets from PCAP files are processed
   - Correct packet counts in statistics
   - No dropped packets due to EOF detection
   - Alerts and flows are generated correctly

3. **EOF Detection:**
   - Log message: "PCAP file mode: EOF detected..."
   - Approximately 100 zero-packet polls before exit
   - Clean receive loop exit (no crashes)

4. **Shutdown:**
   - Graceful interface shutdown
   - Statistics properly reported
   - No resource leaks
   - Flow tables preserved

5. **Performance:**
   - No performance degradation compared to regular DPDK capture
   - Zero-packet polling overhead is minimal
   - EOF detection is timely (not delayed excessively)

## Troubleshooting

### Issue: Interface exits too early
- Check PCAP file is not corrupted
- Verify PCAP file path is correct
- Ensure PCAP file is not empty

### Issue: Interface never exits
- Verify pcap-file-mode is enabled
- Check that driver is net_pcap (not physical NIC)
- Ensure PCAP file reading completes (check file access)
- Verify threshold (PCAP_FILE_ZERO_POLL_THRESHOLD) is not too high

### Issue: Suricata exits completely instead of just interface
- Verify you're not sending SIGTERM or SIGINT
- Check for crashes in logs
- Ensure proper error handling in receive loop

## Success Criteria

All test cases pass if:

1. ✓ No crashes or errors during execution
2. ✓ All packets from PCAP files are processed correctly
3. ✓ EOF detection occurs after ~100 zero-packet polls
4. ✓ Per-interface exit works as expected
5. ✓ No interference between different interface types
6. ✓ Flow records and statistics are accurate
7. ✓ Graceful shutdown of interfaces
8. ✓ No memory leaks or resource issues
9. ✓ Log messages are informative and accurate
10. ✓ Performance is comparable to regular DPDK capture

## Regression Testing

To ensure no regression with regular DPDK interfaces:

1. Run existing DPDK tests with physical NICs
2. Verify net_null driver behavior unchanged
3. Test interrupt mode is not affected
4. Verify IPS mode works correctly
5. Check multi-queue configurations
6. Validate bond interface functionality

Run these tests with and without the new feature to ensure backward compatibility.
