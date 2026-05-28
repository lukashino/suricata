# `detect.results-format` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a runtime-selectable `detect.results-format` (`portable` | `extended`) that controls how matched MPM pattern IDs are embedded into outgoing packets. Portable mode overwrites only the 12-byte MAC area with 6 × `uint16_t` slots; extended mode keeps today's prepended-header layout.

**Architecture:** Internal storage (`Packet::matched_pids[64]` as `uint32_t`) is unchanged. A new global enum `g_results_format` is read at config-load time. `DPDKReleasePacket` dispatches to one of two writers — `WritePortablePids()` (new) or `WriteExtendedPids()` (today's prepend logic, refactored). Three fail-loud startup checks reject configurations that cannot produce correct output in portable mode.

**Tech Stack:** C (Suricata), DPDK mbuf API, Hyperscan MPM, Suricata `ConfGet*` YAML helpers, Suricata `FAIL_IF` / `UtRegisterTest` unit-test framework, bash + Python (Scapy) e2e tests.

**Spec:** `docs/superpowers/specs/2026-05-28-detect-results-format-design.md`

---

## Pre-flight

- [ ] **Step 0a: Confirm clean working tree**

Run: `git status`
Expected: working tree clean on branch `fpga-patternmatch-prefilter-save-pcaps` (or its agreed worktree). If not clean, ask the user.

- [ ] **Step 0b: Confirm baseline build is green**

Run: `make -j$(nproc) -C src 2>&1 | tail -5`
Expected: build succeeds (no errors). Note any pre-existing warnings — those are not your problem.

---

## Task 1: Add `ResultsFormat` enum, global, and YAML key parsing (Check 1)

**Files:**
- Modify: `src/source-dpdk.h` (export enum + global)
- Modify: `src/source-dpdk.c` (define global)
- Modify: `src/detect-engine.c` around line 2575 (parse the key during detect-engine init)

**Why here:** `detect.*` keys are already parsed inside `DetectEngineCtxInitReal()` in `src/detect-engine.c` (e.g. `detect.sgh-reverse-matching` at 2575, `detect.max-mpm-payload-pattern-length` at 2584). That's the established pattern — follow it.

- [ ] **Step 1.1: Declare enum and global in header**

Add to `src/source-dpdk.h`, just below the `#include` block near the top (find a similar `extern uint32_t g_max_mpm_pattern_ids;` declaration if present — otherwise place near the other DPDK globals):

```c
typedef enum {
    RESULTS_FORMAT_PORTABLE = 0,
    RESULTS_FORMAT_EXTENDED = 1,
} ResultsFormat;

extern ResultsFormat g_results_format;
```

If `g_max_mpm_pattern_ids` is declared in `src/decode.h:465` (it currently is) but **not** in `source-dpdk.h`, leave it where it is; just add the new declarations above to `source-dpdk.h`.

- [ ] **Step 1.2: Define global in source-dpdk.c**

Locate the line `uint32_t g_max_mpm_pattern_ids = MATCHED_PIDS_ARR_LEN_THRESH;` (currently `src/source-dpdk.c:98`). Immediately below it, add:

```c
/* Set by detect.results-format YAML key during detect-engine init.
 * No safe default: parsing fails loud if the key is missing/invalid. */
ResultsFormat g_results_format = RESULTS_FORMAT_EXTENDED;
```

(The initializer value here doesn't matter — Check 1 below FatalErrors before any packet is processed if the key is absent. We pick `EXTENDED` so any accidental path that runs without config-load still produces the legacy behaviour rather than silently writing into MACs.)

- [ ] **Step 1.3: Parse the key in detect-engine init**

In `src/detect-engine.c`, locate the `detect.sgh-reverse-matching` parsing block at lines ~2575–2581. Immediately after the closing brace of that `if (sgh_rev_matching) { ... }` (the block that sets `DE_REVERSE_SGH_MATCHING`), insert:

```c
    /* detect.results-format: REQUIRED. Selects portable vs extended packet
     * embedding for MPM match results. No safe default. */
    {
        const char *results_format_str = NULL;
        if (ConfGet("detect.results-format", &results_format_str) != 1 ||
                results_format_str == NULL) {
            FatalError("detect.results-format is required and must be "
                       "\"portable\" or \"extended\"");
        }
        if (strcmp(results_format_str, "portable") == 0) {
            g_results_format = RESULTS_FORMAT_PORTABLE;
        } else if (strcmp(results_format_str, "extended") == 0) {
            g_results_format = RESULTS_FORMAT_EXTENDED;
        } else {
            FatalError("detect.results-format has invalid value \"%s\"; "
                       "must be \"portable\" or \"extended\"",
                       results_format_str);
        }
        SCLogConfig("detect.results-format = %s", results_format_str);
    }
```

Add the include if not already present at the top of the file:
```c
#include "source-dpdk.h"
```
(If `HAVE_DPDK` guards exist in this file already, mirror them. If `source-dpdk.h` already comes in transitively, you can skip the explicit include — but verify by building.)

- [ ] **Step 1.4: Build**

Run: `make -j$(nproc) -C src 2>&1 | tail -20`
Expected: build succeeds.

- [ ] **Step 1.5: Manual smoke test — missing key fails loud**

Create a temporary minimal YAML by copying the existing test config and removing the new key. Run:

```bash
cp suricata-pcap-patternmatch.yaml /tmp/sf-test-no-key.yaml
# Ensure 'results-format:' is NOT present under detect: in this file
grep -E '^[[:space:]]*results-format:' /tmp/sf-test-no-key.yaml && echo "REMOVE IT" || echo "OK absent"
./src/suricata -T -c /tmp/sf-test-no-key.yaml -l /tmp 2>&1 | grep -E 'results-format|FATAL' | head -5
```

Expected output contains: `detect.results-format is required and must be "portable" or "extended"` and Suricata exits non-zero.

- [ ] **Step 1.6: Manual smoke test — invalid value fails loud**

```bash
cp suricata-pcap-patternmatch.yaml /tmp/sf-test-bad-key.yaml
# Append a bad key. If suricata-pcap-patternmatch.yaml has a 'detect:' block already, prefer editing it; otherwise append a top-level detect map.
printf '\ndetect:\n  results-format: portible\n' >> /tmp/sf-test-bad-key.yaml
./src/suricata -T -c /tmp/sf-test-bad-key.yaml -l /tmp 2>&1 | grep -E 'results-format|FATAL' | head -5
```

Expected output contains: `detect.results-format has invalid value "portible"; must be "portable" or "extended"`.

- [ ] **Step 1.7: Manual smoke test — valid value logs the config**

```bash
cp suricata-pcap-patternmatch.yaml /tmp/sf-test-good-key.yaml
printf '\ndetect:\n  results-format: extended\n' >> /tmp/sf-test-good-key.yaml
./src/suricata -T -c /tmp/sf-test-good-key.yaml -l /tmp 2>&1 | grep 'results-format'
```

Expected output contains: `detect.results-format = extended`.

- [ ] **Step 1.8: Commit**

```bash
git add src/source-dpdk.h src/source-dpdk.c src/detect-engine.c
git commit -m "detect: add required detect.results-format config key

Wires a new global g_results_format from a required YAML key. Fails loud
at startup if the key is missing or has any value other than \"portable\"
or \"extended\". No behaviour change yet -- subsequent commits wire this
through the DPDK release path and add the portable writer."
```

---

## Task 2: Enforce `max-mpm-pattern-ids <= 6` in portable mode (Check 2)

**Files:**
- Modify: `src/runmode-dpdk.c` around line 850 (the existing `max-mpm-pattern-ids` parsing block).

- [ ] **Step 2.1: Add the check after iface value is finalized**

In `src/runmode-dpdk.c`, after the line:
```c
    g_max_mpm_pattern_ids = iconf->max_mpm_pattern_ids;
```
(currently line 854), insert:

```c
    if (g_results_format == RESULTS_FORMAT_PORTABLE && iconf->max_mpm_pattern_ids > 6) {
        FatalError("%s: detect.results-format=portable but max-mpm-pattern-ids=%u "
                   "exceeds the 6-slot limit of the portable format. "
                   "Lower max-mpm-pattern-ids to <=6 or use results-format=extended.",
                   iconf->iface, iconf->max_mpm_pattern_ids);
    }
```

Ensure `source-dpdk.h` is included in `runmode-dpdk.c` (it likely already is via existing DPDK headers; if not, add `#include "source-dpdk.h"`).

- [ ] **Step 2.2: Build**

Run: `make -j$(nproc) -C src 2>&1 | tail -10`
Expected: build succeeds.

- [ ] **Step 2.3: Manual smoke test — portable + count 12 fails loud**

```bash
cp suricata-pcap-patternmatch.yaml /tmp/sf-test-cnt12.yaml
printf '\ndetect:\n  results-format: portable\n' >> /tmp/sf-test-cnt12.yaml
# Confirm the iface already has max-mpm-pattern-ids: 12 (it does in suricata.yaml.in default).
./src/suricata -T -c /tmp/sf-test-cnt12.yaml -l /tmp 2>&1 | grep -E 'portable|FATAL' | head -5
```

Expected output contains: `detect.results-format=portable but max-mpm-pattern-ids=12 exceeds the 6-slot limit`.

- [ ] **Step 2.4: Manual smoke test — portable + count 6 passes the check**

```bash
cp suricata-pcap-patternmatch.yaml /tmp/sf-test-cnt6.yaml
# Edit the iface block so max-mpm-pattern-ids: 6 (use sed against an unambiguous match)
sed -i 's/max-mpm-pattern-ids: 12/max-mpm-pattern-ids: 6/' /tmp/sf-test-cnt6.yaml
printf '\ndetect:\n  results-format: portable\n' >> /tmp/sf-test-cnt6.yaml
./src/suricata -T -c /tmp/sf-test-cnt6.yaml -l /tmp 2>&1 | grep -E 'results-format|FATAL' | head -5
```

Expected: `detect.results-format = portable` appears, and there is no FATAL about the 6-slot limit. (Other unrelated FATALs may occur if `-T` can't fully validate DPDK without a NIC; if so, look specifically for absence of the 6-slot message.)

- [ ] **Step 2.5: Commit**

```bash
git add src/runmode-dpdk.c
git commit -m "dpdk: reject max-mpm-pattern-ids > 6 in portable results format

Portable mode has exactly 6 fixed uint16_t slots in the 12-byte MAC area;
a max-mpm-pattern-ids value above 6 would silently truncate. Fail loud at
config-load instead."
```

---

## Task 3: Post-compile pid-range check for portable mode (Check 3)

**Files:**
- Modify: `src/util-mpm-hs.c` (hook into `SCHSPreparePatterns` — the per-PatternDatabase finalize where `pattern_cnt` is known).

**Why here:** The matched-pids array stores the Hyperscan callback `id` parameter, which is the index into `pd->parray[]` (range `0..pd->pattern_cnt-1`). The max representable pid in portable mode is `(1 << 14) - 1 = 16383`. So if any compiled PatternDatabase has `pattern_cnt > 16384`, portable mode cannot represent its match correctly.

- [ ] **Step 3.1: Locate `SCHSPreparePatterns`**

Run: `grep -n "SCHSPreparePatterns\b" src/util-mpm-hs.c`
Expected: function definition exists. Note the line where `pd->pattern_cnt` is final (after `parray` is populated and before `HashTableAdd(g_db_table, pd, 1)` at line ~937). The check belongs there — right before the new pd is cached.

- [ ] **Step 3.2: Add the check**

Just before the `int r = HashTableAdd(g_db_table, pd, 1);` line (currently line ~937), add:

```c
    /* Portable results-format embeds pattern IDs in 14 bits per slot.
     * matched_pids stores the Hyperscan callback id, which is a 0-based
     * index into pd->parray[] -- so its max value is pattern_cnt - 1. */
    if (g_results_format == RESULTS_FORMAT_PORTABLE && pd->pattern_cnt > (1u << 14)) {
        FatalError("detect.results-format=portable requires every MPM pattern "
                   "database to fit in 14 bits (< 16384 patterns). This "
                   "database has %u patterns. Reduce the rule set or use "
                   "results-format=extended.", pd->pattern_cnt);
    }
```

Add `#include "source-dpdk.h"` near the top of `src/util-mpm-hs.c` if not already present (check for any existing `source-dpdk.h` or `runmode-dpdk.h` include first; if neither is present, add the include).

- [ ] **Step 3.3: Build**

Run: `make -j$(nproc) -C src 2>&1 | tail -10`
Expected: build succeeds.

- [ ] **Step 3.4: Manual smoke test — small rule set passes**

```bash
cp /tmp/sf-test-cnt6.yaml /tmp/sf-test-compile.yaml
./src/suricata -T -c /tmp/sf-test-compile.yaml -l /tmp 2>&1 | grep -E 'pattern|FATAL|portable' | head -10
```

Expected: no FATAL about "14 bits" appears with the existing `custom-patlen/shmu.rules` rule set (which is large but should have well under 16k patterns per pd). If it does fire, that's a genuine signal that the rule set already exceeds portable mode's capacity — report this to the user before continuing.

- [ ] **Step 3.5: Commit**

```bash
git add src/util-mpm-hs.c
git commit -m "mpm-hs: reject pattern databases > 2^14 patterns in portable format

In portable results-format the matched-pid is encoded into 14 bits, so a
PatternDatabase with more than 16384 patterns cannot be represented. Fail
loud at pattern-compile time rather than silently truncating at runtime."
```

---

## Task 4: Refactor `DPDKReleasePacket` write path — extract `WriteExtendedPids` (pure refactor)

**Files:**
- Modify: `src/source-dpdk.c` around lines 322–365 (the existing prepend block inside `DPDKReleasePacket`).

**Goal:** Move the existing prepend logic verbatim into a new `static void WriteExtendedPids(Packet *p)` and replace the original code with a single call to it. No behaviour change.

- [ ] **Step 4.1: Add the extracted function**

Immediately above the existing `static void DPDKReleasePacket(Packet *p)` in `src/source-dpdk.c`, add:

```c
/**
 * \brief Extended results format writer.
 *
 * Prepends a variable-length header to the packet via DPDK mbuf headroom:
 *   | RESERVED (1B, 0xff) | PATIDs_LEN (2B) | PATID_SIZE (1B) | [PAT_ID (4B)]... |
 *   | Original Ethernet | IP | ...
 *
 * On insufficient headroom, logs a warning and leaves the packet unchanged.
 */
static void WriteExtendedPids(Packet *p)
{
    uint16_t pattern_ids_cnt = p->matched_pids_cnt;
    if (p->matched_pids[0] == UINT32_MAX) {
        pattern_ids_cnt = 1;
    }
    uint16_t pattern_ids_bytes = pattern_ids_cnt * sizeof(uint32_t);
    uint16_t header_size = 4; /* RESERVED + PATIDs_LEN + PATID_SIZE */
    uint16_t prepend_size = header_size + pattern_ids_bytes;

    uint8_t *prepend_ptr = (uint8_t *)rte_pktmbuf_prepend(p->dpdk_v.mbuf, prepend_size);
    if (prepend_ptr != NULL) {
        prepend_ptr[0] = 0xff;
        memcpy(prepend_ptr + 1, &pattern_ids_bytes, sizeof(uint16_t));
        prepend_ptr[3] = sizeof(uint32_t);
        for (uint32_t i = 0; i < pattern_ids_cnt; i++) {
            memcpy(prepend_ptr + header_size + i * sizeof(uint32_t),
                    &p->matched_pids[i], sizeof(uint32_t));
        }
    } else {
        SCLogWarning("Insufficient headroom for %u pattern IDs (need %u bytes), "
                     "try to increase mbuf size in your primary application",
                     p->matched_pids_cnt, prepend_size);
    }
}
```

- [ ] **Step 4.2: Replace the inline block in `DPDKReleasePacket`**

In `src/source-dpdk.c`, locate the block in `DPDKReleasePacket` that currently runs from the comment `/* Calculate space needed for pattern ID header: ... */` (around line 326) down through the closing `}` of the `else { SCLogWarning(...) }` branch (around line 358), plus the commented-out debug `printf` block immediately after. Replace that entire block with:

```c
    WriteExtendedPids(p);
```

- [ ] **Step 4.3: Build**

Run: `make -j$(nproc) -C src 2>&1 | tail -10`
Expected: build succeeds.

- [ ] **Step 4.4: Behavioural sanity — run existing e2e test**

Run: `bash custom-patlen/test-pattern-ids.sh 2>&1 | tail -30`
Expected: same pass/fail status as before this task. If the test was passing on master of this branch, it must still pass. If it was already failing for unrelated reasons, the failure pattern must be identical.

- [ ] **Step 4.5: Commit**

```bash
git add src/source-dpdk.c
git commit -m "dpdk: extract WriteExtendedPids from DPDKReleasePacket (no behaviour change)

Pure refactor in preparation for adding a second writer for the portable
results format. Existing prepend logic is unchanged; only the call site
moves."
```

---

## Task 5: Add pure `EncodePortablePids` helper with unit tests (TDD)

**Files:**
- Create: `src/util-results-format.h` (header for the pure encoding helper)
- Create: `src/util-results-format.c` (encoder + unit tests)
- Modify: `src/Makefile.am` (add the new files)
- Modify: `src/suricata.c` (register the unit-test entry point — same pattern as other Ut modules)

**Why a separate file:** the encoding is the most-likely-to-have-bugs piece (bit packing, sentinels, overflow detection). It is pure (input: `uint32_t pids[]`, `uint32_t cnt`; output: `uint8_t out[12]`) and has no DPDK dependency, so we can unit-test it. The DPDK release path will call this helper in Task 6.

- [ ] **Step 5.1: Write the header**

Create `src/util-results-format.h`:

```c
/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 */

#ifndef SURICATA_UTIL_RESULTS_FORMAT_H
#define SURICATA_UTIL_RESULTS_FORMAT_H

#include "suricata-common.h"

/**
 * \brief Encode up to 6 MPM pattern IDs into a 12-byte buffer (portable format).
 *
 * Layout: 6 little/host-endian uint16_t slots overlaid on the dst+src MAC area.
 * Each slot: bit15 = PREFILTER_PKT_PAYLOAD_FN, bit14 = PREFILTER_PKT_TOSERVER_DIR,
 *            low 14 bits = pattern id (0..16383).
 *
 * On overflow (pids_cnt > 6, or pids[0] == UINT32_MAX, or any pid >= 2^14),
 * the entire 12-byte buffer is filled with 0xFF as an overflow sentinel.
 *
 * \param out      Caller-provided 12-byte buffer (the MAC area in the mbuf).
 * \param pids     Source pattern IDs in the uint32_t format produced by the
 *                 MPM/payload pipeline (with the flag bits in their top bits).
 * \param pids_cnt Number of valid entries in `pids`.
 */
void EncodePortablePids(uint8_t out[12], const uint32_t *pids, uint32_t pids_cnt);

#ifdef UNITTESTS
void UtilResultsFormatRegisterTests(void);
#endif

#endif /* SURICATA_UTIL_RESULTS_FORMAT_H */
```

- [ ] **Step 5.2: Write the failing tests first**

Create `src/util-results-format.c` with the tests but a deliberately-broken implementation that will fail:

```c
/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 */

#include "suricata-common.h"
#include "util-results-format.h"
#include "decode.h" /* for PREFILTER_PKT_* flag bits and PREFILTER_FLAGS_SPACE */

void EncodePortablePids(uint8_t out[12], const uint32_t *pids, uint32_t pids_cnt)
{
    /* deliberately broken -- fixed in Step 5.4 */
    (void)out; (void)pids; (void)pids_cnt;
}

#ifdef UNITTESTS
#include "util-unittest.h"

/* Test 1: empty input -> all 12 bytes zero. */
static int UtilResultsFormatTest01(void)
{
    uint8_t out[12];
    memset(out, 0xAA, 12);
    EncodePortablePids(out, NULL, 0);
    for (int i = 0; i < 12; i++)
        FAIL_IF(out[i] != 0x00);
    PASS;
}

/* Test 2: single bare pid (no flags) -> slot[0] = pid, rest zero. */
static int UtilResultsFormatTest02(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x1234 };
    EncodePortablePids(out, pids, 1);
    uint16_t *slots = (uint16_t *)out;
    FAIL_IF(slots[0] != 0x1234);
    for (int i = 1; i < 6; i++)
        FAIL_IF(slots[i] != 0x0000);
    PASS;
}

/* Test 3: PAYLOAD_FN flag -> bit15 set. */
static int UtilResultsFormatTest03(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x42 | PREFILTER_PKT_PAYLOAD_FN };
    EncodePortablePids(out, pids, 1);
    uint16_t *slots = (uint16_t *)out;
    FAIL_IF(slots[0] != (0x42 | 0x8000));
    PASS;
}

/* Test 4: TOSERVER flag -> bit14 set. */
static int UtilResultsFormatTest04(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x42 | PREFILTER_PKT_TOSERVER_DIR };
    EncodePortablePids(out, pids, 1);
    uint16_t *slots = (uint16_t *)out;
    FAIL_IF(slots[0] != (0x42 | 0x4000));
    PASS;
}

/* Test 5: both flags set -> bit15 | bit14. */
static int UtilResultsFormatTest05(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x42 | PREFILTER_PKT_PAYLOAD_FN | PREFILTER_PKT_TOSERVER_DIR };
    EncodePortablePids(out, pids, 1);
    uint16_t *slots = (uint16_t *)out;
    FAIL_IF(slots[0] != (0x42 | 0xC000));
    PASS;
}

/* Test 6: max representable pid (16383) -> low 14 bits = 0x3FFF. */
static int UtilResultsFormatTest06(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x3FFF };
    EncodePortablePids(out, pids, 1);
    uint16_t *slots = (uint16_t *)out;
    FAIL_IF(slots[0] != 0x3FFF);
    PASS;
}

/* Test 7: pid >= 2^14 -> overflow sentinel (all 0xFF). */
static int UtilResultsFormatTest07(void)
{
    uint8_t out[12];
    memset(out, 0, 12);
    uint32_t pids[1] = { 0x4000 };
    EncodePortablePids(out, pids, 1);
    for (int i = 0; i < 12; i++)
        FAIL_IF(out[i] != 0xFF);
    PASS;
}

/* Test 8: 6 valid pids -> 6 slots filled, no overflow. */
static int UtilResultsFormatTest08(void)
{
    uint8_t out[12];
    uint32_t pids[6] = { 1, 2, 3, 4, 5, 6 };
    EncodePortablePids(out, pids, 6);
    uint16_t *slots = (uint16_t *)out;
    for (int i = 0; i < 6; i++)
        FAIL_IF(slots[i] != (uint16_t)(i + 1));
    PASS;
}

/* Test 9: 7 pids -> overflow sentinel. */
static int UtilResultsFormatTest09(void)
{
    uint8_t out[12];
    memset(out, 0, 12);
    uint32_t pids[7] = { 1, 2, 3, 4, 5, 6, 7 };
    EncodePortablePids(out, pids, 7);
    for (int i = 0; i < 12; i++)
        FAIL_IF(out[i] != 0xFF);
    PASS;
}

/* Test 10: MPM sentinel UINT32_MAX in pids[0] -> overflow sentinel. */
static int UtilResultsFormatTest10(void)
{
    uint8_t out[12];
    memset(out, 0, 12);
    uint32_t pids[1] = { UINT32_MAX };
    EncodePortablePids(out, pids, 1);
    for (int i = 0; i < 12; i++)
        FAIL_IF(out[i] != 0xFF);
    PASS;
}

/* Test 11: 4 pids fewer than 6 -> trailing slots are 0x0000. */
static int UtilResultsFormatTest11(void)
{
    uint8_t out[12];
    memset(out, 0xAA, 12);
    uint32_t pids[4] = { 0x11, 0x22, 0x33, 0x44 };
    EncodePortablePids(out, pids, 4);
    uint16_t *slots = (uint16_t *)out;
    FAIL_IF(slots[0] != 0x11);
    FAIL_IF(slots[1] != 0x22);
    FAIL_IF(slots[2] != 0x33);
    FAIL_IF(slots[3] != 0x44);
    FAIL_IF(slots[4] != 0x0000);
    FAIL_IF(slots[5] != 0x0000);
    PASS;
}

void UtilResultsFormatRegisterTests(void)
{
    UtRegisterTest("UtilResultsFormatTest01", UtilResultsFormatTest01);
    UtRegisterTest("UtilResultsFormatTest02", UtilResultsFormatTest02);
    UtRegisterTest("UtilResultsFormatTest03", UtilResultsFormatTest03);
    UtRegisterTest("UtilResultsFormatTest04", UtilResultsFormatTest04);
    UtRegisterTest("UtilResultsFormatTest05", UtilResultsFormatTest05);
    UtRegisterTest("UtilResultsFormatTest06", UtilResultsFormatTest06);
    UtRegisterTest("UtilResultsFormatTest07", UtilResultsFormatTest07);
    UtRegisterTest("UtilResultsFormatTest08", UtilResultsFormatTest08);
    UtRegisterTest("UtilResultsFormatTest09", UtilResultsFormatTest09);
    UtRegisterTest("UtilResultsFormatTest10", UtilResultsFormatTest10);
    UtRegisterTest("UtilResultsFormatTest11", UtilResultsFormatTest11);
}
#endif /* UNITTESTS */
```

- [ ] **Step 5.3: Wire into the build and unit-test registry**

In `src/Makefile.am`, locate any `util-*.c`/`util-*.h` pair line group (e.g. `util-validate.c util-validate.h`) and add `util-results-format.c util-results-format.h` to the source list in alphabetical order. Keep the trailing backslash convention of surrounding lines intact.

In `src/suricata.c`, locate `RegisterAllModules()` or the equivalent function that calls `*RegisterTests(void)` (search: `grep -n "RegisterTests(" src/suricata.c | head -20`). Add — inside the existing `#ifdef UNITTESTS` block where other tests are registered:

```c
    UtilResultsFormatRegisterTests();
```

And add at the top of `src/suricata.c`:

```c
#include "util-results-format.h"
```

- [ ] **Step 5.4: Build with unit tests enabled**

Run: `./configure --enable-unittests && make -j$(nproc) -C src 2>&1 | tail -20`

If the project is already configured with unit tests, just rebuild: `make -j$(nproc) -C src 2>&1 | tail -20`.

Expected: build succeeds.

- [ ] **Step 5.5: Run the tests and verify they FAIL**

Run: `./src/suricata -u -U "UtilResultsFormat" 2>&1 | tail -30`
Expected: all 11 `UtilResultsFormatTestNN` tests fail (because `EncodePortablePids` is the empty stub).

- [ ] **Step 5.6: Write the real implementation**

In `src/util-results-format.c`, replace the stub `EncodePortablePids` with:

```c
void EncodePortablePids(uint8_t out[12], const uint32_t *pids, uint32_t pids_cnt)
{
    memset(out, 0, 12);

    bool overflow = (pids_cnt > 6) || (pids_cnt > 0 && pids[0] == UINT32_MAX);
    if (!overflow) {
        for (uint32_t i = 0; i < pids_cnt; i++) {
            uint32_t pid = pids[i] & PREFILTER_FLAGS_SPACE;
            if (pid >= (1u << 14)) {
                overflow = true;
                break;
            }
        }
    }
    if (overflow) {
        memset(out, 0xFF, 12);
        return;
    }

    uint16_t *slots = (uint16_t *)out;
    for (uint32_t i = 0; i < pids_cnt; i++) {
        uint32_t v = pids[i];
        uint16_t pid14 = (uint16_t)(v & 0x3FFF);
        uint16_t flags = 0;
        if (v & PREFILTER_PKT_PAYLOAD_FN)   flags |= 0x8000;
        if (v & PREFILTER_PKT_TOSERVER_DIR) flags |= 0x4000;
        slots[i] = pid14 | flags;
    }
}
```

- [ ] **Step 5.7: Build and re-run tests, expect PASS**

Run: `make -j$(nproc) -C src 2>&1 | tail -10 && ./src/suricata -u -U "UtilResultsFormat" 2>&1 | tail -20`
Expected: all 11 tests pass.

- [ ] **Step 5.8: Commit**

```bash
git add src/util-results-format.h src/util-results-format.c src/Makefile.am src/suricata.c
git commit -m "util: add EncodePortablePids + unit tests

Pure encoder for the 12-byte portable results-format slot block. Carries
all the bit-packing, overflow-sentinel, and zero-fill logic in a single
testable function with no DPDK dependency. Wired into the existing
suricata -u unit-test runner."
```

---

## Task 6: Wire `WritePortablePids` and dispatch on `g_results_format`

**Files:**
- Modify: `src/source-dpdk.c` (add `WritePortablePids`, dispatch in `DPDKReleasePacket`).

- [ ] **Step 6.1: Add `WritePortablePids`**

In `src/source-dpdk.c`, just below the `WriteExtendedPids` function added in Task 4, add:

```c
#include "util-results-format.h"

/**
 * \brief Portable results format writer.
 *
 * Overwrites the 12-byte dst+src MAC area with up to 6 uint16_t pattern-id
 * slots. Packet layout (Ethertype, IP header, payload, ...) is byte-identical
 * to input -- no header bytes are added. See util-results-format.h for the
 * exact encoding.
 */
static void WritePortablePids(Packet *p)
{
    uint8_t *mac_area = rte_pktmbuf_mtod(p->dpdk_v.mbuf, uint8_t *);
    EncodePortablePids(mac_area, p->matched_pids, p->matched_pids_cnt);
}
```

If `util-results-format.h` is already included via another header, move the include to the top of the file alongside the other includes (don't leave it mid-file).

- [ ] **Step 6.2: Dispatch in `DPDKReleasePacket`**

Replace the `WriteExtendedPids(p);` line introduced in Task 4 with:

```c
    if (g_results_format == RESULTS_FORMAT_PORTABLE) {
        WritePortablePids(p);
    } else {
        WriteExtendedPids(p);
    }
```

- [ ] **Step 6.3: Build**

Run: `make -j$(nproc) -C src 2>&1 | tail -10`
Expected: build succeeds.

- [ ] **Step 6.4: Re-run extended e2e regression**

Run: `bash custom-patlen/test-pattern-ids.sh 2>&1 | tail -30`
Expected: same status as Task 4.4. This test still uses `extended`, so portable wiring must not affect it.

- [ ] **Step 6.5: Commit**

```bash
git add src/source-dpdk.c
git commit -m "dpdk: dispatch DPDKReleasePacket writer on detect.results-format

Adds WritePortablePids (overwrites the 12-byte MAC area, preserving packet
layout for external parsers) and dispatches between it and the existing
WriteExtendedPids based on g_results_format."
```

---

## Task 7: Document the new key in `suricata.yaml.in`

**Files:**
- Modify: `suricata.yaml.in` around line 1735 (the existing `detect:` block).

- [ ] **Step 7.1: Insert the documented key**

In `suricata.yaml.in`, immediately after `detect:` at line 1735, before `sgh-reverse-matching: yes` at line 1736, insert:

```yaml
  # Format used to embed MPM pattern-match results into outgoing packets
  # (for downstream FPGA/external parsers).
  #
  #   portable: 6 uint16_t pattern IDs overwrite the 12-byte src+dst MAC
  #             area. No header bytes are added; packet layout is preserved
  #             so external parsers continue to see normal Ethernet/IP/...
  #             Per-pid bits (host byte order): bit15 = PAYLOAD_FN,
  #             bit14 = TOSERVER, low 14 bits = pid (max id 16383,
  #             max 6 pids per packet). Overflow (count>6 or pid>=2^14)
  #             produces all 12 MAC bytes set to 0xFF as a sentinel.
  #
  #   extended: variable-length header prepended to the packet
  #             (RESERVED(0xff) | LEN(2B) | SIZE(1B) | [pid u32]...).
  #             Carries up to max-mpm-pattern-ids pids with full 30-bit
  #             pid space, but changes the on-wire packet layout.
  #
  # REQUIRED -- Suricata exits at startup if this key is missing.
  results-format: portable
```

- [ ] **Step 7.2: Verify there are no other `detect:` blocks**

Run: `grep -n "^detect:" suricata.yaml.in`
Expected: exactly one match at line ~1735. If more than one, ask the user.

- [ ] **Step 7.3: Commit**

```bash
git add suricata.yaml.in
git commit -m "yaml: document new required detect.results-format key

Adds the suricata.yaml.in entry for detect.results-format, describing both
\"portable\" (12-byte MAC overlay, packet layout preserved) and \"extended\"
(prepended header, full pid range) modes plus the overflow sentinel."
```

---

## Task 8: End-to-end test additions (portable round-trip, overflow, config validation)

**Files:**
- Create: `custom-patlen/test-portable-format.sh`
- Create: `custom-patlen/parse_portable.py` (Python/Scapy helper)

**Note:** the existing `custom-patlen/test-pattern-ids.sh` covers extended-mode round-tripping. Don't merge into it — add a sibling script so the two test suites stay independent.

- [ ] **Step 8.1: Add the Python parser helper**

Create `custom-patlen/parse_portable.py`:

```python
#!/usr/bin/env python3
"""Parse the portable results-format from a PCAP and report per-packet pids.

Layout (host byte order, little-endian on x86_64):
  Bytes 0..11 of each frame = 6 x uint16_t slots overlaying dst+src MAC.
  Each slot:
    bit15 = PAYLOAD_FN
    bit14 = TOSERVER
    low 14 bits = pid (0..16383)
  All slots 0xFFFF (i.e. all 12 bytes 0xFF) = overflow sentinel.
  Slot value 0x0000 = empty slot.
"""
import struct
import sys

from scapy.all import rdpcap

OVERFLOW_SENTINEL = b"\xff" * 12

def decode_slot(slot: int):
    payload_fn = bool(slot & 0x8000)
    toserver = bool(slot & 0x4000)
    pid = slot & 0x3FFF
    return pid, toserver, payload_fn

def main(path: str) -> int:
    packets = rdpcap(path)
    all_overflow = True
    for idx, pkt in enumerate(packets):
        raw = bytes(pkt)[:12]
        if raw == OVERFLOW_SENTINEL:
            print(f"pkt {idx}: OVERFLOW")
            continue
        all_overflow = False
        slots = struct.unpack("<6H", raw)
        entries = []
        for s in slots:
            if s == 0x0000:
                continue
            pid, toserver, payload_fn = decode_slot(s)
            entries.append(f"pid={pid} ts={int(toserver)} pl={int(payload_fn)}")
        print(f"pkt {idx}: {', '.join(entries) if entries else 'empty'}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
```

Make it executable: `chmod +x custom-patlen/parse_portable.py`.

- [ ] **Step 8.2: Add the e2e test script**

Create `custom-patlen/test-portable-format.sh`:

```bash
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
    # Set max-mpm-pattern-ids to the requested count (suricata.yaml.in default = 12).
    sed -i "s/max-mpm-pattern-ids: [0-9]\+/max-mpm-pattern-ids: ${count}/" "$out"
    # Append (or set) detect.results-format.
    if grep -qE '^detect:' "$out"; then
        # Insert under existing detect block (works because we just need *a* value)
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

# --- Test 3: portable + max-mpm-pattern-ids=12 -> FATAL ---
YAML="$WORK_DIR/portable-cnt12.yaml"
make_yaml "$YAML" "portable" 12
"$SURICATA_BIN" -T -c "$YAML" -l "$WORK_DIR" > "$WORK_DIR/portable-cnt12.log" 2>&1
if grep -q 'exceeds the 6-slot limit' "$WORK_DIR/portable-cnt12.log"; then
    pass "portable + count>6 -> FATAL"
else
    fail "portable + count>6 -> expected FATAL"
    info "log tail:"; tail -5 "$WORK_DIR/portable-cnt12.log"
fi

# --- Test 4: portable round-trip ---
# Mirrors test-pattern-ids.sh's invocation: requires root + DPDK, runs the
# PCAP-in/PCAP-out flow defined by suricata-pcap-patternmatch.yaml.
YAML="$WORK_DIR/portable-cnt6.yaml"
make_yaml "$YAML" "portable" 6
OUTPUT_PCAP="${SCRIPT_DIR}/shmu-tls-new.pcap"   # path defined in YAML_BASE
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
```

`chmod +x custom-patlen/test-portable-format.sh`.

**Note on Test 4:** the existing `test-pattern-ids.sh` runs Suricata against the input pcap and produces an output pcap. Inspect that script for the exact invocation and either reuse its runner via `DPDK_PCAP_RUNNER` env var, or copy the invocation block in. Don't invent a new runner.

- [ ] **Step 8.3: Run the new test suite**

```bash
bash custom-patlen/test-portable-format.sh 2>&1 | tail -30
```

Expected: Tests 1–3 (config validation) pass. Test 4 either passes or is skipped depending on environment.

- [ ] **Step 8.4: Run the existing extended-mode test for regression**

```bash
bash custom-patlen/test-pattern-ids.sh 2>&1 | tail -30
```

Expected: same status as Task 4.4 — extended mode still produces the prepended header.

- [ ] **Step 8.5: Commit**

```bash
git add custom-patlen/test-portable-format.sh custom-patlen/parse_portable.py
git commit -m "test: e2e tests for detect.results-format=portable

Covers (1) missing/invalid key -> FATAL, (2) portable + max-mpm-pattern-ids>6
-> FATAL, and (3) round-trip decode of the 12-byte MAC overlay back to
per-packet pid lists via Scapy. Skips the round-trip test when no DPDK
runner is available in the environment."
```

---

## Self-review (perform after all tasks above; do not skip)

- [ ] **Step 9.1: Re-read the spec section by section and confirm coverage**

For each section in `docs/superpowers/specs/2026-05-28-detect-results-format-design.md`:
- Configuration → Task 1 (parsing), Task 7 (docs).
- Internal storage → unchanged (verified by extended e2e regression in Task 4.4 / 6.4 / 8.4).
- Output stage / WritePortablePids / WriteExtendedPids → Task 4, 5, 6.
- Check 1 (YAML required key) → Task 1.
- Check 2 (count cap) → Task 2.
- Check 3 (pid-range scan) → Task 3.
- Testing → Task 5 (unit), Task 8 (e2e).

- [ ] **Step 9.2: Type / symbol consistency sweep**

Run:
```bash
grep -n "RESULTS_FORMAT_\|g_results_format\|EncodePortablePids\|WritePortablePids\|WriteExtendedPids" src/ -r
```
Expected: every identifier is defined exactly once and used with the same spelling / casing everywhere.

- [ ] **Step 9.3: Final build + full suite**

```bash
make -j$(nproc) -C src 2>&1 | tail -5
./src/suricata -u -U "UtilResultsFormat" 2>&1 | tail -20
bash custom-patlen/test-portable-format.sh 2>&1 | tail -20
bash custom-patlen/test-pattern-ids.sh 2>&1 | tail -20
```

Expected: build clean, unit tests pass, both e2e suites pass (or skip cleanly).

- [ ] **Step 9.4: Push when the user asks**

Don't push without explicit instruction from the user.
