/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 */

#include "suricata-common.h"
#include "util-results-format.h"
#include "decode.h" /* for PREFILTER_PKT_* flag bits and PREFILTER_FLAGS_SPACE */

void EncodePortablePids(uint8_t out[PORTABLE_FORMAT_BYTES], const uint32_t *pids, uint32_t pids_cnt)
{
    memset(out, 0, PORTABLE_FORMAT_BYTES);

    bool overflow = (pids_cnt > PORTABLE_FORMAT_MAX_PIDS) ||
                    (pids_cnt > 0 && pids[0] == UINT32_MAX);
    if (!overflow) {
        for (uint32_t i = 0; i < pids_cnt; i++) {
            uint32_t pid = pids[i] & PREFILTER_FLAGS_SPACE;
            if (pid >= (1u << PORTABLE_FORMAT_PID_BITS)) {
                overflow = true;
                break;
            }
        }
    }
    if (overflow) {
        memset(out, 0xFF, PORTABLE_FORMAT_BYTES);
        return;
    }

    for (uint32_t i = 0; i < pids_cnt; i++) {
        uint32_t v = pids[i];
        uint16_t slot = (uint16_t)(v & PORTABLE_FORMAT_PID_MASK);
        if (v & PREFILTER_PKT_PAYLOAD_FN)   slot |= PORTABLE_FORMAT_FLAG_PAYLOAD;
        if (v & PREFILTER_PKT_TOSERVER_DIR) slot |= PORTABLE_FORMAT_FLAG_TOSERVER;
        /* Little-endian byte serialization — wire format is portable. */
        out[i * 2 + 0] = (uint8_t)(slot & 0xFF);
        out[i * 2 + 1] = (uint8_t)(slot >> 8);
    }
}

#ifdef UNITTESTS
#include "util-unittest.h"

static uint16_t SlotAt(const uint8_t out[12], uint32_t idx)
{
    return (uint16_t)out[idx * 2] | ((uint16_t)out[idx * 2 + 1] << 8);
}

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
    FAIL_IF(SlotAt(out, 0) != 0x1234);
    for (uint32_t i = 1; i < 6; i++)
        FAIL_IF(SlotAt(out, i) != 0x0000);
    PASS;
}

/* Test 3: PAYLOAD_FN flag -> bit15 set. */
static int UtilResultsFormatTest03(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x42 | PREFILTER_PKT_PAYLOAD_FN };
    EncodePortablePids(out, pids, 1);
    FAIL_IF(SlotAt(out, 0) != (0x42 | 0x8000));
    PASS;
}

/* Test 4: TOSERVER flag -> bit14 set. */
static int UtilResultsFormatTest04(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x42 | PREFILTER_PKT_TOSERVER_DIR };
    EncodePortablePids(out, pids, 1);
    FAIL_IF(SlotAt(out, 0) != (0x42 | 0x4000));
    PASS;
}

/* Test 5: both flags set -> bit15 | bit14. */
static int UtilResultsFormatTest05(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x42 | PREFILTER_PKT_PAYLOAD_FN | PREFILTER_PKT_TOSERVER_DIR };
    EncodePortablePids(out, pids, 1);
    FAIL_IF(SlotAt(out, 0) != (0x42 | 0xC000));
    PASS;
}

/* Test 6: max representable pid (16383) -> low 14 bits = 0x3FFF. */
static int UtilResultsFormatTest06(void)
{
    uint8_t out[12];
    uint32_t pids[1] = { 0x3FFF };
    EncodePortablePids(out, pids, 1);
    FAIL_IF(SlotAt(out, 0) != 0x3FFF);
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
    for (uint32_t i = 0; i < 6; i++)
        FAIL_IF(SlotAt(out, i) != (uint16_t)(i + 1));
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
    FAIL_IF(SlotAt(out, 0) != 0x11);
    FAIL_IF(SlotAt(out, 1) != 0x22);
    FAIL_IF(SlotAt(out, 2) != 0x33);
    FAIL_IF(SlotAt(out, 3) != 0x44);
    FAIL_IF(SlotAt(out, 4) != 0x0000);
    FAIL_IF(SlotAt(out, 5) != 0x0000);
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
