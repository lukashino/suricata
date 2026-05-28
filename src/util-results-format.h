/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 */

#ifndef SURICATA_UTIL_RESULTS_FORMAT_H
#define SURICATA_UTIL_RESULTS_FORMAT_H

#include "suricata-common.h"

/* Portable results-format layout constants.
 * The 12-byte buffer overlays the dst+src MAC area and holds 6 little-endian
 * uint16_t slots. Each slot packs pid into the low 14 bits and flag bits at
 * the top (bit15=PAYLOAD_FN, bit14=TOSERVER_DIR). */
#define PORTABLE_FORMAT_MAX_PIDS      6
#define PORTABLE_FORMAT_PID_BITS      14
#define PORTABLE_FORMAT_PID_MASK      ((1u << PORTABLE_FORMAT_PID_BITS) - 1)
#define PORTABLE_FORMAT_BYTES         (PORTABLE_FORMAT_MAX_PIDS * 2)
#define PORTABLE_FORMAT_FLAG_PAYLOAD  0x8000u
#define PORTABLE_FORMAT_FLAG_TOSERVER 0x4000u

/**
 * \brief Encode up to 6 MPM pattern IDs into a 12-byte buffer (portable format).
 *
 * Layout: 6 little-endian uint16_t slots overlaid on the dst+src MAC area.
 * Each slot: bit15 = PREFILTER_PKT_PAYLOAD_FN, bit14 = PREFILTER_PKT_TOSERVER_DIR,
 *            low 14 bits = pattern id (0..16383).
 *
 * On overflow (pids_cnt > 6, or pids[0] == UINT32_MAX, or any pid -- after
 * stripping flag bits -- >= 2^14), the entire 12-byte buffer is filled with
 * 0xFF as an overflow sentinel.
 *
 * \param out      Caller-provided 12-byte buffer (the MAC area in the mbuf).
 * \param pids     Source pattern IDs in the uint32_t format produced by the
 *                 MPM/payload pipeline (with the flag bits in their top bits).
 * \param pids_cnt Number of valid entries in `pids`.
 */
void EncodePortablePids(uint8_t out[PORTABLE_FORMAT_BYTES], const uint32_t *pids, uint32_t pids_cnt);

#ifdef UNITTESTS
void UtilResultsFormatRegisterTests(void);
#endif

#endif /* SURICATA_UTIL_RESULTS_FORMAT_H */
