/* Copyright (C) 2007-2016 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Jim Xu <jim.xu@windriver.com>
 * \author Justin Viiret <justin.viiret@intel.com>
 *
 * MPM pattern matcher that calls the Hyperscan regex matcher.
 */

#ifndef SURICATA_UTIL_MPM_HS__H
#define SURICATA_UTIL_MPM_HS__H

typedef struct SCHSPattern_ {
    /* length of the pattern */
    uint16_t len;
    /* flags describing the pattern */
    uint8_t flags;
    /* holds the original pattern that was added */
    uint8_t *original_pat;
    /* pattern id */
    uint32_t id;

    uint16_t offset;
    uint16_t depth;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

    /* only used at ctx init time, when this structure is part of a hash
     * table. */
    struct SCHSPattern_ *next;
} SCHSPattern;

/** Stores original (pre-truncation) pattern data for TP/FP classification */
typedef struct OriginalPatternInfo_ {
    uint8_t *original_pat;    /**< full original pattern bytes (allocated copy) */
    uint16_t original_len;    /**< full original length before truncation */
    uint8_t flags;            /**< MPM_PATTERN_FLAG_NOCASE etc. */
    uint16_t offset;          /**< original offset constraint */
    uint16_t depth;           /**< original depth constraint */
} OriginalPatternInfo;

/** For each pattern index in the (possibly truncated) database, maps to the
 *  original patterns that were registered before truncation. */
typedef struct TruncatedPatternMap_ {
    OriginalPatternInfo *originals;  /**< array of original patterns */
    uint32_t count;                  /**< number of originals */
    bool was_truncated;              /**< true if ANY original was longer than threshold */
} TruncatedPatternMap;

typedef struct SCHSCtx_ {
    /* hash used during ctx initialization */
    SCHSPattern **init_hash;

    /* pattern database and pattern arrays. */
    void *pattern_db;

    /* size of database, for accounting. */
    size_t hs_db_size;
} SCHSCtx;

typedef struct SCHSThreadCtx_ {
    /* Hyperscan scratch space region for this thread, capable of handling any
     * database that has been compiled. */
    void *scratch;

    /* size of scratch space, for accounting. */
    size_t scratch_size;
} SCHSThreadCtx;

void MpmHSRegister(void);

void MpmHSGlobalCleanup(void);

struct DetectEngineCtx_;
void SCHSBuildTruncationMap(MpmCtx *mpm_ctx, const struct DetectEngineCtx_ *de_ctx);

void SCHSVerifyTruncatedMatches(const MpmCtx *mpm_ctx,
        const uint8_t *matched_pat_bitset, uint32_t bitset_size,
        const uint8_t *buf, uint32_t buflen,
        uint64_t *tp_short, uint64_t *tp_long, uint64_t *fp_long,
        const char *ctx_type);

#endif /* SURICATA_UTIL_MPM_HS__H */
