/* Copyright (C) 2024 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_MPM_RXP__H
#define SURICATA_UTIL_MPM_RXP__H

struct regex_conf {
    uint32_t nb_qps;
    uint16_t qp_id_base;
    struct rte_regex_ops **ops;
//   struct regex_stats_burst *stats;
};

typedef struct SCRXPPattern_ {
    int unused;
    // /* length of the pattern */
    // uint16_t len;
    // /* flags describing the pattern */
    // uint8_t flags;
    // /* holds the original pattern that was added */
    // uint8_t *original_pat;
    // /* pattern id */
    // uint32_t id;

    // uint16_t offset;
    // uint16_t depth;

    // /* sid(s) for this pattern */
    // uint32_t sids_size;
    // SigIntId *sids;

    // /* only used at ctx init time, when this structure is part of a hash
    //  * table. */
    // struct SCRXPPattern_ *next;
} SCRXPPattern;

typedef struct SCRXPCtx_ {
    int unused;
    // /* hash used during ctx initialization */
    // SCRXPPattern **init_hash;

    // /* pattern database and pattern arrays. */
    // void *pattern_db;

    // /* size of database, for accounting. */
    // size_t hs_db_size;
} SCRXPCtx;

typedef struct SCRXPThreadCtx_ {
    int unused;
    // /* Hyperscan scratch space region for this thread, capable of handling any
    //  * database that has been compiled. */
    // void *scratch;

    // /* size of scratch space, for accounting. */
    // size_t scratch_size;
} SCRXPThreadCtx;

void MpmRXPRegister(void);

void MpmRXPGlobalCleanup(void);

#endif /* SURICATA_UTIL_MPM_RXP__H */
