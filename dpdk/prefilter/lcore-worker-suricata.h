/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <lukas.sismis@cesnet.cz>
 */

#ifndef LCORE_WORKER_SURICATA_H
#define LCORE_WORKER_SURICATA_H

#include "dev-conf.h"
#include "lcore-worker.h"
#include "lcores-manager.h"

/*
 * Get a pointer to the beginning of memory, where the value will be assigned.
 * In case if offload is empty value is 0, otherwise an actual offset.
 * Offset is a length in bytes between the beginning of memory and the beginning
 * of data for the current offload.
 */
#define SET_OFFSET(ptr_hdr) \
    if ((ptr_hdr) == NULL) { \
        memset(priv_size + (t<<4), 0x00, sizeof(uint16_t)); \
        continue; \
    } \
    memcpy(priv_size + (t<<4), &offset, sizeof(uint16_t))

struct lcore_values *ThreadSuricataInit(struct lcore_init *init_vals);
void ThreadSuricataRun(struct lcore_values *lv);
void ThreadSuricataStatsDump(struct lcore_values *lv);
void ThreadSuricataStatsExit(struct lcore_values *lv, struct pf_stats *stats);
void ThreadSuricataDeinit(struct lcore_init *vals, struct lcore_values *lv);

#endif // LCORE_WORKER_SURICATA_H
