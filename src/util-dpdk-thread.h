/* Copyright (C) 2025 Open Information Security Foundation
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
 * DPDK threading helpers.
 *
 * This module centralizes DPDK-specific thread lifecycle handling (spawn/join/exit)
 * and lcore allocation based on Suricata's CPU affinity configuration.
 */

#ifndef SURICATA_UTIL_DPDK_THREAD_H
#define SURICATA_UTIL_DPDK_THREAD_H

#include "tm-threads.h"

#ifdef HAVE_DPDK

/** Initialize internal DPDK threading state (call once after EAL init). */
void DpdkThreadingInit(void);

/** Allocate the next enabled lcore for the given interface from worker-cpu-set. */
uint32_t DpdkLcoreAllocate(const char *iface);

/** Register custom lifecycle callbacks for a DPDK-managed Suricata thread. */
void DpdkThreadLifecycleRegister(ThreadVars *tv, uint32_t lcore_id);

#endif /* HAVE_DPDK */

#endif /* SURICATA_UTIL_DPDK_THREAD_H */
