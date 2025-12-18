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

#include "tm-threads-common.h"

typedef struct ThreadVars_ ThreadVars;

#ifdef HAVE_DPDK

/** Initialize internal DPDK threading state (call once after EAL init). */
void DpdkThreadingInit(void);

/** Allocate the next enabled lcore for the given interface from worker-cpu-set. */
uint32_t DpdkLcoreAllocate(const char *iface);

/** Spawn the thread on the lcore stored in `tv->capture_worker_id`. */
TmEcode DpdkThreadSpawn(ThreadVars *tv);

/** Wait for the lcore stored in `tv->capture_worker_id` to finish. */
TmEcode DpdkThreadJoin(ThreadVars *tv);

/** Return true if the thread is configured to be managed by DPDK (lcore thread). */
bool DpdkThreadAffinityHandled(const ThreadVars *tv);

/** Thread-exit hook for lcore threads (does not call pthread_exit). */
void DpdkThreadExit(ThreadVars *tv, int64_t code);

#endif /* HAVE_DPDK */

#endif /* SURICATA_UTIL_DPDK_THREAD_H */
