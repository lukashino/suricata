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
 * DPDK threading helpers implementation.
 */

#include "suricata-common.h"

#include "threadvars.h"
#include "tm-threads.h"
#include "util-affinity.h"
#include "util-debug.h"
#include "util-dpdk-thread.h"

#ifdef HAVE_DPDK

#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_lcore.h>

static cpu_set_t dpdk_used_lcores;
static bool dpdk_used_lcores_init;

typedef struct DpdkThreadCtx_ {
    uint32_t lcore_id;
} DpdkThreadCtx;

void DpdkThreadingInit(void)
{
    CPU_ZERO(&dpdk_used_lcores);
    dpdk_used_lcores_init = true;
}

uint32_t DpdkLcoreAllocate(const char *iface)
{
    if (!dpdk_used_lcores_init) {
        DpdkThreadingInit();
    }

    ThreadsAffinityType *itaf = GetAffinityTypeForNameAndIface("worker-cpu-set", iface);
    if (itaf == NULL) {
        itaf = GetAffinityTypeForNameAndIface("worker-cpu-set", NULL);
    }
    if (itaf == NULL) {
        FatalError("Specify worker-cpu-set list in the threading section");
    }

    const uint32_t max_cpu = MIN((uint32_t)RTE_MAX_LCORE, (uint32_t)CPU_SETSIZE);
    for (uint32_t cpu = 0; cpu < max_cpu; cpu++) {
        if (!CPU_ISSET(cpu, &itaf->cpu_set)) {
            continue;
        }
        if (CPU_ISSET(cpu, &dpdk_used_lcores)) {
            continue;
        }
        if (!rte_lcore_is_enabled(cpu)) {
            continue;
        }

        CPU_SET(cpu, &dpdk_used_lcores);
        return cpu;
    }

    FatalError("Interface %s requested more DPDK lcores than available in worker-cpu-set", iface);
    return TM_THREAD_AFFINITY_INVALID;
}

static int DpdkThreadEntry(void *arg)
{
    ThreadVars *tv = (ThreadVars *)arg;
    if (tv != NULL && tv->tm_func != NULL) {
        (void)tv->tm_func(tv);
    }
    return 0;
}

static TmEcode DpdkThreadSpawn(ThreadVars *tv, void *data)
{
    DpdkThreadCtx *ctx = (DpdkThreadCtx *)data;
    if (tv == NULL || tv->tm_func == NULL || ctx == NULL) {
        FatalError("DpdkThreadSpawn called with invalid thread");
    }

    if (ctx->lcore_id == TM_THREAD_AFFINITY_INVALID) {
        FatalError("DpdkThreadSpawn called without assigned lcore for thread %s", tv->name);
    }

    const int rc = rte_eal_remote_launch(DpdkThreadEntry, (void *)tv, ctx->lcore_id);
    if (rc != 0) {
        FatalError("Error (%s): can not launch function on lcore", rte_strerror(-rc));
    }
    return TM_ECODE_OK;
}

static TmEcode DpdkThreadJoin(ThreadVars *tv, void *data)
{
    DpdkThreadCtx *ctx = (DpdkThreadCtx *)data;
    if (tv == NULL || ctx == NULL) {
        return TM_ECODE_FAILED;
    }

    const int rc = rte_eal_wait_lcore(ctx->lcore_id);
    if (rc < 0) {
        FatalError("Error (%s): can not wait on lcore", rte_strerror(-rc));
    }

    return TM_ECODE_OK;
}

static void DpdkThreadExit(ThreadVars *tv, int64_t code, void *data)
{
    (void)tv;
    (void)code;
    (void)data;
}

static void DpdkThreadCtxFree(void *ptr)
{
    SCFree(ptr);
}

static const TmThreadLifecycleOps dpdk_thread_ops = {
    .spawn = DpdkThreadSpawn,
    .join = DpdkThreadJoin,
    .exit = DpdkThreadExit,
};

void DpdkThreadLifecycleRegister(ThreadVars *tv, uint32_t lcore_id)
{
    DpdkThreadCtx *ctx = SCCalloc(1, sizeof(*ctx));
    if (unlikely(ctx == NULL)) {
        FatalError("Failed to allocate DPDK thread context");
    }
    ctx->lcore_id = lcore_id;

    TmThreadLifecycleRegister(tv, &dpdk_thread_ops, ctx, DpdkThreadCtxFree, true, lcore_id);
}

#endif /* HAVE_DPDK */
