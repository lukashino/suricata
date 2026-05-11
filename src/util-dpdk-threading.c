/* Copyright (C) 2024-2026 Open Information Security Foundation
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
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * DPDK threading backend. Selects between EAL lcore launch (workers)
 * and DPDK control threads (managers/command threads) based on
 * ThreadVars::type.
 */

#include "suricata-common.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tm-threads-common.h"
#include "util-affinity.h"
#include "util-dpdk-threading.h"
#include "util-threading-backend.h"
#include "util-debug.h"
#include "runmodes.h"
#include "util-dpdk-common.h"

#ifdef HAVE_DPDK

extern uint64_t threading_set_stack_size;

static bool stacksize_warn_once = false;

/**
 * \brief Wrapper to convert ThreadVars thread function signature
 *        from void* (*)(void*) to int (*)(void*) for DPDK EAL launch.
 */
static int DpdkEalThreadWrapper(void *arg)
{
    ThreadVars *tv = (ThreadVars *)arg;
    tv->tm_func(tv);
    return 0;
}

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
/**
 * \brief Wrapper to convert ThreadVars thread function signature
 *        for DPDK control thread (returns uint32_t).
 */
static uint32_t DpdkCtrlThreadWrapper(void *arg)
{
    ThreadVars *tv = (ThreadVars *)arg;
    tv->tm_func(tv);
    return 0;
}
#endif

static void DpdkSpawnWorker(ThreadVars *tv)
{
    if (threading_set_stack_size && SCConfGetNode("dpdk.eal-params.huge-worker-stack") == NULL) {
        if (!stacksize_warn_once) {
            stacksize_warn_once = true;
            SCLogWarning("DPDK worker threads do not support Suricata-configured stack size. "
                         "Use additional DPDK EAL argument huge-worker-stack:[size in kB without a "
                         "unit] "
                         "to also set stack size for DPDK worker threads.");
        }
    }
    if (!(tv->thread_setup_flags & THREAD_SET_AFFTYPE)) {
        FatalError("%s: DPDK requires set threading affinity setting", tv->iface_name);
    }
    ThreadsAffinityType *taf = &thread_affinity[tv->cpu_affinity];
    if (!RunmodeIsWorkers() || !(tv->cpu_affinity == WORKER_CPU_SET)) {
        FatalError("%s: DPDK EAL threads can only initialize worker threads", tv->iface_name);
    }

    ThreadsAffinityType *if_taf = FindAffinityByInterface(taf, tv->iface_name);
    if (if_taf) {
        taf = if_taf;
    }

    if (UtilAffinityGetAffinedCPUNum(taf) == 0) {
        if (!taf->nocpu_warned) {
            SCLogWarning("No CPU affinity set for %s", AffinityGetYamlPath(taf));
            taf->nocpu_warned = true;
        }
    }

    if (taf->mode_flag != EXCLUSIVE_AFFINITY) {
        FatalError("%s: DPDK requires exclusive affinity setting", tv->iface_name);
    }

    /* If CPU is in a set overwrite the default thread prio */
    if (CPU_ISSET(tv->thread_id, &taf->lowprio_cpu)) {
        tv->thread_priority = PRIO_LOW;
    } else if (CPU_ISSET(tv->thread_id, &taf->medprio_cpu)) {
        tv->thread_priority = PRIO_MEDIUM;
    } else if (CPU_ISSET(tv->thread_id, &taf->hiprio_cpu)) {
        tv->thread_priority = PRIO_HIGH;
    } else {
        tv->thread_priority = taf->prio;
    }
    tv->thread_setup_flags =
            THREAD_SET_PRIORITY; // affinity is handled, prio handles the thread itself

    tv->thread_id = AffinityGetNextCPU(tv, taf);

    SCLogPerf("Setting prio %d for thread \"%s\" to cpu/core "
              "%" PRIu64 ", thread id %lu",
            tv->thread_priority, tv->name, tv->thread_id, SCGetThreadIdLong());

    int ret = rte_eal_remote_launch(DpdkEalThreadWrapper, (void *)tv, (unsigned)tv->thread_id);
    if (ret != 0) {
        FatalError("Unable to create DPDK EAL thread %s with rte_eal_remote_launch(): retval %d",
                tv->name, ret);
    }
}

static void DpdkJoinWorker(ThreadVars *tv)
{
    int ret = rte_eal_wait_lcore((unsigned)tv->thread_id);
    if (ret < 0) {
        SCLogError("%s: error waiting for DPDK lcore %" PRIu64 " (%s) to finish (%s)",
                tv->iface_name, tv->thread_id, tv->name, rte_strerror(-ret));
    }
}

static void DpdkSpawnControl(ThreadVars *tv)
{
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    rte_thread_t handle;
    int ret = rte_thread_create_control(&handle, tv->name, DpdkCtrlThreadWrapper, (void *)tv);
    if (ret != 0) {
        FatalError("Unable to create DPDK control thread %s with rte_thread_create_control(): %s",
                tv->name, rte_strerror(-ret));
    }
    /* opaque_id is uintptr_t; safely fits in uint64_t */
    tv->thread_id = (uint64_t)handle.opaque_id;
#else
    pthread_t handle;
    int ret = rte_ctrl_thread_create(&handle, tv->name, NULL, tv->tm_func, (void *)tv);
    if (ret != 0) {
        FatalError("Unable to create DPDK control thread %s with rte_ctrl_thread_create(): %s",
                tv->name, rte_strerror(-ret));
    }
    tv->thread_id = (uint64_t)handle;
#endif
}

static void DpdkJoinControl(ThreadVars *tv)
{
    if (tv->thread_id == 0) {
        return;
    }

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    rte_thread_t handle;
    handle.opaque_id = (uintptr_t)tv->thread_id;
    int ret = rte_thread_join(handle, NULL);
    if (ret != 0) {
        SCLogError("%s: error joining DPDK control thread (%s)", tv->name, rte_strerror(-ret));
    }
#else
    pthread_join((pthread_t)tv->thread_id, NULL);
#endif
}

static void DpdkBackendSpawn(ThreadVars *tv)
{
    if (tv->type == TVT_PPT) {
        DpdkSpawnWorker(tv);
    } else {
        DpdkSpawnControl(tv);
    }
}

static void DpdkBackendJoin(ThreadVars *tv)
{
    if (tv->type == TVT_PPT) {
        DpdkJoinWorker(tv);
    } else {
        DpdkJoinControl(tv);
    }
}

static const ThreadingBackend dpdk_backend = {
    .name = "dpdk",
    .Spawn = DpdkBackendSpawn,
    .Join = DpdkBackendJoin,
};

#endif /* HAVE_DPDK */

void DpdkThreadingBackendRegister(void)
{
#ifdef HAVE_DPDK
    ThreadingBackendRegister(&dpdk_backend);
#endif
}
