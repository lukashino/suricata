/* Copyright (C) 2021 Open Information Security Foundation
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
 * \author Lukas Sismis <sismis@cesnet.cz>
 */

#ifndef UTIL_DPDK_C
#define UTIL_DPDK_C

#include "suricata.h"
#include "flow-bypass.h"
#include "decode.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include "util-byte.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-i40e.h"

uint32_t ArrayMaxValue(const uint32_t *arr, uint16_t arr_len)
{
    uint32_t max = 0;
    for (uint16_t i = 0; i < arr_len; i++) {
        max = MAX(arr[i], max);
    }
    return max;
}

// Used to determine size for memory allocation of a string
uint8_t CountDigits(uint32_t n)
{
    uint8_t digits_cnt = 0;
    if (n == 0)
        return 1;

    while (n != 0) {
        n = n / 10;
        digits_cnt++;
    }
    return digits_cnt;
}

void DPDKCleanupEAL(void)
{
#ifdef HAVE_DPDK
    if (SCRunmodeGet() == RUNMODE_DPDK && rte_eal_process_type() == RTE_PROC_PRIMARY) {
        int retval = rte_eal_cleanup();
        if (retval != 0)
            SCLogError("EAL cleanup failed: %s", strerror(-retval));
    }
#endif
}

void DPDKCloseDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    int retval;
    if (SCRunmodeGet() == RUNMODE_DPDK && rte_eal_process_type() == RTE_PROC_PRIMARY) {
        uint16_t port_id;
        retval = rte_eth_dev_get_port_by_name(ldev->dev, &port_id);
        if (retval < 0) {
            SCLogError("%s: failed get port id, error: %s", ldev->dev, rte_strerror(-retval));
            return;
        }

        SCLogPerf("%s: closing device", ldev->dev);
        rte_eth_dev_close(port_id);
    }
#endif
}

void DPDKFreeDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    if (SCRunmodeGet() == RUNMODE_DPDK) {
        SCLogDebug("%s: releasing packet mempool", ldev->dev);
        rte_mempool_free(ldev->dpdk_vars.pkt_mp);
    }
#endif
}

#ifdef HAVE_DPDK
/**
 * Retrieves name of the port from port id
 * Not thread-safe
 * @param pid
 * @return static dev_name on success
 */
const char *DPDKGetPortNameByPortID(uint16_t pid)
{
    static char dev_name[RTE_ETH_NAME_MAX_LEN];
    int32_t ret = rte_eth_dev_get_name_by_port(pid, dev_name);
    if (ret < 0) {
        FatalError("Port %d: Failed to obtain port name (err: %s)", pid, rte_strerror(-ret));
    }
    return dev_name;
}

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_C */