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
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 */

#ifndef UTIL_DPDK_H
#define UTIL_DPDK_H

#include "autoconf.h"

#ifdef HAVE_DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_tcp.h>

#include "util-device.h"
#include "util-atomic.h"
#include "decode.h"

#define RSS_HKEY_LEN 40

#if RTE_VER_YEAR < 22
#define RTE_ETH_MQ_RX_RSS ETH_MQ_RX_RSS

#endif

#if RTE_VER_YEAR < 21 || RTE_VER_YEAR == 21 && RTE_VER_MONTH < 11
#define RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE DEV_TX_OFFLOAD_MBUF_FAST_FREE

#define RTE_ETH_RX_OFFLOAD_CHECKSUM DEV_RX_OFFLOAD_CHECKSUM
#define RTE_ETH_RX_OFFLOAD_RSS_HASH DEV_RX_OFFLOAD_RSS_HASH

#define RTE_ETH_MQ_TX_NONE ETH_MQ_TX_NONE

#define RTE_ETH_MQ_RX_NONE ETH_MQ_RX_NONE

#define RTE_ETH_RSS_IP     ETH_RSS_IP
#define RTE_ETH_RSS_UDP    ETH_RSS_UDP
#define RTE_ETH_RSS_TCP    ETH_RSS_TCP
#define RTE_ETH_RSS_SCTP   ETH_RSS_SCTP
#define RTE_ETH_RSS_TUNNEL ETH_RSS_TUNNEL

#define RTE_ETH_RSS_L3_SRC_ONLY ETH_RSS_L3_SRC_ONLY
#define RTE_ETH_RSS_L3_DST_ONLY ETH_RSS_L3_DST_ONLY
#define RTE_ETH_RSS_L4_SRC_ONLY ETH_RSS_L4_SRC_ONLY
#define RTE_ETH_RSS_L4_DST_ONLY ETH_RSS_L4_DST_ONLY

#define RTE_ETH_RSS_IPV4               ETH_RSS_IPV4
#define RTE_ETH_RSS_FRAG_IPV4          ETH_RSS_FRAG_IPV4
#define RTE_ETH_RSS_NONFRAG_IPV4_TCP   ETH_RSS_NONFRAG_IPV4_TCP
#define RTE_ETH_RSS_NONFRAG_IPV4_UDP   ETH_RSS_NONFRAG_IPV4_UDP
#define RTE_ETH_RSS_NONFRAG_IPV4_SCTP  ETH_RSS_NONFRAG_IPV4_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV4_OTHER ETH_RSS_NONFRAG_IPV4_OTHER
#define RTE_ETH_RSS_IPV6               ETH_RSS_IPV6
#define RTE_ETH_RSS_FRAG_IPV6          ETH_RSS_FRAG_IPV6
#define RTE_ETH_RSS_NONFRAG_IPV6_TCP   ETH_RSS_NONFRAG_IPV6_TCP
#define RTE_ETH_RSS_NONFRAG_IPV6_UDP   ETH_RSS_NONFRAG_IPV6_UDP
#define RTE_ETH_RSS_NONFRAG_IPV6_SCTP  ETH_RSS_NONFRAG_IPV6_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV6_OTHER ETH_RSS_NONFRAG_IPV6_OTHER
#define RTE_ETH_RSS_L2_PAYLOAD         ETH_RSS_L2_PAYLOAD
#define RTE_ETH_RSS_IPV6_EX            ETH_RSS_IPV6_EX
#define RTE_ETH_RSS_IPV6_TCP_EX        ETH_RSS_IPV6_TCP_EX
#define RTE_ETH_RSS_IPV6_UDP_EX        ETH_RSS_IPV6_UDP_EX
#define RTE_ETH_RSS_PORT               ETH_RSS_PORT
#define RTE_ETH_RSS_VXLAN              ETH_RSS_VXLAN
#define RTE_ETH_RSS_GENEVE             ETH_RSS_GENEVE
#define RTE_ETH_RSS_NVGRE              ETH_RSS_NVGRE
#define RTE_ETH_RSS_GTPU               ETH_RSS_GTPU

#define RTE_MBUF_F_RX_IP_CKSUM_MASK PKT_RX_IP_CKSUM_MASK
#define RTE_MBUF_F_RX_IP_CKSUM_NONE PKT_RX_IP_CKSUM_NONE
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD PKT_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_IP_CKSUM_BAD  PKT_RX_IP_CKSUM_BAD

#define RTE_MBUF_F_RX_L4_CKSUM_MASK PKT_RX_L4_CKSUM_MASK
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD PKT_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD  PKT_RX_L4_CKSUM_BAD
#endif
typedef enum { DPDK_COPY_MODE_NONE, DPDK_COPY_MODE_TAP, DPDK_COPY_MODE_IPS } DpdkCopyModeEnum;

typedef enum {
    DPDK_ETHDEV_MODE, // run as DPDK primary process
    DPDK_RING_MODE,   // run as DPDK secondary process
} DpdkOperationMode;

/* DPDK Flags */
// General flags
#define DPDK_PROMISC   (1 << 0) /**< Promiscuous mode */
#define DPDK_MULTICAST (1 << 1) /**< Enable multicast packets */
// Offloads
#define DPDK_RX_CHECKSUM_OFFLOAD (1 << 4) /**< Enable chsum offload */

#endif /* HAVE_DPDK */

typedef struct DPDKIfaceConfig_ {
#ifdef HAVE_DPDK
    char iface[RTE_ETH_NAME_MAX_LEN];
    uint16_t port_id;
    uint16_t socket_id;
    DpdkOperationMode op_mode;
    /* number of threads - zero means all available */
    int threads;
    /* Ring mode settings */
    // Holds reference to all rx/tx rings, later assigned to workers
    struct rte_ring **rx_rings;
    struct rte_ring **tx_rings;
    struct rte_ring **tasks_rings;
    struct rte_ring **results_rings;
    struct rte_mempool **messages_mempools;
    /* End of ring mode settings */
    /* IPS mode */
    DpdkCopyModeEnum copy_mode;
    const char *out_iface;
    uint16_t out_port_id;
    /* DPDK flags */
    uint32_t flags;
    ChecksumValidationMode checksum_mode;
    uint64_t rss_hf;
    /* set maximum transmission unit of the device in bytes */
    uint16_t mtu;
    uint16_t nb_rx_queues;
    uint16_t nb_rx_desc;
    uint16_t nb_tx_queues;
    uint16_t nb_tx_desc;
    uint32_t mempool_size;
    uint32_t mempool_cache_size;
    struct rte_mempool *pkt_mempool;
    SC_ATOMIC_DECLARE(unsigned int, ref);
    /* threads bind queue id one by one */
    SC_ATOMIC_DECLARE(uint16_t, queue_id);
    SC_ATOMIC_DECLARE(uint16_t, inconsitent_numa_cnt);
    void (*DerefFunc)(void *);

    struct rte_flow *flow[100];
#endif
} DPDKIfaceConfig;

uint32_t ArrayMaxValue(const uint32_t *arr, uint16_t arr_len);
uint8_t CountDigits(uint32_t n);
void DPDKCleanupEAL(void);

void DPDKCloseDevice(LiveDevice *ldev);

#ifdef HAVE_DPDK
struct PFConfRingEntry {
    char rx_ring_name[RTE_RING_NAMESIZE];
    uint16_t pf_lcores;
    struct rte_ring *tasks_ring;
    struct rte_ring *results_ring;
    struct rte_mempool *message_mp;
};

struct PFConf {
    uint32_t ring_entries_cnt;
    struct PFConfRingEntry *ring_entries;
};

enum PFMessageType {
    PF_MESSAGE_BYPASS_ADD,
    PF_MESSAGE_BYPASS_SOFT_DELETE,
    PF_MESSAGE_BYPASS_HARD_DELETE,
    PF_MESSAGE_BYPASS_UPDATE,
    PF_MESSAGE_BYPASS_FORCE_EVICT,
    PF_MESSAGE_BYPASS_EVICT,
    PF_MESSAGE_BYPASS_FLOW_NOT_FOUND,
    PF_MESSAGE_CNT,
};

struct DPDKBypassManagerAssistantData {
    struct rte_ring *results_ring;
    struct rte_mempool *msg_mp;
    struct rte_mempool_cache *msg_mpc;
};

struct DPDKFlowBypassData {
    struct rte_ring *tasks_ring;
    struct rte_mempool *msg_mp;
    struct rte_mempool_cache *msg_mp_cache;
    uint8_t pending_msgs;
};

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_H */
