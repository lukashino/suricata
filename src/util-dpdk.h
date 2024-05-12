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
#ifdef HAVE_DPDK_BOND
#include <rte_eth_bond.h>
#endif
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_flow.h>
#include <rte_version.h>
#include <rte_hash.h>
#include <rte_tcp.h>

#include "util-device.h"
#include "util-atomic.h"
#include "decode.h"
#include "tm-threads.h"

#define PREFILTER_CONF_MEMZONE_NAME "prefilter_conf"
#define BURST_SIZE                  32
#define RSS_HKEY_LEN 40

#if RTE_VERSION < RTE_VERSION_NUM(22, 0, 0, 0)
#define RTE_ETH_MQ_RX_RSS ETH_MQ_RX_RSS
#endif

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
#define RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE DEV_TX_OFFLOAD_MBUF_FAST_FREE

#define RTE_ETH_RX_OFFLOAD_CHECKSUM DEV_RX_OFFLOAD_CHECKSUM

#define RTE_ETH_RX_OFFLOAD_VLAN_STRIP       DEV_RX_OFFLOAD_VLAN_STRIP
#define RTE_ETH_RX_OFFLOAD_IPV4_CKSUM       DEV_RX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_RX_OFFLOAD_UDP_CKSUM        DEV_RX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_RX_OFFLOAD_TCP_CKSUM        DEV_RX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_RX_OFFLOAD_TCP_LRO          DEV_RX_OFFLOAD_TCP_LRO
#define RTE_ETH_RX_OFFLOAD_QINQ_STRIP       DEV_RX_OFFLOAD_QINQ_STRIP
#define RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM
#define RTE_ETH_RX_OFFLOAD_MACSEC_STRIP     DEV_RX_OFFLOAD_MACSEC_STRIP
#define RTE_ETH_RX_OFFLOAD_HEADER_SPLIT     DEV_RX_OFFLOAD_HEADER_SPLIT
#define RTE_ETH_RX_OFFLOAD_VLAN_FILTER      DEV_RX_OFFLOAD_VLAN_FILTER
#define RTE_ETH_RX_OFFLOAD_VLAN_EXTEND      DEV_RX_OFFLOAD_VLAN_EXTEND
#define RTE_ETH_RX_OFFLOAD_SCATTER          DEV_RX_OFFLOAD_SCATTER
#define RTE_ETH_RX_OFFLOAD_TIMESTAMP        DEV_RX_OFFLOAD_TIMESTAMP
#define RTE_ETH_RX_OFFLOAD_SECURITY         DEV_RX_OFFLOAD_SECURITY
#define RTE_ETH_RX_OFFLOAD_KEEP_CRC         DEV_RX_OFFLOAD_KEEP_CRC
#define RTE_ETH_RX_OFFLOAD_SCTP_CKSUM       DEV_RX_OFFLOAD_SCTP_CKSUM
#define RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM  DEV_RX_OFFLOAD_OUTER_UDP_CKSUM
#define RTE_ETH_RX_OFFLOAD_RSS_HASH DEV_RX_OFFLOAD_RSS_HASH
#define RTE_MBUF_F_FIRST_FREE               PKT_FIRST_FREE

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
    int32_t socket_id;
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
    SC_ATOMIC_DECLARE(uint16_t, inconsistent_numa_cnt);
    DPDKWorkerSync *workers_sync;
    void (*DerefFunc)(void *);

    struct rte_flow *flow[100];
#endif
} DPDKIfaceConfig;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct DPDKThreadVars_ {
    /* counters */
    uint64_t pkts;
    ThreadVars *tv;
    TmSlot *slot;
    LiveDevice *livedev;
    ChecksumValidationMode checksum_mode;
    bool intr_enabled;
    /* references to packet and drop counters */
    uint16_t capture_dpdk_packets;
    uint16_t capture_dpdk_rx_errs;
    uint16_t capture_dpdk_imissed;
    uint16_t capture_dpdk_rx_no_mbufs;
    uint16_t capture_dpdk_ierrors;
    uint16_t capture_dpdk_tx_errs;
    unsigned int flags;
    int threads;
    /* for IPS */
    DpdkCopyModeEnum copy_mode;
    uint16_t out_port_id;
    /* Entry in the peers_list */

    uint64_t bytes;
    uint64_t accepted;
    uint64_t dropped;
    uint16_t port_id;
    uint16_t queue_id;
    int32_t port_socket_id;
    struct rte_mbuf *received_mbufs[BURST_SIZE];
    DpdkOperationMode op_mode;
    union {
        struct rte_mempool *pkt_mempool;
        struct {
            struct rte_ring *rx_ring;
            struct rte_ring *tx_ring;
            struct rte_ring *tasks_ring;
            struct rte_ring *results_ring;
            struct rte_mempool *msg_mp;
        } rings;
    };
    DPDKWorkerSync *workers_sync;
} DPDKThreadVars;

uint32_t ArrayMaxValue(const uint32_t *arr, uint16_t arr_len);
uint8_t CountDigits(uint32_t n);
void DPDKCleanupEAL(void);

void DPDKCloseDevice(LiveDevice *ldev);
void DPDKFreeDevice(LiveDevice *ldev);

#ifdef HAVE_DPDK
const char *DPDKGetPortNameByPortID(uint16_t pid);
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

void DPDKCloseDevice(LiveDevice *ldev);
void DevicePostStartPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name);
void DevicePreStopPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_H */
