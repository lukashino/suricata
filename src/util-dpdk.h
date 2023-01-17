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

/* Offloads flags */
enum ofldsIdxsPf {
    IPV4_ID,
    IPV6_ID,
    TCP_ID,
    UDP_ID
};

enum ofldsIdxsSur {
    MATCH_RULES
};

#define IPV4_OFFLOAD(val) ((val) << IPV4_ID)
#define IPV6_OFFLOAD(val) ((val) << IPV6_ID)
#define TCP_OFFLOAD(val) ((val) << TCP_ID)
#define UDP_OFFLOAD(val) ((val) << UDP_ID)

#define MATCH_RULES_OFFLOAD(val) ((val) << MATCH_RULES)

#define CNT_METADATA_TO_SURI 4
#define CNT_METADATA_FROM_SURI 1

typedef struct MetadataRules {
    size_t cnt;
    uint32_t rules[32]; // change then
} metadata_rules_t;

typedef struct MetadataFromSuri {
    bool set_metadata[CNT_METADATA_FROM_SURI];
    metadata_rules_t rules_metadata;
} metadata_from_suri_t;

typedef struct MetadataIpv4 {
    Address src_addr;
    Address dst_addr;
    PacketEngineEvents events;
} metadata_ipv4_t;

typedef struct MetadataIpv6 {
    Address src_addr;
    Address dst_addr;
} metadata_ipv6_t;

typedef struct MetadataTcp {
    Port src_port;
    Port dst_port;
    uint16_t payload_len;
    uint16_t l4_len;
    PacketEngineEvents events;
} metadata_tcp_t;

typedef struct MetadataUdp {
    Port src_port;
    Port dst_port;
    uint16_t payload_len;
    uint16_t l4_len;
} metadata_udp_t;

typedef struct MetadataToSuri {
    bool set_metadata[CNT_METADATA_TO_SURI]; // 4 - MAX pocet metadat, ukazuji na zacatek jednotlivych metadat
    metadata_ipv4_t metadata_ipv4;
    metadata_ipv6_t metadata_ipv6;
    metadata_tcp_t metadata_tcp;
    metadata_udp_t metadata_udp;
} metadata_to_suri_t;

typedef struct MetadataToSuriHelp {
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
} metadata_to_suri_help_t;

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
    uint16_t *cnt_offlds_suri_requested;
    uint16_t (*idxes_offlds_suri_requested)[16];
    uint16_t oflds_suri_requested;
    uint16_t cnt_offlds_suri_support;
    uint16_t idxes_offlds_suri_support[16];
    uint16_t oflds_suri_support;
    /* End of ring mode settings */
    /* IPS mode */
    DpdkCopyModeEnum copy_mode;
    const char *out_iface;
    uint16_t out_port_id;
    /* DPDK flags */
    uint32_t flags;
    ChecksumValidationMode checksum_mode;
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
    uint16_t oflds_pf_support;
    uint16_t oflds_suri_requested;
    uint16_t oflds_final_IDS;
    uint16_t oflds_pf_requested;
    uint16_t oflds_final_IPS;
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
