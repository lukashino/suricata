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
* \author Andrei Shchapaniak <xshcha00@vutbr.cz>
*/

#ifndef METADATA_H
#define METADATA_H

#define PCRE2_CODE_UNIT_WIDTH 8
#include <netinet/in.h>

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-atomic.h"
#include "tm-threads-common.h"
#include "threads.h"
#include "util-device.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-bypass.h"
#include "runmode-dpdk.h"
#include "source-dpdk.h"
#include "decode.h"

/*
 * Get a source pointer, where the value is placed and the size of the value
 * that will be copied.
 */
#define SET_DATA_TO_PRIV(src, size) do { \
    memcpy(priv_size + (offset<<3), (src), (size)); \
    offset += (size); \
} while(0)

/*
 * Set events to the packet
 */
#define METADATA_SET_EVENT(p, e) do { \
    if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)

/*
 * Set TCP options
 */
#define SET_OPTS(dst, src) \
    (dst).type = (src).type; \
    (dst).len  = (src).len; \
    (dst).data = (src).data

// copied from decode-ipv4.c
typedef struct IPV4Options_ {
    IPV4Opt o_rr;
    IPV4Opt o_qs;
    IPV4Opt o_ts;
    IPV4Opt o_sec;
    IPV4Opt o_lsrr;
    IPV4Opt o_cipso;
    IPV4Opt o_sid;
    IPV4Opt o_ssrr;
    IPV4Opt o_rtralt;
} IPV4Options;

typedef struct Metadata {
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;

    Address src_addr;
    Address dst_addr;
    uint8_t ip_opt_len;
    IPV4Vars ip_opt_vars;

    Port src_port;
    Port dst_port;
    uint8_t proto;
    uint16_t payload_len;
    uint8_t tcp_opt_len;
    TCPVars tcp_opt_vars;

    uint16_t l4_len;

    PacketEngineEvents events;
} metadata_t;

static inline size_t MetadataGetVlanOffset(struct rte_ether_hdr *, uint16_t *);
int MetadataDecodePacketL4(uint8_t *, metadata_t *, uint8_t, size_t, uint16_t);
int MetadataDecodePacketL3(struct rte_mbuf *, metadata_t *);

#endif // METADATA_H
