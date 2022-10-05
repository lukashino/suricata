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

#define SET_OFFSET(ptr_hdr) \
    if ((ptr_hdr) == NULL) { \
        memset(priv_size + (t<<4), 0x00, sizeof(uint16_t)); \
        continue; \
    } \
    memcpy(priv_size + (t<<4), &offset, sizeof(uint16_t))

#define SET_DATA_TO_PRIV(src, size) do { \
    memcpy(priv_size + (offset<<3), (src), (size)); \
    offset += (size); \
} while(0)

#define METADATA_SET_EVENT(p, e) do { \
    if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)

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

    Address srcA;
    Address dstA;
    uint8_t ip_opt_len;
    IPV4Vars ip_opt_vars;

    Port srcP;
    Port dstP;
    uint8_t proto;
    uint16_t payload_len;
    uint8_t tcp_opt_len;
    TCPVars tcp_opt_vars;

    uint16_t l3_len;
    uint16_t l4_len;

    PacketEngineEvents events;
} metadata_t;

void setIpv4(Address *, uint32_t);
void setIpv6(Address *, uint8_t *);
static inline size_t get_vlan_offset(struct rte_ether_hdr *, uint16_t *);
static int IPV4OptValidateTimestamp(const IPV4Opt *);
static int IPV4OptValidateRoute(const IPV4Opt *);
static int IPV4OptValidateGeneric(const IPV4Opt *);
static int IPV4OptValidateCIPSO(const IPV4Opt *);
int decodeIPV4Options(uint8_t *, uint8_t, metadata_t *);
int decodeTCPOptions(uint8_t *, uint8_t, metadata_t *);
int decodePacketTCP(metadata_t *, uint16_t);
int decodePacketUDP(metadata_t *, uint16_t);
int decodePacketL4(uint8_t, size_t, unsigned char *, metadata_t *, uint16_t);
int decodePacketIPv6(uint16_t, metadata_t *);
int decodePacketIPv4(uint16_t, metadata_t *);
int decodePacketL3(metadata_t *, struct rte_mbuf *);

#endif // METADATA_H