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

static inline size_t MetadataGetVlanOffset(struct rte_ether_hdr *, uint16_t *);
int MetadataDecodePacketL4(uint8_t *, metadata_to_suri_t *, metadata_to_suri_help_t *, uint8_t, size_t, uint16_t);
int MetadataDecodePacketL3(struct rte_mbuf *, metadata_to_suri_t *, metadata_to_suri_help_t *);

#endif // METADATA_H
