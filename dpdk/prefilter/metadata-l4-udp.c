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
*
 */

#include "metadata-l4-udp.h"

int MetadataDecodePacketUDP(metadata_to_suri_t *metadata_to_suri, metadata_to_suri_help_t *metadata_to_suri_help, uint16_t len) {
    uint16_t udp_raw_len;

    if (unlikely(len < UDP_HEADER_LEN)) {
        return UDP_HLEN_TOO_SMALL;
    }

    udp_raw_len = rte_be_to_cpu_16(metadata_to_suri_help->udp_hdr->dgram_len);
    if (unlikely(len < udp_raw_len)) {
        return UDP_PKT_TOO_SMALL;
    }

    if (unlikely(len != udp_raw_len)) {
        return UDP_HLEN_INVALID;
    }

    metadata_to_suri->metadata_udp.src_port = rte_be_to_cpu_16(metadata_to_suri_help->udp_hdr->src_port);
    metadata_to_suri->metadata_udp.dst_port = rte_be_to_cpu_16(metadata_to_suri_help->udp_hdr->dst_port);
    metadata_to_suri->metadata_udp.payload_len = len - UDP_HEADER_LEN;
    metadata_to_suri->metadata_udp.l4_len = UDP_HEADER_LEN;

    return 0;
}
