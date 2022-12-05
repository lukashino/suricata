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

#include "metadata-l3-ipv6.h"

void MetadataIpv6ConvertTo(Address *dst, uint8_t *src) {
    dst->family = AF_INET6;
    dst->family_padding = 0;
    memcpy(&(dst->address.address_un_data8[0]), src, sizeof(uint32_t)*4);
}

int MetadataDecodePacketIPv6(metadata_t *meta_data, uint16_t len) {
    int ret;
    uint16_t ipv6_raw_len = 0;

    if (meta_data->ipv6_hdr->proto == 44) {
        memset(meta_data, 0x00, sizeof(void*) * 4);
        return 0;
    }

    if (unlikely(len < IPV6_HEADER_LEN)) {
        return IPV6_PKT_TOO_SMALL;
    }

    unsigned int version = (meta_data->ipv6_hdr->vtc_flow & 0xf0) >> 4;
    if (unlikely(version != 6)) {
        return IPV6_WRONG_IP_VER;
    }

    ipv6_raw_len = IPV6_HEADER_LEN + rte_be_to_cpu_16(meta_data->ipv6_hdr->payload_len);
    if (unlikely(len < ipv6_raw_len)) {
        return IPV6_TRUNC_PKT;
    }

    MetadataIpv6ConvertTo(&meta_data->src_addr, &meta_data->ipv6_hdr->src_addr[0]);
    MetadataIpv6ConvertTo(&meta_data->dst_addr, &meta_data->ipv6_hdr->dst_addr[0]);

    ret = MetadataDecodePacketL4((uint8_t *)meta_data->ipv6_hdr, meta_data, ipv6_raw_len - IPV6_HEADER_LEN,
            meta_data->ipv6_hdr->proto, IPV6_HEADER_LEN);

    return ret;
}
