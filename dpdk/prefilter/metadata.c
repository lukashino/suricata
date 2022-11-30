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

#include "metadata.h"

void MetadataIpv4ConvertTo(Address *dst, uint32_t src) {
    dst->family = AF_INET;
    dst->family_padding = 0;
    memcpy(&(dst->address.address_un_data32[0]), &src, sizeof(uint32_t));
    memset(&(dst->address.address_un_data32[1]), 0x00, sizeof(uint32_t)*3);
}

void MetadataIpv6ConvertTo(Address *dst, uint8_t *src) {
    dst->family = AF_INET6;
    dst->family_padding = 0;
    memcpy(&(dst->address.address_un_data8[0]), src, sizeof(uint32_t)*4);
}

static inline size_t GetVlanOffset(struct rte_ether_hdr *eth_hdr, uint16_t *proto)
{
    size_t vlan_offset = 0;
    if (rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) == *proto) {
        struct rte_vlan_hdr *vlan_hdr = (struct rte_vlan_hdr *)(eth_hdr + 1);
        vlan_offset = sizeof(struct rte_vlan_hdr);
        *proto = rte_be_to_cpu_16(vlan_hdr->eth_proto);
        if (rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) == *proto) {
            vlan_hdr = vlan_hdr + 1;
            *proto = vlan_hdr->eth_proto;
            vlan_offset += sizeof(struct rte_vlan_hdr);
        }
    }
    return vlan_offset;
}

static int IPV4OptValidateTimestamp(const IPV4Opt *o)
{
    uint8_t ptr;
    uint8_t flag;
    uint8_t rec_size;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_TS_MIN))
        return IPV4_OPT_INVALID_LEN; // ENGINE_SET_INVALID_EVENT

    /* Data is required */
    if (unlikely(o->data == NULL))
        return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

    ptr = *o->data;

    /* We need the flag to determine what is in the option payload */
    if (unlikely(ptr < 5))
        return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

    flag = *(o->data + 1) & 0x0f;

    /* A flag of 1|3 means we have both the ip+ts in each record */
    rec_size = ((flag == 1) || (flag == 3)) ? 8 : 4;

    /* Address pointer is 1 based and points at least after
     * type+len+ptr+ovfl+flag, must be incremented by by the rec_size
     * and cannot extend past option length.
     */
    if (unlikely(((ptr - 5) % rec_size) || (ptr > o->len + 1)))
        return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

    return 0;
}

static int IPV4OptValidateRoute(const IPV4Opt *o)
{
    uint8_t ptr;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_ROUTE_MIN))
        return IPV4_OPT_INVALID_LEN;

    /* Data is required */
    if (unlikely(o->data == NULL))
        return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

    ptr = *o->data;

    /* Address pointer is 1 based and points at least after type+len+ptr,
     * must be a incremented by 4 bytes (address size) and cannot extend
     * past option length.
     */
    if (unlikely((ptr < 4) || (ptr % 4) || (ptr > o->len + 1)))
        return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

    return 0;
}

static int IPV4OptValidateGeneric(const IPV4Opt *o)
{
    switch (o->type) {
        /* See: RFC 4782 */
        case IPV4_OPT_QS:
            if (o->len < IPV4_OPT_QS_MIN)
                return IPV4_OPT_INVALID_LEN; // ENGINE_SET_INVALID_EVENT

            break;
        /* See: RFC 1108 */
        case IPV4_OPT_SEC: case IPV4_OPT_SID:
            if (o->len != IPV4_OPT_SEC_LEN)
                return IPV4_OPT_INVALID_LEN; // ENGINE_SET_INVALID_EVENT

            break;
        /* See: RFC 2113 */
        case IPV4_OPT_RTRALT:
            if (o->len != IPV4_OPT_RTRALT_LEN)
                return IPV4_OPT_INVALID_LEN; // ENGINE_SET_INVALID_EVENT

            break;
        default:
            /* Should never get here unless there is a coding error */
            return IPV4_OPT_UNKNOWN; // ENGINE_SET_INVALID_EVENT
    }

    return 0;
}

static int IPV4OptValidateCIPSO(const IPV4Opt *o)
{
    //    uint32_t doi;
    const uint8_t *tag;
    uint16_t len;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_CIPSO_MIN))
        return IPV4_OPT_INVALID_LEN; // ENGINE_SET_INVALID_EVENT

    /* Data is required */
    if (unlikely(o->data == NULL))
        return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

    //    doi = *o->data;
    tag = o->data + 4;
    len = o->len - 1 - 1 - 4; /* Length of tags after header */

    /* NOTE: We know len has passed min tests prior to this call */

    /* Check that tags are formatted correctly
     * [-ttype--][--tlen--][-tagdata-...]
     */
    while (len) {
        uint8_t ttype;
        uint8_t tlen;

        /* Tag header must fit within option length */
        if (unlikely(len < 2))
            return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

        /* Tag header is type+len */
        ttype = *(tag++);
        tlen = *(tag++);

        /* Tag length must fit within the option length */
        if (unlikely(tlen > len))
            return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

        switch(ttype) {
            case 1:
            case 2:
            case 5:
            case 6:
            case 7:
                /* Tag is at least 4 and at most the remainder of option len */
                if (unlikely((tlen < 4) || (tlen > len)))
                    return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

                /* The alignment octet is always 0 except tag
                 * type 7, which has no such field.
                 */
                if (unlikely((ttype != 7) && (*tag != 0)))
                    return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT

                /* Skip the rest of the tag payload */
                tag += tlen - 2;
                len -= tlen;

                continue;
            case 0:
                /* Tag type 0 is reserved and thus invalid */
                /** \todo Wireshark marks this a padding, but spec says reserved. */
                return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT
            default:
                /** \todo May not want to return error here on unknown tag type (at least not for 3|4) */
                return IPV4_OPT_MALFORMED; // ENGINE_SET_INVALID_EVENT
        }
    }

    return 0;
}

int DecodeIPV4Options(uint8_t *pkt, uint8_t opt_len, metadata_t *meta_data) {
    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));

    if (opt_len % 8)
        METADATA_SET_EVENT(meta_data, IPV4_OPT_PAD_REQUIRED);

    while (opt_len)
    {
        meta_data->ip_opt_vars.opt_cnt++;

        /* single byte options */
        if (*pkt == IPV4_OPT_EOL) {
            /** \todo What if more data exist after EOL (possible covert channel or data leakage)? */
            SCLogDebug("IPV4OPT %" PRIu8 " len 1 @ %d/%d",
                    *pkt, (len - plen), (len - 1));
            meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_EOL;
            break;
        } else if (*pkt == IPV4_OPT_NOP) {
            SCLogDebug("IPV4OPT %" PRIu8 " len 1 @ %d/%d",
                    *pkt, (len - plen), (len - 1));
            pkt++;
            opt_len--;

            meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_NOP;

            /* multibyte options */
        } else {
            if (unlikely(opt_len < 2)) {
                /** \todo What if padding is non-zero (possible covert channel or data leakage)? */
                /** \todo Spec seems to indicate EOL required if there is padding */
                METADATA_SET_EVENT(meta_data, IPV4_OPT_EOL_REQUIRED);
                break;
            }

            /* Option length is too big for packet */
            if (unlikely(*(pkt+1) > opt_len)) {
                return IPV4_OPT_INVALID_LEN;
            }

            IPV4Opt opt = {*pkt, *(pkt+1), opt_len > 2 ? (pkt + 2) : NULL };

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(opt.len > opt_len || opt.len < 2)) {
                return IPV4_OPT_INVALID_LEN;
            }
            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            /** \todo Figure out which IP options are more common and list them first */
            switch (opt.type) {
                case IPV4_OPT_TS:
                    if (opts.o_ts.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateTimestamp(&opt) == 0) {
                        opts.o_ts = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_TS;
                    }
                    break;
                case IPV4_OPT_RR:
                    if (opts.o_rr.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(&opt) == 0) {
                        opts.o_rr = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_RR;
                    }
                    break;
                case IPV4_OPT_QS:
                    if (opts.o_qs.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(&opt) == 0) {
                        opts.o_qs = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_QS;
                    }
                    break;
                case IPV4_OPT_SEC:
                    if (opts.o_sec.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(&opt) == 0) {
                        opts.o_sec = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_SEC;
                    }
                    break;
                case IPV4_OPT_LSRR:
                    if (opts.o_lsrr.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(&opt) == 0) {
                        opts.o_lsrr = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_LSRR;
                    }
                    break;
                case IPV4_OPT_CIPSO:
                    if (opts.o_cipso.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateCIPSO(&opt) == 0) {
                        opts.o_cipso = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_CIPSO;
                    }
                    break;
                case IPV4_OPT_SID:
                    if (opts.o_sid.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(&opt) == 0) {
                        opts.o_sid = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_SID;
                    }
                    break;
                case IPV4_OPT_SSRR:
                    if (opts.o_ssrr.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(&opt) == 0) {
                        opts.o_ssrr = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_SSRR;
                    }
                    break;
                case IPV4_OPT_RTRALT:
                    if (opts.o_rtralt.type != 0) {
                        METADATA_SET_EVENT(meta_data, IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(&opt) == 0) {
                        opts.o_rtralt = opt;
                        meta_data->ip_opt_vars.opts_set |= IPV4_OPT_FLAG_RTRALT;
                    }
                    break;
                default:
                    SCLogDebug("IPV4OPT <unknown> (%" PRIu8 ") len %" PRIu8,
                            opt.type, opt.len);
                    METADATA_SET_EVENT(meta_data, IPV4_OPT_INVALID);
                    /* Warn - we can keep going */
                    break;
            }

            pkt += opt.len;
            opt_len -= opt.len;
        }
    }

    return 0;
}

int DecodeTCPOptions(uint8_t *pkt, uint8_t opt_len, metadata_t *meta_data)
{
    uint8_t tcp_opt_cnt = 0;
    TCPOpt tcp_opts[TCP_OPTMAX];

    uint16_t plen = opt_len;
    while (plen)
    {
        const uint8_t type = *pkt;

        /* single byte options */
        if (type == TCP_OPT_EOL) {
            break;
        } else if (type == TCP_OPT_NOP) {
            pkt++;
            plen--;

            /* multibyte options */
        } else {
            if (plen < 2) {
                break;
            }

            const uint8_t olen = *(pkt+1);

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(olen > plen || olen < 2)) {
                return TCP_OPT_INVALID_LEN;
            }

            tcp_opts[tcp_opt_cnt].type = type;
            tcp_opts[tcp_opt_cnt].len  = olen;
            tcp_opts[tcp_opt_cnt].data = (olen > 2) ? (pkt+2) : NULL;

            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            switch (type) {
                case TCP_OPT_WS:
                    if (olen != TCP_OPT_WS_LEN) {
                        METADATA_SET_EVENT(meta_data ,TCP_OPT_INVALID_LEN);
                    } else {
                        if (meta_data->tcp_opt_vars.ws.type != 0) {
                            METADATA_SET_EVENT(meta_data, TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(meta_data->tcp_opt_vars.ws, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_MSS:
                    if (olen != TCP_OPT_MSS_LEN) {
                        METADATA_SET_EVENT(meta_data ,TCP_OPT_INVALID_LEN);
                    } else {
                        if (meta_data->tcp_opt_vars.mss.type != 0) {
                            METADATA_SET_EVENT(meta_data ,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(meta_data->tcp_opt_vars.mss, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_SACKOK:
                    if (olen != TCP_OPT_SACKOK_LEN) {
                        METADATA_SET_EVENT(meta_data ,TCP_OPT_INVALID_LEN);
                    } else {
                        if (meta_data->tcp_opt_vars.sackok.type != 0) {
                            METADATA_SET_EVENT(meta_data ,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(meta_data->tcp_opt_vars.sackok, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_TS:
                    if (olen != TCP_OPT_TS_LEN) {
                        METADATA_SET_EVENT(meta_data ,TCP_OPT_INVALID_LEN);
                    } else {
                        if (meta_data->tcp_opt_vars.ts_set) {
                            METADATA_SET_EVENT(meta_data ,TCP_OPT_DUPLICATE);
                        } else {
                            uint32_t values[2];
                            memcpy(&values, tcp_opts[tcp_opt_cnt].data, sizeof(values));
                            meta_data->tcp_opt_vars.ts_val = SCNtohl(values[0]);
                            meta_data->tcp_opt_vars.ts_ecr = SCNtohl(values[1]);
                            meta_data->tcp_opt_vars.ts_set = true;
                        }
                    }
                    break;
                case TCP_OPT_SACK:
                    SCLogDebug("SACK option, len %u", olen);
                    if ((olen != 2) &&
                            (olen < TCP_OPT_SACK_MIN_LEN ||
                                    olen > TCP_OPT_SACK_MAX_LEN ||
                                    !((olen - 2) % 8 == 0)))
                    {
                        METADATA_SET_EVENT(meta_data ,TCP_OPT_INVALID_LEN);
                    } else {
                        if (meta_data->tcp_opt_vars.sack.type != 0) {
                            METADATA_SET_EVENT(meta_data ,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(meta_data->tcp_opt_vars.sack, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_TFO:
                    SCLogDebug("TFO option, len %u", olen);
                    if ((olen != 2) && (olen < TCP_OPT_TFO_MIN_LEN || olen > TCP_OPT_TFO_MAX_LEN ||
                                               !(((olen - 2) & 0x1) == 0))) {
                        METADATA_SET_EVENT(meta_data ,TCP_OPT_INVALID_LEN);
                    } else {
                        if (meta_data->tcp_opt_vars.tfo.type != 0) {
                            METADATA_SET_EVENT(meta_data ,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(meta_data->tcp_opt_vars.tfo, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                /* experimental options, could be TFO */
                case TCP_OPT_EXP1:
                case TCP_OPT_EXP2:
                    SCLogDebug("TCP EXP option, len %u", olen);
                    if (olen == 4 || olen == 12) {
                        uint16_t magic = SCNtohs(*(uint16_t *)tcp_opts[tcp_opt_cnt].data);
                        if (magic == 0xf989) {
                            if (meta_data->tcp_opt_vars.tfo.type != 0) {
                                METADATA_SET_EVENT(meta_data ,TCP_OPT_DUPLICATE);
                            } else {
                                SET_OPTS(meta_data->tcp_opt_vars.tfo, tcp_opts[tcp_opt_cnt]);
                                meta_data->tcp_opt_vars.tfo.type = TCP_OPT_TFO; // treat as regular TFO
                            }
                        }
                    } else {
                        METADATA_SET_EVENT(meta_data ,TCP_OPT_INVALID_LEN);
                    }
                    break;
                /* RFC 2385 MD5 option */
                case TCP_OPT_MD5:
                    SCLogDebug("MD5 option, len %u", olen);
                    if (olen != 18) {
                        return TCP_OPT_INVALID_LEN; // ENGINE SET INVALID EVENT
                    } else {
                        /* we can't validate the option as the key is out of band */
                        meta_data->tcp_opt_vars.md5_option_present = true;
                    }
                    break;
                /* RFC 5925 AO option */
                case TCP_OPT_AO:
                    SCLogDebug("AU option, len %u", olen);
                    if (olen < 4) {
                        return TCP_OPT_INVALID_LEN; // ENGINE SET INVALID EVENT
                    } else {
                        /* we can't validate the option as the key is out of band */
                        meta_data->tcp_opt_vars.ao_option_present = true;
                    }
                    break;
            }

            pkt += olen;
            plen -= olen;
            tcp_opt_cnt++;
        }
    }

    return 0;
}

int DecodePacketTCP(metadata_t *meta_data, uint16_t len) {
    uint16_t tcp_len;
    int ret;

    if (unlikely(len < TCP_HEADER_LEN)) {
        return TCP_PKT_TOO_SMALL;
    }

    tcp_len = (meta_data->tcp_hdr->data_off & 0xf0) >> 2;
    if (unlikely(len < tcp_len)) {
        return TCP_HLEN_TOO_SMALL;
    }

    meta_data->tcp_opt_len = tcp_len - TCP_HEADER_LEN;
    if (unlikely(meta_data->tcp_opt_len > TCP_OPTLENMAX)) {
        return TCP_INVALID_OPTLEN;
    }

    if (meta_data->tcp_opt_len > 0) {
        ret = DecodeTCPOptions((uint8_t *)meta_data->tcp_hdr + TCP_HEADER_LEN, meta_data->tcp_opt_len, meta_data);
        if (ret != 0) {
            return ret;
        }
    }

    meta_data->src_port = rte_be_to_cpu_16(meta_data->tcp_hdr->src_port);
    meta_data->dst_port = rte_be_to_cpu_16(meta_data->tcp_hdr->dst_port);
    meta_data->payload_len = len - tcp_len;
    meta_data->l4_len = tcp_len;

    return 0;
}

int DecodePacketUDP(metadata_t *meta_data, uint16_t len) {
    uint16_t udp_raw_len;

    if (unlikely(len < UDP_HEADER_LEN)) {
        return UDP_HLEN_TOO_SMALL;
    }

    udp_raw_len = rte_be_to_cpu_16(meta_data->udp_hdr->dgram_len);
    if (unlikely(len < udp_raw_len)) {
        return UDP_PKT_TOO_SMALL;
    }

    if (unlikely(len != udp_raw_len)) {
        return UDP_HLEN_INVALID;
    }

    meta_data->src_port = rte_be_to_cpu_16(meta_data->udp_hdr->src_port);
    meta_data->dst_port = rte_be_to_cpu_16(meta_data->udp_hdr->dst_port);
    meta_data->payload_len = len - UDP_HEADER_LEN;
    meta_data->l4_len = UDP_HEADER_LEN;

    return 0;
}

int DecodePacketL4(uint8_t proto, size_t size, unsigned char *ptr, metadata_t *meta_data, uint16_t len)
{
    int ret = 0;
    meta_data->proto = proto;

    if (proto == IPPROTO_TCP) {
        meta_data->tcp_hdr = (struct rte_tcp_hdr *)(ptr + size);
        ret = DecodePacketTCP(meta_data, len);
    } else if (proto == IPPROTO_UDP) {
        meta_data->udp_hdr = (struct rte_udp_hdr *)(ptr + size);
        ret = DecodePacketUDP(meta_data, len);
    }

    return ret;
}

int DecodePacketIPv4(metadata_t *meta_data, uint16_t len) {
    int ret;
    int ipv4_len, ipv4_raw_len;

    int fo = rte_be_to_cpu_16(meta_data->ipv4_hdr->fragment_offset) & 0x1fff;
    int mf = rte_be_to_cpu_16(meta_data->ipv4_hdr->fragment_offset) & 0x2000;

    if (fo > 0 || mf >> 13) {
        memset(meta_data, 0x00, sizeof(void*) * 4);
        return 0;
    }

    if (unlikely(len < IPV4_HEADER_LEN)) {
        return IPV4_PKT_TOO_SMALL;
    }

    if (unlikely(meta_data->ipv4_hdr->version != 4)) {
        return IPV4_WRONG_IP_VER;
    }

    ipv4_len = rte_ipv4_hdr_len(meta_data->ipv4_hdr);
    if (unlikely(ipv4_len < IPV4_HEADER_LEN)) {
        return IPV4_HLEN_TOO_SMALL;
    }

    ipv4_raw_len = rte_be_to_cpu_16(meta_data->ipv4_hdr->total_length);
    if (unlikely(ipv4_raw_len < ipv4_len)) {
        return IPV4_IPLEN_SMALLER_THAN_HLEN;
    }

    if (unlikely(len < ipv4_raw_len)) {
        return IPV4_TRUNC_PKT;
    }

    MetadataIpv4ConvertTo(&meta_data->src_addr, meta_data->ipv4_hdr->src_addr);
    MetadataIpv4ConvertTo(&meta_data->dst_addr, meta_data->ipv4_hdr->dst_addr);

    meta_data->ip_opt_len = ipv4_len - IPV4_HEADER_LEN;
    if (meta_data->ip_opt_len > 0) {
        ret = DecodeIPV4Options((uint8_t *)meta_data->ipv4_hdr + IPV4_HEADER_LEN,meta_data->ip_opt_len, meta_data);
        if (ret != 0) {
            return ret;
        }
    }

    ret = DecodePacketL4(meta_data->ipv4_hdr->next_proto_id, ipv4_len,
            (unsigned char *)meta_data->ipv4_hdr, meta_data, ipv4_raw_len - ipv4_len);

    return ret;
}

int DecodePacketIPv6(metadata_t *meta_data, uint16_t len) {
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

    ret = DecodePacketL4(meta_data->ipv6_hdr->proto, IPV6_HEADER_LEN,
            (unsigned char *)meta_data->ipv6_hdr, meta_data, ipv6_raw_len - IPV6_HEADER_LEN);

    return ret;
}

int DecodePacketL3(metadata_t *meta_data, struct rte_mbuf *pkt)
{
    struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type;
    size_t offset;
    int ret = 0;

    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ether_type = eth_hdr->ether_type;
    offset = GetVlanOffset(eth_hdr, &ether_type); // TODO INTERESTING change in if condition translation from cpu to be

    if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        meta_data->ipv4_hdr = (struct rte_ipv4_hdr *)((char *)(eth_hdr + 1) + offset);
        ret = DecodePacketIPv4(meta_data, pkt->pkt_len - ETHERNET_HEADER_LEN);
    } else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
        meta_data->ipv6_hdr = (struct rte_ipv6_hdr *)((char *)(eth_hdr + 1) + offset);
        ret = DecodePacketIPv6(meta_data, pkt->pkt_len - ETHERNET_HEADER_LEN);
    }

    return ret;
}
