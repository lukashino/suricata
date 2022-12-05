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
#include "metadata-l4-tcp.h"

static int MetadataDecodeTCPOptions(uint8_t *pkt, uint8_t opt_len, metadata_t *meta_data) {
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

int MetadataDecodePacketTCP(metadata_t *meta_data, uint16_t len) {
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
        ret = MetadataDecodeTCPOptions((uint8_t *)meta_data->tcp_hdr + TCP_HEADER_LEN, meta_data->tcp_opt_len, meta_data);
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
