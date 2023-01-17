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

#ifndef SURICATA_METADATA_L3_IPV4_H
#define SURICATA_METADATA_L3_IPV4_H

#include "metadata.h"

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

void MetadataIpv4ConvertTo(Address *, uint32_t);
int MetadataDecodePacketIPv4(metadata_to_suri_t *, metadata_to_suri_help_t *, uint16_t);
static int MetadataDecodeIPV4Options(uint8_t *, metadata_to_suri_t *, uint8_t);
static int MetadataIPV4OptValidateTimestamp(const IPV4Opt *);
static int MetadataIPV4OptValidateRoute(const IPV4Opt *);
static int MetadataIPV4OptValidateGeneric(const IPV4Opt *);
static int MetadataIPV4OptValidateCIPSO(const IPV4Opt *);

#endif // SURICATA_METADATA_L3_IPV4_H
