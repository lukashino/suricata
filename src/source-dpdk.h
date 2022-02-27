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

#ifndef SURICATA_SOURCE_DPDK_H
#define SURICATA_SOURCE_DPDK_H

#include "suricata-common.h"

#ifdef HAVE_DPDK
#include <rte_ethdev.h>
#endif

#define DPDK_BURST_TX_WAIT_US 1

/* DPDK Flags */
// General flags
#define DPDK_PROMISC   (1 << 0) /**< Promiscuous mode */
#define DPDK_MULTICAST (1 << 1) /**< Enable multicast packets */
#define DPDK_IRQ_MODE  (1 << 2) /**< Interrupt mode */
// Offloads
#define DPDK_RX_CHECKSUM_OFFLOAD (1 << 4) /**< Enable chsum offload */

void DPDKSetTimevalOfMachineStart(void);

typedef struct DPDKWorkerSync_ {
    uint16_t worker_cnt;
    SC_ATOMIC_DECLARE(uint16_t, worker_checked_in);
} DPDKWorkerSync;

/**
 * \brief per packet DPDK vars
 *
 * This structure is used by the release data system and for IPS
 */
typedef struct DPDKPacketVars_ {
    struct rte_mbuf *mbuf;
    uint16_t out_port_id;
    uint16_t out_queue_id;
    uint8_t copy_mode;
    struct rte_ring *tx_ring; // pkt is sent to this ring (same as out_port_*)
} DPDKPacketVars;

void DevicePostStartPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name);
void DevicePreStopPMDSpecificActions(DPDKThreadVars *ptv, const char *driver_name);

void TmModuleReceiveDPDKRegister(void);
void TmModuleDecodeDPDKRegister(void);
void DPDKSetTimevalOfMachineStart(void);

#endif /* SURICATA_SOURCE_DPDK_H */
