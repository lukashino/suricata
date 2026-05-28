#!/usr/bin/env python3
"""Parse the portable results-format from a PCAP and report per-packet pids.

Layout (little-endian, host-independent):
  Bytes 0..11 of each frame = 6 x uint16_t slots overlaying dst+src MAC.
  Each slot:
    bit15 = PAYLOAD_FN
    bit14 = TOSERVER
    low 14 bits = pid (0..16383)
  All slots 0xFFFF (i.e. all 12 bytes 0xFF) = overflow sentinel.
  Slot value 0x0000 = empty slot.
"""
import struct
import sys

from scapy.all import rdpcap

OVERFLOW_SENTINEL = b"\xff" * 12

def decode_slot(slot: int):
    payload_fn = bool(slot & 0x8000)
    toserver = bool(slot & 0x4000)
    pid = slot & 0x3FFF
    return pid, toserver, payload_fn

def main(path: str) -> int:
    packets = rdpcap(path)
    for idx, pkt in enumerate(packets):
        raw = bytes(pkt)[:12]
        if raw == OVERFLOW_SENTINEL:
            print(f"pkt {idx}: OVERFLOW")
            continue
        slots = struct.unpack("<6H", raw)
        entries = []
        for s in slots:
            if s == 0x0000:
                continue
            pid, toserver, payload_fn = decode_slot(s)
            entries.append(f"pid={pid} ts={int(toserver)} pl={int(payload_fn)}")
        print(f"pkt {idx}: {', '.join(entries) if entries else 'empty'}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
