# Design: `detect.results-format` — portable vs extended MPM-result packet embedding

Date: 2026-05-28
Branch: `fpga-patternmatch-prefilter-save-pcaps`
Author: Lukas Sismis (with Claude)

## Problem

The branch currently embeds matched MPM pattern IDs into outgoing packets using
an **extended** format: a variable-length header is prepended before the
Ethernet frame (`RESERVED(0xff) | PATIDs_LEN(2B) | PATID_SIZE(1B) | [pid u32]...`).
This carries up to 64 pids with a full 30-bit pid space but **changes the
on-wire packet layout**, breaking downstream systems that perform standard
packet parsing.

For the port to a deployment where external packet parsing is a critical
feature, we need to additionally support a **portable** format that overwrites
only the 12-byte MAC area (dst+src), preserving every other byte of the packet.
Pids must therefore downscale from `uint32_t` to `uint16_t`.

Both formats must be selectable at runtime via configuration.

## Goals

1. Add a **required** YAML key `detect.results-format` with values `portable`
   or `extended`. Missing/invalid → fail-loud at startup.
2. Implement `portable` writer: 6 × `uint16_t` slots overwriting the 12-byte
   MAC area, no header bytes, packet layout otherwise byte-identical to input.
3. Preserve per-pid direction/origin bits (`PAYLOAD_FN`, `TOSERVER`) in both
   formats — in portable, packed into the top 2 bits of each `uint16_t`.
4. Fail-loud at startup on any condition that would make portable mode produce
   a wrong result: pid space too large for 14 bits, or `max-mpm-pattern-ids > 6`.
5. Keep the existing extended format working unchanged for users that want
   maximum pid count / id range.

## Non-goals

- Changing the internal `Packet::matched_pids` representation or the MPM
  callback / payload writer paths. Format conversion happens **only** at the
  packet-release boundary.
- Supporting more than one format simultaneously per Suricata process. The
  format is a global protocol choice.
- Making `pid == 0` distinguishable from "empty slot" in portable mode. This
  collision is inherited from the original `159eb2153` design and is acceptable
  here; rules whose fast-pattern id happens to be 0 will simply look empty in
  that slot.

## Configuration

In `suricata.yaml.in`, under `detect:`:

```yaml
detect:
  # Format used to embed MPM pattern-match results into outgoing packets.
  #
  #   portable: 6 uint16_t pattern IDs overwrite the 12-byte src+dst MAC
  #             area. No header bytes are added; packet layout is preserved
  #             so external parsers continue to see normal Ethernet/IP/...
  #             Per-pid bits: bit15=PAYLOAD_FN, bit14=TOSERVER,
  #             low 14 bits = pid (max id 16383, max 6 pids per packet).
  #             Overflow (count>6 OR pid>=2^14) -> all 12 MAC bytes
  #             set to 0xFF as overflow sentinel.
  #
  #   extended: variable-length header prepended to the packet
  #             (RESERVED(0xff)/LEN(2B)/SIZE(1B)/[pid u32]...). Carries up to
  #             max-mpm-pattern-ids pids with full 30-bit space, but
  #             changes the on-wire packet layout.
  #
  # REQUIRED key -- there is no safe default.
  results-format: portable    # or "extended"
```

`max-mpm-pattern-ids` (per-DPDK-iface) keeps its current meaning for
`extended`. In `portable`, values > 6 are rejected at startup.

## Internal storage (unchanged)

- `Packet::matched_pids[MATCHED_PIDS_ARR_LEN_THRESH]` remains `uint32_t[64]`.
- `src/detect-engine-payload.c` write paths and `src/util-mpm-hs.c` Hyperscan
  callback remain unchanged — they continue to pack `PREFILTER_PKT_PAYLOAD_FN`
  / `PREFILTER_PKT_TOSERVER_DIR` into the top bits of `uint32_t`.
- The MPM-side overflow sentinel (`matched_pids[0] == UINT32_MAX`) is preserved.

This keeps the format decision a thin shim at the output stage.

## Output stage

New globals in `src/source-dpdk.c`:

```c
typedef enum {
    RESULTS_FORMAT_PORTABLE = 0,
    RESULTS_FORMAT_EXTENDED = 1,
} ResultsFormat;

extern ResultsFormat g_results_format;
```

`DPDKReleasePacket` dispatches once:

```c
if (g_results_format == RESULTS_FORMAT_PORTABLE) {
    WritePortablePids(p);
} else {
    WriteExtendedPids(p);   /* today's rte_pktmbuf_prepend(...) logic, moved */
}
```

### `WritePortablePids` (new)

```c
static void WritePortablePids(Packet *p)
{
    uint8_t *mac_area = rte_pktmbuf_mtod(p->dpdk_v.mbuf, uint8_t *);
    /* dst MAC (6B) + src MAC (6B) = 12B starting at offset 0 */
    memset(mac_area, 0, 12);

    bool overflow = (p->matched_pids_cnt > 6) ||
                    (p->matched_pids[0] == UINT32_MAX);
    if (!overflow) {
        for (uint32_t i = 0; i < p->matched_pids_cnt; i++) {
            uint32_t pid = p->matched_pids[i] & PREFILTER_FLAGS_SPACE;
            if (pid >= (1u << 14)) { overflow = true; break; }
        }
    }
    if (overflow) {
        memset(mac_area, 0xff, 12);   /* sentinel: all 12 MAC bytes = 0xFF */
        return;
    }

    uint16_t *slots = (uint16_t *)mac_area;   /* 6 slots */
    for (uint32_t i = 0; i < p->matched_pids_cnt; i++) {
        uint32_t v = p->matched_pids[i];
        uint16_t pid14 = (uint16_t)(v & 0x3FFF);
        uint16_t flags = 0;
        if (v & PREFILTER_PKT_PAYLOAD_FN)   flags |= 0x8000; /* bit15 */
        if (v & PREFILTER_PKT_TOSERVER_DIR) flags |= 0x4000; /* bit14 */
        slots[i] = pid14 | flags;
    }
    /* trailing slots already zero from memset; pid==0 + flags==0 = empty */
}
```

### `WriteExtendedPids` (refactored from today's code)

Verbatim move of the current `rte_pktmbuf_prepend(...)` block from
`DPDKReleasePacket` into its own function. No behavioural change.

## Startup safety checks (fail-loud)

### Check 1 — YAML key validation

In the new config-parse routine: if `detect.results-format` is missing, or is
not one of `portable` / `extended`:

```
FatalError("detect.results-format is required and must be \"portable\" or \"extended\"");
```

### Check 2 — DPDK iface count cap

In `runmode-dpdk.c`, while parsing each DPDK iface's `max-mpm-pattern-ids`:

```c
if (g_results_format == RESULTS_FORMAT_PORTABLE && iconf->max_mpm_pattern_ids > 6) {
    FatalError("detect.results-format=portable but %s: max-mpm-pattern-ids=%u "
               "exceeds the 6-slot limit of the portable format. "
               "Lower max-mpm-pattern-ids to <=6 or use results-format=extended.",
               iconf->iface, iconf->max_mpm_pattern_ids);
}
```

### Check 3 — Post-compile pid-range scan

Hooked into pattern-compile finalize (preferred location:
`src/util-mpm-hs.c` after all `PatternDatabase`s are built, or a one-shot walk
from `src/detect-engine.c` after `SigGroupBuild`):

```c
if (g_results_format == RESULTS_FORMAT_PORTABLE) {
    uint32_t max_seen = /* iterate parray[] across all PatternDatabases */;
    if (max_seen >= (1u << 14)) {
        FatalError("detect.results-format=portable requires all MPM pattern IDs to fit "
                   "in 14 bits (< 16384). Largest assigned pid is %u. "
                   "Reduce the rule set or use results-format=extended.", max_seen);
    }
}
```

## Files touched

| File | Change |
|---|---|
| `suricata.yaml.in` | New documented `detect.results-format` block. |
| `src/source-dpdk.c` | Split `DPDKReleasePacket` write path into `WritePortablePids()` + `WriteExtendedPids()`; define `g_results_format`. |
| `src/source-dpdk.h` | Export `ResultsFormat` enum and `g_results_format`. |
| `src/runmode-dpdk.c` | Parse `detect.results-format`. Enforce `max-mpm-pattern-ids <= 6` in portable mode. |
| `src/util-mpm-hs.c` *or* `src/detect-engine.c` | Post-compile scan: FatalError if any assigned pid ≥ 2^14 in portable mode. |
| `custom-patlen/test-pattern-ids.sh` (or sibling) | Add portable, overflow, and config-validation cases. |

No changes to `Packet::matched_pids` layout, `g_max_mpm_pattern_ids`, the
Hyperscan callback in `src/util-mpm-hs.c:1099`, or the
`src/detect-engine-payload.c` write paths.

## Testing

Reuse the existing `custom-patlen/test-pattern-ids.sh` harness style.

1. **Format round-trip on existing pcap fixtures**
   - `portable`: parse output pcap, assert
     (a) the 12-byte MAC area decodes back to the expected uint16 pids in slot
         order,
     (b) bit15 / bit14 reflect the toserver / payload-fn flags from input,
     (c) unused slots are `0x0000`,
     (d) IP/TCP/payload bytes are byte-identical to input (no header growth).
   - `extended`: existing test continues to pass (regression guard).

2. **Overflow paths (portable)**
   - Rule set producing > 6 matches on one packet → output MAC area is
     12 × `0xFF`.
   - Rule set with an assigned pid ≥ 16384 → `suricata -T` exits non-zero with
     the Check-3 message (not a runtime failure).

3. **Config validation (`suricata -T`)**
   - Missing `detect.results-format` → exits non-zero with Check-1 message.
   - `results-format: portable` + `max-mpm-pattern-ids: 12` → exits non-zero
     with Check-2 message.
   - Typo (`results-format: portible`) → exits non-zero with Check-1 message
     listing valid values.

## Risks / open items

- Endianness: the portable format writes `uint16_t` slots directly into the
  MAC area in **host byte order** (matching the original `159eb2153` design,
  which wrote `uint32_t` MAC slots the same way). This must be documented in
  the YAML comment so downstream parsers know what to expect on
  little-endian vs big-endian capture machines.
- `pid == 0 + flags == 0` collides with "empty slot". Acceptable per design
  decision above.
- If the pattern compile path doesn't expose a single point to scan all
  assigned pids easily, fall back to scanning during the Hyperscan callback
  the first time (lazy) — but startup-time check is strongly preferred and
  should be the default.
