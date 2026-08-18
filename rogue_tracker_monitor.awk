# rogue_tracker_monitor.awk -- BLE rogue-tracker (AirTag / Tile / Samsung
# SmartTag / Google Find My Device Network) structural signature detector.
# Run as:
#   hcidump -i hci0 --raw | awk -f rid_common.awk -f rogue_tracker_monitor.awk
#
# WHY THIS IS A DIFFERENT KIND OF DETECTOR THAN EVERYTHING ELSE IN THIS
# PAYLOAD: Flock cameras and Mesh-Detect's watchlist both key off a stable
# manufacturer OUI. Rogue trackers are specifically engineered NOT to have
# one -- Apple/Samsung/Google's anti-stalking BLE designs use a random,
# periodically-rotating BLE address on purpose, precisely so a static
# OUI/MAC list can't track the tracker. Detecting these requires matching
# the ADVERTISEMENT PAYLOAD STRUCTURE (company/service ID + a protocol-
# specific type byte), not the MAC -- and even then, a single sighting
# proves nothing (could be anyone's tracker in a store, in a neighboring
# apartment, etc). The actually-useful signal is PERSISTENCE: the same
# structural identity (see note on MAC-vs-payload-identity below) staying
# near you over a sustained window. This file only does the structural
# match and emits one hit line per sighting; deliberately NOT time-window
# logic -- see payload.sh's handle_tracker_line() for that, and for why it
# lives in bash and not here.
#
# FOUR PROTOCOLS, sourced and verified against (not assumed from memory):
#   - Apple Find My "offline finding" beacon (what an AirTag/Find My
#     accessory broadcasts while separated from its owner's phone -- the
#     state relevant to "is this following me", not the short-range
#     nearby-pairing beacon): AD type 0xFF (Manufacturer Specific Data),
#     company ID bytes 4C 00 (Apple, little-endian), then type byte 0x12,
#     length byte 0x19 (25), status byte, 22 bytes of partial public key.
#     Byte layout verified against seemoo-lab/openhaystack's ESP32 firmware
#     (Firmware/ESP32/main/openhaystack_main.c adv_data[] array), the
#     reference implementation for constructing this exact beacon.
#     NOTE: the BLE MAC address itself is derived from (and rotates in
#     lockstep with) the advertised public key, so within one rotation
#     window (order of ~15+ min) the MAC is a valid stand-in identifier for
#     "the same physical tag" -- that's what the persistence tracking in
#     payload.sh keys on.
#   - Tile: AD type 0x02/0x03 (16-bit Service UUID list) containing UUID
#     0xFEED (bytes ED FE on the wire, little-endian). Tile's protocol is
#     undocumented/proprietary, but this UUID is the confirmed, widely
#     reverse-engineered discovery signature. Unlike the others, Tile's BLE
#     MAC does NOT rotate (does not change in connected or lost states),
#     which actually makes persistence tracking more reliable for Tile, not
#     less.
#   - Samsung SmartTag (registered/paired, "offline finding" -- the state
#     relevant here): AD type 0x16 (Service Data - 16-bit UUID), UUID
#     0xFD5A (bytes 5A FD on the wire). Byte structure per academic analysis
#     of Samsung's crowd-sourced Bluetooth location system (Heinrich et al.,
#     "Privacy Analysis of Samsung's Crowd-Sourced Bluetooth Location
#     Tracking System", arXiv:2210.14702) -- only the AD type + UUID gate is
#     used here (see file header note on scope below).
#   - Google Find My Device Network (FMDN): AD type 0x16, UUID 0xFEAA (bytes
#     AA FE on the wire -- the same Eddystone service UUID, reused), then a
#     frame-type byte: 0x40 = normal rotating-identifier mode, 0x41 =
#     "unwanted tracking protection activated" -- i.e. the accessory has
#     ITSELF detected it's been separated from its owner and is
#     self-flagging exactly the condition this whole detector exists to
#     find. Source: Google's own public spec (Find Hub Network Accessory
#     Specification, developers.google.com/nearby/fast-pair/specifications/
#     extensions/fmdn). This is the one protocol here where the device
#     volunteers the "might be stalking someone" signal directly -- treated
#     as a high-confidence immediate alert in payload.sh rather than
#     needing the persistence window the other three protocols require.
#
# SCOPE NOTE: only the header (AD type + company/service ID + protocol type
# byte) is parsed and verified against the sources above. The deeper
# per-protocol payload fields (Apple's status-byte bit meanings, Samsung's
# aging counter/privacy-ID/battery fields, FMDN's hashed-flags byte) are NOT
# decoded -- confidence in those exact sub-byte semantics from the sources
# consulted wasn't as solid as the header-level signatures, and the header
# match alone is sufficient to identify "this is protocol X's tracking
# beacon", which is what drives the alert. A future refinement could add
# battery-level / rotation-state decoding on top of this.
#
# Same architecture as flock_wifi_monitor.awk / mesh_wifi_monitor.awk: own
# capture process (here, its own `hcidump -i hci0 --raw`, running alongside
# the existing drone-RID BLE reader and the Flock BLE hcitool lescan cycle
# -- HCI monitor sockets support multiple simultaneous readers, same
# reasoning as the multi-tcpdump-reader WiFi side) and its own copy of the
# hcidump reassembly / LE Advertising Report "structure of arrays" parsing
# already hardware-verified for rid_ble_monitor.awk (see that file's header
# for the citation) -- not merged into that file via a 3rd -f, for the same
# reason as the WiFi detectors: its rules end in `next`, which would block
# anything appended after it in one merged awk program.
#
# Each hit also carries RSSI (signal strength -- distance from the
# transmitter, not GPS position) as "|rssi=N" dBm when available, via
# rid_common.awk's shared ble_total_adv_len()/ble_rssi_for() helpers --
# same trailing-per-report-RSSI layout rid_ble_monitor.awk's header cites.

BEGIN {
    tnpkt = 0
    tstarted = 0
}

/^[><] / {
    if (tstarted && tnpkt > 0) process_tracker_packet()
    tstarted = 1
    tnpkt = 0
    n = split($0, toks, " ")
    for (k = 2; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { tnpkt++; tpkt[tnpkt] = toks[k] }
    }
    next
}

{
    if (!tstarted) next   # ignore hcidump's own startup banner lines
    n = split($0, toks, " ")
    for (k = 1; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { tnpkt++; tpkt[tnpkt] = toks[k] }
    }
}

END {
    if (tstarted && tnpkt > 0) process_tracker_packet()
}

# Emit at most once for the 1st sighting of a (mac,protocol) pair, then
# again every EMIT_EVERY sightings after that -- a packet-count-based
# throttle (not time-based: busybox awk's systime() support is unconfirmed
# on this device, unlike bash's `date`, which payload.sh already relies on
# elsewhere) so a tracker advertising every ~1-2s doesn't flood the hits
# file. The real time-window persistence decision lives in payload.sh,
# which sees every throttled-through hit with a fresh `date +%s` read.
function tracker_throttle_ok(key,    c) {
    seen_count[key]++
    c = seen_count[key]
    return (c == 1 || c % 50 == 0)
}

# rssi is 127 (not-available sentinel) or a signed dBm value from
# ble_rssi_for() -- appended as its own "|rssi=N" segment, same optional-
# trailing-field convention as rid_common.awk's emit_hit(), so it's
# suppressed rather than printed when not meaningful.
function scan_tracker_adv_data(arr, start, len, mac, rssi,    i, adlen, adtype, \
                                u1, u2, b, j, key, rssi_sfx) {
    rssi_sfx = (rssi != "" && rssi != 127) ? "|rssi=" rssi : ""
    i = start
    while (i < start + len) {
        adlen = hex2dec(arr[i])
        if (adlen == 0) break
        if (i + adlen > start + len) break   # malformed/truncated, bail

        adtype = hex2dec(arr[i + 1])

        if (adtype == 255 && adlen >= 6) {           # Manufacturer Specific Data
            u1 = toupper(arr[i + 2]); u2 = toupper(arr[i + 3])
            if (u1 == "4C" && u2 == "00") {           # Apple
                b = hex2dec(arr[i + 4])
                if (b == 18) {                        # 0x12 offline finding
                    key = mac "|applefindmy"
                    if (tracker_throttle_ok(key)) {
                        print "ble_tracker|" mac "|applefindmy|status=" arr[i + 6] rssi_sfx
                        fflush()
                    }
                }
            }
        } else if ((adtype == 2 || adtype == 3) && adlen >= 3) {   # 16-bit UUID list
            for (j = i + 2; j + 1 <= i + adlen; j += 2) {
                u1 = toupper(arr[j]); u2 = toupper(arr[j + 1])
                if (u1 == "ED" && u2 == "FE") {       # Tile (0xFEED)
                    key = mac "|tile"
                    if (tracker_throttle_ok(key)) {
                        print "ble_tracker|" mac "|tile|" rssi_sfx
                        fflush()
                    }
                }
            }
        } else if (adtype == 22 && adlen >= 3) {      # Service Data - 16-bit UUID
            u1 = toupper(arr[i + 2]); u2 = toupper(arr[i + 3])
            if (u1 == "5A" && u2 == "FD") {           # Samsung SmartTag (0xFD5A)
                key = mac "|smarttag"
                if (tracker_throttle_ok(key)) {
                    print "ble_tracker|" mac "|smarttag|" rssi_sfx
                    fflush()
                }
            } else if (u1 == "AA" && u2 == "FE" && adlen >= 4) {   # Eddystone/FMDN (0xFEAA)
                b = hex2dec(arr[i + 4])
                if (b == 65) {                        # 0x41 unwanted tracking
                    key = mac "|fmdn_unwanted"
                    if (tracker_throttle_ok(key)) {
                        print "ble_tracker|" mac "|fmdn_unwanted|" rssi_sfx
                        fflush()
                    }
                } else if (b == 64) {                 # 0x40 normal
                    key = mac "|fmdn_normal"
                    if (tracker_throttle_ok(key)) {
                        print "ble_tracker|" mac "|fmdn_normal|" rssi_sfx
                        fflush()
                    }
                }
            }
        }
        i += 1 + adlen
    }
}

# Same HCI LE Advertising Report "structure of arrays" layout as
# rid_ble_monitor.awk's process_ble_packet() -- see that file's header for
# the Bluetooth Core Spec citation and hardware verification note.
function process_tracker_packet(    nreports, r, addr_start, len_start, \
                                     adv_start, addr_base, lendata, mac, \
                                     rssi_start, rssi) {
    if (tnpkt < 5) return
    if (toupper(tpkt[1]) != "04") return   # H4 event packet
    if (toupper(tpkt[2]) != "3E") return   # LE Meta Event
    if (hex2dec(tpkt[4]) != 2) return      # LE Advertising Report subevent
    nreports = hex2dec(tpkt[5])
    if (nreports < 1 || nreports > 25) return   # sanity cap

    addr_start = 6 + nreports + nreports   # skip Event_Types + Address_Types
    len_start  = addr_start + 6 * nreports
    adv_start  = len_start + nreports
    rssi_start = adv_start + ble_total_adv_len(tpkt, len_start, nreports)

    for (r = 0; r < nreports; r++) {
        addr_base = addr_start + 6 * r
        lendata = hex2dec(tpkt[len_start + r])
        mac = mac_str_ble(tpkt, addr_base)
        rssi = ble_rssi_for(tpkt, rssi_start, r, tnpkt)
        if (lendata > 0 && adv_start + lendata - 1 <= tnpkt) {
            scan_tracker_adv_data(tpkt, adv_start, lendata, mac, rssi)
        }
        adv_start += lendata
    }
}
