# glasses_ble_monitor.awk -- BLE smart-glasses detector via manufacturer
# company ID (Manufacturer Specific Data, AD type 0xFF), run as:
#   hcidump -i hci0 --raw | awk -f rid_common.awk -f glasses_ble_monitor.awk
#
# UNVERIFIED SIGNATURES -- read before trusting a hit from this file:
#   Source: Noezsolution/pineapple-pager-glasses-detector (payload.sh), which
#   documents these exact company-ID-to-brand mappings but cites no source
#   for any of them -- no Bluetooth SIG assigned-numbers reference, no
#   field-testing tracker, nothing. Four different company IDs mapped to
#   the same "Meta Ray-Ban" product is unusual for one vendor -- could mean
#   different advertisement types carry different chipset suppliers' own
#   IDs (Meta's glasses may report a component vendor's ID in some frames,
#   or support Google Fast Pair carrying a Google-associated ID alongside
#   their own), or could mean some entries are guessed/wrong. Never
#   independently confirmed against real hardware by this file's author,
#   or by this port. Every hit here is a diagnostic lead, not a confirmed
#   detection -- payload.sh's handle_glasses_ble_line() alerts it at the
#   same soft tier as flock_ble_monitor.awk's UUID signature (logged only,
#   no vibrate/LED), for exactly this reason.
#
# Manufacturer Specific Data structure (AD type 0xFF): 2-byte company ID,
# little-endian on the wire -- same field/byte-order Apple's Find My uses
# (4C 00 = company ID 0x004C), see rogue_tracker_monitor.awk's header for
# that citation. Company ID (conventional big-endian form) -> wire bytes
# -> brand label, per the source above:
#   0x0d53 -> 53 0d  |  0x01ab -> ab 01  |  0x058e -> 8e 05  |
#   0x00e0 -> e0 00  -- all four: "Meta Ray-Ban" (see caveat above)
#   0x03c2 -> c2 03  -- Snap Spectacles
#   0x009e -> 9e 00  -- Bose Frames
#   0x0822 -> 22 08  -- Vuzix
#   0x0987 -> 87 09  -- XREAL
#
# Own hcidump process, same adapter, same reasoning as every other BLE
# detector here -- HCI monitor sockets support multiple simultaneous
# readers, so this is another passive listener, not another radio. Same
# HCI LE Advertising Report "structure of arrays" parsing already
# hardware-verified for rid_ble_monitor.awk (see that file's header for the
# citation), including its trailing per-report RSSI byte (see
# rid_common.awk's ble_total_adv_len()/ble_rssi_for()).

BEGIN {
    gbnpkt = 0
    gbstarted = 0

    # Keyed on the wire-order (little-endian) byte pair, lowercase.
    glasses_company["530d"] = "Meta Ray-Ban"
    glasses_company["ab01"] = "Meta Ray-Ban"
    glasses_company["8e05"] = "Meta Ray-Ban"
    glasses_company["e000"] = "Meta Ray-Ban"
    glasses_company["c203"] = "Snap Spectacles"
    glasses_company["9e00"] = "Bose Frames"
    glasses_company["2208"] = "Vuzix"
    glasses_company["8709"] = "XREAL"
}

/^[><] / {
    if (gbstarted && gbnpkt > 0) process_glasses_packet()
    gbstarted = 1
    gbnpkt = 0
    n = split($0, toks, " ")
    for (k = 2; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { gbnpkt++; gbpkt[gbnpkt] = toks[k] }
    }
    next
}

{
    if (!gbstarted) next   # ignore hcidump's own startup banner lines
    n = split($0, toks, " ")
    for (k = 1; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { gbnpkt++; gbpkt[gbnpkt] = toks[k] }
    }
}

END {
    if (gbstarted && gbnpkt > 0) process_glasses_packet()
}

# Same 1st + every-10th packet-count throttle as the other BLE detectors,
# keyed per (mac, company-id) pair.
function glasses_throttle_ok(key,    c) {
    gb_seen[key]++
    c = gb_seen[key]
    return (c == 1 || c % 10 == 0)
}

function scan_glasses_adv_data(arr, start, len, mac, rssi,    i, adlen, adtype, cid, brand, key, rssi_sfx) {
    rssi_sfx = (rssi != "" && rssi != 127) ? "|rssi=" rssi : ""
    i = start
    while (i < start + len) {
        adlen = hex2dec(arr[i])
        if (adlen == 0) break
        if (i + adlen > start + len) break   # malformed/truncated, bail

        adtype = hex2dec(arr[i + 1])
        if (adtype == 255 && adlen >= 3) {   # Manufacturer Specific Data
            cid = tolower(arr[i + 2] arr[i + 3])
            if (cid in glasses_company) {
                brand = glasses_company[cid]
                key = mac "|" cid
                if (glasses_throttle_ok(key)) {
                    print "ble_glasses|" mac "|" brand "|cid=0x" arr[i + 3] arr[i + 2] rssi_sfx
                    fflush()
                }
            }
        }
        i += 1 + adlen
    }
}

# Same HCI LE Advertising Report layout as rid_ble_monitor.awk's
# process_ble_packet() -- see that file's header for the citation.
function process_glasses_packet(    nreports, r, addr_start, len_start, \
                                     adv_start, addr_base, lendata, mac, \
                                     rssi_start, rssi) {
    if (gbnpkt < 5) return
    if (toupper(gbpkt[1]) != "04") return   # H4 event packet
    if (toupper(gbpkt[2]) != "3E") return   # LE Meta Event
    if (hex2dec(gbpkt[4]) != 2) return      # LE Advertising Report subevent
    nreports = hex2dec(gbpkt[5])
    if (nreports < 1 || nreports > 25) return   # sanity cap

    addr_start = 6 + nreports + nreports   # skip Event_Types + Address_Types
    len_start  = addr_start + 6 * nreports
    adv_start  = len_start + nreports
    rssi_start = adv_start + ble_total_adv_len(gbpkt, len_start, nreports)

    for (r = 0; r < nreports; r++) {
        addr_base = addr_start + 6 * r
        lendata = hex2dec(gbpkt[len_start + r])
        mac = mac_str_ble(gbpkt, addr_base)
        rssi = ble_rssi_for(gbpkt, rssi_start, r, gbnpkt)
        if (lendata > 0 && adv_start + lendata - 1 <= gbnpkt) {
            scan_glasses_adv_data(gbpkt, adv_start, lendata, mac, rssi)
        }
        adv_start += lendata
    }
}
