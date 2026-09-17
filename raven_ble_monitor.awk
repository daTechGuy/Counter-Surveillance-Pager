# raven_ble_monitor.awk -- Flock Safety "Raven" acoustic gunshot-detector BLE
# scanner, run under ble_dispatch.awk on the shared hcidump capture (see that
# file's header for the full command line; hits go to -v RAVEN_HITS_FILE).
#
# A SEPARATE device class from every other Flock detector in this payload:
# Raven is Flock's acoustic gunshot-detection hardware (comparable to
# ShotSpotter/SoundThinking), a different product line from the ALPR cameras
# flock_wifi_monitor.awk/flock_ble_monitor.awk target. Ported from
# lukeswitz/oui-spy-unified-blue (src/engines/flock_match.h,
# flockMatchRavenUuid()) -- not yet field-confirmed against a real Raven
# unit by this project, same caveat as flock_ble_monitor.awk's
# mfg_serial_tn_validated path.
#
# Detection is by BLE GATT Service UUID combination, two tiers corresponding
# to two firmware generations:
#
#   fw12  -- ANY of 5 proprietary 128-bit service UUIDs (GPS/Power/Upload/
#     Config/Error -- custom, no real Bluetooth SIG assignment). Standalone
#     evidence: specific enough that a coincidental match from an unrelated
#     device is effectively impossible.
#   fw11x -- ALL THREE of Device Information (0x180A) + Heart Rate (0x1809)
#     + Location and Navigation (0x1819), three ordinary SIG-standard
#     16-bit services -- individually common (any fitness tracker/
#     smartwatch can advertise Heart Rate or Device Information alone), but
#     oui-spy-unified-blue's own source treats this exact combination
#     together as the discriminating signature for older Raven firmware.
#     Only counted when all three appear on the SAME advertisement, never a
#     partial match.
#
# The 5 proprietary UUIDs are the Bluetooth Base UUID
# (00000000-0000-1000-8000-00805F9B34FB) with a vendor-chosen 16-bit-style
# value spliced into the same string position the Bluetooth SIG's own
# 16-bit-UUID-to-128-bit expansion uses. Verified byte-for-byte with a
# throwaway Python one-liner before hardcoding these, not hand-transcribed:
# BLE sends 128-bit UUIDs little-endian (least-significant byte first), so
# e.g. GPS's textual "00003100-0000-1000-8000-00805f9b34fb" becomes, on the
# wire, fb 34 9b 5f 80 00 00 80 00 10 00 00 00 31 00 00 -- the 12-byte
# "fb349b5f80000080001000" prefix is shared by all 5 (and by the plain
# 16-bit-derived form of 0x180A/0x1809/0x1819 too, for that matter -- real
# devices just don't usually bother expanding an SIG-assigned 16-bit UUID
# out to 128 bits over the air, which is why those three are matched via
# the ordinary 16-bit Service UUID list instead, below).
#
# Same LE Advertising Report "structure of arrays" layout already
# hardware-verified for rid_ble_monitor.awk, same Address-type filter as
# flock_ble_monitor.awk's (see that file's header for why it's narrow, not a
# general phone-noise cut).
#
# Packet reassembly is not here: ble_dispatch.awk does it once for every BLE
# detector and fills rvpkt[]/rvnpkt when WANT_RAVEN is set, then calls
# process_raven_ble_packet(). Written for its own hcidump process originally
# (flock-sky-spy, never committed), converted when ported so Raven adds no
# capture or decode process of its own.

BEGIN {
    # 128-bit Service UUIDs, wire order (little-endian), 32 uppercase hex
    # chars each -- see header for the derivation. Value is the label used
    # in the emitted "svc=" field.
    RAVEN_UUID128["FB349B5F800000800010000000310000"] = "gps"
    RAVEN_UUID128["FB349B5F800000800010000000320000"] = "power"
    RAVEN_UUID128["FB349B5F800000800010000000330000"] = "upload"
    RAVEN_UUID128["FB349B5F800000800010000000340000"] = "config"
    RAVEN_UUID128["FB349B5F800000800010000000350000"] = "error"
}

# Same 1st + every-10th packet-count throttle as flock_ble_monitor.awk's.
function raven_throttle_ok(key,    c) {
    rv_seen[key]++
    c = rv_seen[key]
    return (c == 1 || c % 10 == 0)
}

# Scan one advertisement's AD structures for the Raven signature. 16-bit
# Service UUID lists (AD type 0x02/0x03) are checked for the three
# SIG-standard fw11x UUIDs; 128-bit Service UUID lists (AD type 0x06/0x07)
# are checked for the five proprietary fw12 UUIDs -- standalone evidence,
# reported immediately per match. The fw11x tally happens after the full
# walk, since all three must appear on the same advertisement.
function scan_raven_adv_data(arr, start, len, mac, rssi,
        i, adlen, adtype, j, u128, has_dev_info, has_hrt, has_old_loc, key, out) {
    out = (RAVEN_HITS_FILE != "") ? RAVEN_HITS_FILE : "/dev/stdout"
    i = start
    has_dev_info = 0
    has_hrt = 0
    has_old_loc = 0
    while (i < start + len) {
        adlen = hex2dec(arr[i])
        if (adlen == 0) break
        if (i + adlen > start + len) break   # malformed/truncated, bail

        adtype = hex2dec(arr[i + 1])
        if ((adtype == 2 || adtype == 3) && adlen >= 3) {   # 16-bit UUID list
            for (j = i + 2; j + 1 <= i + adlen; j += 2) {
                if (toupper(arr[j]) == "0A" && toupper(arr[j + 1]) == "18") has_dev_info = 1
                else if (toupper(arr[j]) == "09" && toupper(arr[j + 1]) == "18") has_hrt = 1
                else if (toupper(arr[j]) == "19" && toupper(arr[j + 1]) == "18") has_old_loc = 1
            }
        } else if ((adtype == 6 || adtype == 7) && adlen >= 17) {   # 128-bit UUID list
            for (j = i + 2; j + 15 <= i + adlen; j += 16) {
                u128 = toupper(arr[j]) toupper(arr[j+1]) toupper(arr[j+2]) toupper(arr[j+3]) \
                       toupper(arr[j+4]) toupper(arr[j+5]) toupper(arr[j+6]) toupper(arr[j+7]) \
                       toupper(arr[j+8]) toupper(arr[j+9]) toupper(arr[j+10]) toupper(arr[j+11]) \
                       toupper(arr[j+12]) toupper(arr[j+13]) toupper(arr[j+14]) toupper(arr[j+15])
                if (u128 in RAVEN_UUID128) {
                    key = mac "|raven_fw12_" RAVEN_UUID128[u128]
                    if (raven_throttle_ok(key)) {
                        print "ble_raven|" mac "|fw12|svc=" RAVEN_UUID128[u128] \
                              ((rssi != "" && rssi != 127) ? "|rssi=" rssi : "") >> out
                        fflush()
                    }
                }
            }
        }
        i += 1 + adlen
    }

    if (has_dev_info && has_hrt && has_old_loc) {
        key = mac "|raven_fw11x"
        if (raven_throttle_ok(key)) {
            print "ble_raven|" mac "|fw11x" ((rssi != "" && rssi != 127) ? "|rssi=" rssi : "") >> out
            fflush()
        }
    }
}

# Same HCI LE Advertising Report layout / Address-type filter as
# flock_ble_monitor.awk's process_flock_ble_packet() -- see that file's
# header for the citation and why the filter is narrow, not a general
# phone-noise cut.
function process_raven_ble_packet(    nreports, r, addrtype_start, addr_start, len_start, \
                                       adv_start, addr_base, lendata, mac, \
                                       rssi_start, rssi, addr_type) {
    if (rvnpkt < 5) return
    if (toupper(rvpkt[1]) != "04") return   # H4 event packet
    if (toupper(rvpkt[2]) != "3E") return   # LE Meta Event
    if (hex2dec(rvpkt[4]) != 2) return      # LE Advertising Report subevent
    nreports = hex2dec(rvpkt[5])
    if (nreports < 1 || nreports > 25) return   # sanity cap

    addrtype_start = 6 + nreports          # skip Event_Types, Address_Types next
    addr_start = addrtype_start + nreports
    len_start  = addr_start + 6 * nreports
    adv_start  = len_start + nreports
    rssi_start = adv_start + ble_total_adv_len(rvpkt, len_start, nreports)

    for (r = 0; r < nreports; r++) {
        addr_base = addr_start + 6 * r
        lendata = hex2dec(rvpkt[len_start + r])
        mac = mac_str_ble(rvpkt, addr_base)
        rssi = ble_rssi_for(rvpkt, rssi_start, r, rvnpkt)
        addr_type = hex2dec(rvpkt[addrtype_start + r])
        if (lendata > 0 && (addr_type == 0 || addr_type == 1) \
            && adv_start + lendata - 1 <= rvnpkt) {
            scan_raven_adv_data(rvpkt, adv_start, lendata, mac, rssi)
        }
        adv_start += lendata
    }
}
