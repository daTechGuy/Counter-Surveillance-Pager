# flock_ble_monitor.awk -- BLE Flock Safety camera detection, two independent
# paths, run under ble_dispatch.awk on the shared hcidump capture:
#
# PATH 1 -- 16-bit Service UUID 0x09C8. UNVERIFIED SIGNATURE -- read before
# trusting a hit from this path the way you would flock_wifi_monitor.awk's or
# the name-string BLE scan's:
#   Source: cncartistsec/BluePine-WiFi-Pineapple-Pager (funcs_scan.sh), which
#   cites "wgreenberg/flock-you" as the origin of a "0x09C8 (XUNTONG)"
#   signature -- but BluePine's own scan function never actually calls this
#   check; as of the commit reviewed, it exists only as a comment, never
#   wired into working code, so it was never field-verified by its own
#   author either. That comment is also internally inconsistent about what
#   KIND of field 0x09C8 is: labeled "Manufacturer ID" on one line, but the
#   concrete byte example given ("03 03 C8 09") is actually AD type 0x03 --
#   Complete List of 16-bit Service UUIDs -- not AD type 0xFF (Manufacturer
#   Specific Data, the field BLE "Company Identifiers" like Apple's 0x004C
#   actually live in; see rogue_tracker_monitor.awk for what that looks
#   like). This path implements the one concrete, unambiguous part -- 16-bit
#   Service UUID 0x09C8, bytes "C8 09" little-endian, same AD-type family as
#   Tile's 0xFEED in rogue_tracker_monitor.awk -- not the Manufacturer-
#   Specific-Data reading, which was never demonstrated with real bytes
#   anywhere this was sourced from.
#   Every hit here is a diagnostic lead, not a confirmed detection --
#   payload.sh's handle_flock_ble_line() alerts it at the same soft tier as
#   a Flock WiFi conf=low hit (logged, no vibrate/LED) for exactly this
#   reason.
#
# PATH 2 -- mfg_serial_tn_validated, added from lukeswitz/oui-spy-unified-blue
# (src/engines/flock_match.h, FLOCK_SIG_VALIDATED), which turns out to
# resolve PATH 1's own ambiguity: that fork DOES read 0x09C8 as a
# Manufacturer-Specific-Data Company ID (XUNTONG, Flock's battery vendor),
# with real corroborating evidence attached -- not the unverified guess
# BluePine's comment was. Three independent signals, all ported byte-for-byte
# from that fork's C++, only counted as a hit when ALL THREE agree on the
# same advertisement:
#   1. Company ID 0x09C8 in AD type 0xFF (Manufacturer Specific Data).
#   2. The device's Local Name (AD type 0x08/0x09) is exactly 10 ASCII
#      digits -- post-March-2025 Penguin firmware dropped the "Penguin-"
#      prefix, leaving the bare serial. NOT standalone evidence on its own
#      (any device could coincidentally advertise 10 digits) -- that's why
#      this is corroboration, not its own detection path.
#   3. A "TN" + digits serial substring recoverable from within that same
#      manufacturer-data payload (see flock_ble_extract_tn()).
# Still unproven against a real camera by either this project or
# oui-spy-unified-blue -- see handle_flock_ble_line() for why it's alerted
# (vibrate/LED, same tier as a WiFi conf=medium hit) despite that: three
# independent signals agreeing is meaningfully stronger corroboration than
# PATH 1's bare UUID alone, even pre-field-confirmation.
#
# Both paths are gated by the same BLE address-type filter (ported from that
# fork's flockShouldConsiderAddr()): HCI's own Address_Type field per report
# is checked, and only Public(0)/Random(1) are scanned -- Identity types
# 2/3 mean this controller already resolved the advertiser via its own
# resolving list, which is only possible for a device using resolvable
# private addresses (privacy-mode phones/wearables), never a fixed device
# like a camera. This is a narrow filter, not a general phone-noise cut --
# most ordinary randomized-MAC phone traffic still reports as plain type 1
# and passes through untouched; static-random addresses (which real fixed
# hardware can also use) are indistinguishable from private-random ones at
# this layer without the controller having already resolved them.
#
# Same LE Advertising Report "structure of arrays" parsing already
# hardware-verified for rid_ble_monitor.awk (see that file's header for the
# citation).
#
# Each hit also carries RSSI (signal strength -- distance from the
# transmitter, not GPS position) as "|rssi=N" dBm when available, via
# rid_common.awk's shared ble_total_adv_len()/ble_rssi_for() helpers --
# same trailing-per-report-RSSI layout rid_ble_monitor.awk's header cites.

# Packet reassembly used to live here -- see rogue_tracker_monitor.awk's
# analogous note for why: merged into ble_dispatch.awk alongside
# rid_ble_monitor.awk/rogue_tracker_monitor.awk/glasses_ble_monitor.awk.
# fbnpkt/fbpkt[] are still this function's own state, just written by that
# shared driver now.

# Same 1st + every-10th packet-count throttle as rogue_tracker_monitor.awk's.
function flock_ble_throttle_ok(key,    c) {
    fb_seen[key]++
    c = fb_seen[key]
    return (c == 1 || c % 10 == 0)
}

# True iff name is exactly 10 ASCII digits -- ported from oui-spy-unified-
# blue's flockMatchBareSerialName(): post-March-2025 Penguin firmware
# advertises its serial bare (no "Penguin-" prefix), but a 10-digit string
# alone is common enough that it's only used as ONE leg of the 3-way
# corroboration in scan_flock_ble_adv_data() below, never as standalone
# evidence.
function is_flock_ble_bare_serial(s,    i) {
    if (length(s) != 10) return 0
    for (i = 1; i <= 10; i++) {
        if (substr(s, i, 1) !~ /^[0-9]$/) return 0
    }
    return 1
}

# Scan raw bytes [start, start+len) for ASCII "TN" followed by 1+ ASCII
# digit bytes -- ported byte-for-byte from oui-spy-unified-blue's
# flockMatchMfgPayload() (flock_match.h), deliberately NOT via
# rid_common.awk's ascii_from_hex(): that helper stops at the first 0x00
# byte, correct for a real NUL-terminated name field but wrong here --
# manufacturer-specific data is arbitrary binary, and a NUL can legitimately
# appear before an embedded TN-serial.
function flock_ble_extract_tn(arr, start, len,    i, j, v, tn) {
    for (i = start; i < start + len - 1; i++) {
        if (hex2dec(arr[i]) == 84 && hex2dec(arr[i + 1]) == 78) {   # 'T' 'N'
            v = hex2dec(arr[i + 2])
            if (v < 48 || v > 57) continue   # next byte must be a digit
            tn = "TN"
            j = i + 2
            while (j < start + len) {
                v = hex2dec(arr[j])
                if (v < 48 || v > 57) break
                tn = tn sprintf("%c", v)
                j++
            }
            return tn
        }
    }
    return ""
}

# Same AD-structure walk as rogue_tracker_monitor.awk's scan_tracker_adv_data.
# Two independent checks share this one walk (see file header for both):
#   - 16-bit Service UUID list (AD type 0x02/0x03) for UUID 0x09C8 -- PATH 1.
#   - Manufacturer Specific Data (AD type 0xFF) Company ID 0x09C8 + Local
#     Name (AD type 0x08/0x09) + embedded TN-serial -- PATH 2, only reported
#     when all three agree for this same advertisement.
function scan_flock_ble_adv_data(arr, start, len, mac, rssi,
        i, adlen, adtype, u1, u2, j, key, out, name, has_uuid, has_mfg, tn) {
    out = (FLOCK_BLE_HITS_FILE != "") ? FLOCK_BLE_HITS_FILE : "/dev/stdout"
    i = start
    name = ""
    has_uuid = 0
    has_mfg = 0
    tn = ""
    while (i < start + len) {
        adlen = hex2dec(arr[i])
        if (adlen == 0) break
        if (i + adlen > start + len) break   # malformed/truncated, bail

        adtype = hex2dec(arr[i + 1])
        if ((adtype == 2 || adtype == 3) && adlen >= 3) {   # 16-bit UUID list
            for (j = i + 2; j + 1 <= i + adlen; j += 2) {
                u1 = toupper(arr[j]); u2 = toupper(arr[j + 1])
                if (u1 == "C8" && u2 == "09") has_uuid = 1   # UUID 0x09C8, little-endian
            }
        } else if ((adtype == 8 || adtype == 9) && adlen >= 2) {
            name = ascii_from_hex(arr, i + 2, adlen - 1)   # Shortened/Complete Local Name
        } else if (adtype == 255 && adlen >= 3) {
            # Manufacturer Specific Data. Company ID is little-endian --
            # same "C8"/"09" byte order as the Service UUID check above --
            # see oui-spy-unified-blue's flock_match.h: XUNTONG (Flock's
            # battery vendor), Company ID 0x09C8.
            if (toupper(arr[i + 2]) == "C8" && toupper(arr[i + 3]) == "09") {
                has_mfg = 1
                if (adlen > 3) tn = flock_ble_extract_tn(arr, i + 4, adlen - 3)
            }
        }
        i += 1 + adlen
    }

    if (has_uuid) {
        key = mac "|flock_uuid09c8"
        if (flock_ble_throttle_ok(key)) {
            print "ble_flock|" mac "|uuid_09c8" ((rssi != "" && rssi != 127) ? "|rssi=" rssi : "") >> out
            fflush()
        }
    }

    if (has_mfg && tn != "" && is_flock_ble_bare_serial(name)) {
        key = mac "|flock_mfg_serial_tn"
        if (flock_ble_throttle_ok(key)) {
            print "ble_flock|" mac "|mfg_serial_tn_validated|serial=" name "|tn=" tn \
                  ((rssi != "" && rssi != 127) ? "|rssi=" rssi : "") >> out
            fflush()
        }
    }
}

# Same HCI LE Advertising Report layout as rid_ble_monitor.awk's
# process_ble_packet() / rogue_tracker_monitor.awk's process_tracker_packet()
# -- see rid_ble_monitor.awk's header for the Bluetooth Core Spec citation.
function process_flock_ble_packet(    nreports, r, addrtype_start, addr_start, len_start, \
                                       adv_start, addr_base, lendata, mac, \
                                       rssi_start, rssi, addr_type) {
    if (fbnpkt < 5) return
    if (toupper(fbpkt[1]) != "04") return   # H4 event packet
    if (toupper(fbpkt[2]) != "3E") return   # LE Meta Event
    if (hex2dec(fbpkt[4]) != 2) return      # LE Advertising Report subevent
    nreports = hex2dec(fbpkt[5])
    if (nreports < 1 || nreports > 25) return   # sanity cap

    addrtype_start = 6 + nreports          # skip Event_Types, Address_Types next
    addr_start = addrtype_start + nreports
    len_start  = addr_start + 6 * nreports
    adv_start  = len_start + nreports
    rssi_start = adv_start + ble_total_adv_len(fbpkt, len_start, nreports)

    for (r = 0; r < nreports; r++) {
        addr_base = addr_start + 6 * r
        lendata = hex2dec(fbpkt[len_start + r])
        mac = mac_str_ble(fbpkt, addr_base)
        rssi = ble_rssi_for(fbpkt, rssi_start, r, fbnpkt)
        # Address-type filter -- see file header. 0=Public, 1=Random
        # (static or private -- indistinguishable here, real Flock hardware
        # can use either), 2/3=Identity (already host-resolved, only
        # possible for a privacy-mode phone/wearable).
        addr_type = hex2dec(fbpkt[addrtype_start + r])
        if (lendata > 0 && (addr_type == 0 || addr_type == 1) \
            && adv_start + lendata - 1 <= fbnpkt) {
            scan_flock_ble_adv_data(fbpkt, adv_start, lendata, mac, rssi)
        }
        adv_start += lendata
    }
}
