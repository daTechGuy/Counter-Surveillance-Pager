# flock_ble_monitor.awk -- experimental BLE Flock Safety camera detector via
# 16-bit Service UUID 0x09C8, run as:
#   hcidump -i hci0 --raw | awk -f rid_common.awk -f flock_ble_monitor.awk
#
# UNVERIFIED SIGNATURE -- read before trusting a hit from this file the way
# you would flock_wifi_monitor.awk's or the name-string BLE scan's:
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
#   like). This file implements the one concrete, unambiguous part -- 16-bit
#   Service UUID 0x09C8, bytes "C8 09" little-endian, same AD-type family as
#   Tile's 0xFEED in rogue_tracker_monitor.awk -- not the Manufacturer-
#   Specific-Data reading, which was never demonstrated with real bytes
#   anywhere this was sourced from.
#   Every hit here is a diagnostic lead, not a confirmed detection --
#   payload.sh's handle_flock_ble_line() alerts it at the same soft tier as
#   a Flock WiFi conf=low hit (logged, no vibrate/LED) for exactly this
#   reason.
#
# Own hcidump process, same adapter, same reasoning as rogue_tracker_monitor.awk
# / rid_ble_monitor.awk's own readers -- HCI monitor sockets support multiple
# simultaneous readers, so this is another passive listener, not another
# radio. Same hcidump reassembly / LE Advertising Report "structure of
# arrays" parsing already hardware-verified for rid_ble_monitor.awk (see
# that file's header for the citation).

BEGIN {
    fbnpkt = 0
    fbstarted = 0
}

/^[><] / {
    if (fbstarted && fbnpkt > 0) process_flock_ble_packet()
    fbstarted = 1
    fbnpkt = 0
    n = split($0, toks, " ")
    for (k = 2; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { fbnpkt++; fbpkt[fbnpkt] = toks[k] }
    }
    next
}

{
    if (!fbstarted) next   # ignore hcidump's own startup banner lines
    n = split($0, toks, " ")
    for (k = 1; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { fbnpkt++; fbpkt[fbnpkt] = toks[k] }
    }
}

END {
    if (fbstarted && fbnpkt > 0) process_flock_ble_packet()
}

# Same 1st + every-10th packet-count throttle as rogue_tracker_monitor.awk's.
function flock_ble_throttle_ok(key,    c) {
    fb_seen[key]++
    c = fb_seen[key]
    return (c == 1 || c % 10 == 0)
}

# Same AD-structure walk as rogue_tracker_monitor.awk's scan_tracker_adv_data,
# narrowed to just the 16-bit Service UUID list check (AD type 0x02
# incomplete / 0x03 complete) for UUID 0x09C8.
function scan_flock_ble_adv_data(arr, start, len, mac,    i, adlen, adtype, u1, u2, j, key) {
    i = start
    while (i < start + len) {
        adlen = hex2dec(arr[i])
        if (adlen == 0) break
        if (i + adlen > start + len) break   # malformed/truncated, bail

        adtype = hex2dec(arr[i + 1])
        if ((adtype == 2 || adtype == 3) && adlen >= 3) {   # 16-bit UUID list
            for (j = i + 2; j + 1 <= i + adlen; j += 2) {
                u1 = toupper(arr[j]); u2 = toupper(arr[j + 1])
                if (u1 == "C8" && u2 == "09") {   # UUID 0x09C8, little-endian
                    key = mac "|flock_uuid09c8"
                    if (flock_ble_throttle_ok(key)) {
                        print "ble_flock|" mac "|uuid_09c8"
                        fflush()
                    }
                }
            }
        }
        i += 1 + adlen
    }
}

# Same HCI LE Advertising Report layout as rid_ble_monitor.awk's
# process_ble_packet() / rogue_tracker_monitor.awk's process_tracker_packet()
# -- see rid_ble_monitor.awk's header for the Bluetooth Core Spec citation.
function process_flock_ble_packet(    nreports, r, addr_start, len_start, \
                                       adv_start, addr_base, lendata, mac) {
    if (fbnpkt < 5) return
    if (toupper(fbpkt[1]) != "04") return   # H4 event packet
    if (toupper(fbpkt[2]) != "3E") return   # LE Meta Event
    if (hex2dec(fbpkt[4]) != 2) return      # LE Advertising Report subevent
    nreports = hex2dec(fbpkt[5])
    if (nreports < 1 || nreports > 25) return   # sanity cap

    addr_start = 6 + nreports + nreports   # skip Event_Types + Address_Types
    len_start  = addr_start + 6 * nreports
    adv_start  = len_start + nreports

    for (r = 0; r < nreports; r++) {
        addr_base = addr_start + 6 * r
        lendata = hex2dec(fbpkt[len_start + r])
        mac = mac_str_ble(fbpkt, addr_base)
        if (lendata > 0 && adv_start + lendata - 1 <= fbnpkt) {
            scan_flock_ble_adv_data(fbpkt, adv_start, lendata, mac)
        }
        adv_start += lendata
    }
}
