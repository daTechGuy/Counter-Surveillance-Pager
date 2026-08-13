# rid_ble_monitor.awk -- run as:
#   hcidump -i hci0 --raw | awk -f rid_common.awk -f rid_ble_monitor.awk
#
# Parses hcidump's raw hex format, confirmed against this exact device's
# hcidump 5.72 output:
#   "> " (received) or "< " (sent), then hex bytes as "XX " pairs wrapped
#   at 20 bytes/line, continuation lines indented with no marker. Verified
#   by hand against bluez-hcidump's parser.c/hcidump.c source AND a real
#   capture from the device -- the leading byte is the H4 packet-type
#   indicator (0x04 = HCI Event), matching a raw HCI socket read.
#
# Does not touch the adapter -- only observes whatever hcitool/bluetoothd
# already put the controller into scanning for (payload.sh runs this
# alongside Flock-You's own hcitool lescan cycle).
#
# HCI LE Advertising Report event layout (Bluetooth Core Spec Vol 4 Part E
# 7.7.65.2) is "structure of arrays", not "array of structs": all
# Event_Types first, then all Address_Types, then all Addresses, then all
# Length_Data, then the concatenated Data blocks, then all RSSIs -- verified
# against a real single-report capture from this device (see conversation).

BEGIN {
    npkt = 0
    started = 0
}

/^[><] / {
    if (started && npkt > 0) process_ble_packet()
    started = 1
    npkt = 0
    n = split($0, toks, " ")
    for (k = 2; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { npkt++; pkt[npkt] = toks[k] }
    }
    next
}

{
    if (!started) next   # ignore hcidump's own startup banner lines
    n = split($0, toks, " ")
    for (k = 1; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { npkt++; pkt[npkt] = toks[k] }
    }
}

END {
    if (started && npkt > 0) process_ble_packet()
}

# Look for the ASTM Remote ID Service Data AD structure (AD type 0x16,
# UUID 0xFFFA on the wire as bytes FA FF, AD App Code 0x0D) inside one
# report's adv_data slice, arr[start .. start+len-1]. BLE legacy
# advertising carries exactly ONE 25-byte message per advertisement
# (unlike the WiFi methods, which wrap a full message pack) -- confirmed
# against transmitter-linux's hci_le_set_advertising_data().
function scan_ble_adv_data(arr, start, len, mac,    i, adlen, adtype, u1, u2, appcode, msgbase) {
    i = start
    while (i < start + len) {
        adlen = hex2dec(arr[i])
        if (adlen == 0) break
        adtype = hex2dec(arr[i + 1])
        if (adtype == 22 && adlen >= 5) {   # 0x16, Service Data - 16-bit UUID
            u1 = toupper(arr[i + 2])
            u2 = toupper(arr[i + 3])
            appcode = hex2dec(arr[i + 4])
            if (u1 == "FA" && u2 == "FF" && appcode == 13) {
                msgbase = i + 6   # skip len, type, uuid(2), appcode, msg_counter
                if (start + len - msgbase >= 25) {
                    emit_hit("ble", mac, arr, msgbase)
                }
            }
        }
        i += 1 + adlen
    }
}

function process_ble_packet(    nreports, r, evtype_start, addrtype_start, \
                                 addr_start, len_start, adv_start, addr_base, \
                                 lendata, mac) {
    if (npkt < 5) return
    if (toupper(pkt[1]) != "04") return   # H4 event packet
    if (toupper(pkt[2]) != "3E") return   # LE Meta Event
    if (hex2dec(pkt[4]) != 2) return      # LE Advertising Report subevent
    nreports = hex2dec(pkt[5])
    if (nreports < 1 || nreports > 25) return   # sanity cap

    evtype_start   = 6
    addrtype_start = evtype_start + nreports
    addr_start     = addrtype_start + nreports
    len_start      = addr_start + 6 * nreports
    adv_start      = len_start + nreports

    for (r = 0; r < nreports; r++) {
        addr_base = addr_start + 6 * r
        lendata = hex2dec(pkt[len_start + r])
        mac = mac_str_ble(pkt, addr_base)
        if (lendata > 0 && adv_start + lendata - 1 <= npkt) {
            scan_ble_adv_data(pkt, adv_start, lendata, mac)
        }
        adv_start += lendata
    }
}
