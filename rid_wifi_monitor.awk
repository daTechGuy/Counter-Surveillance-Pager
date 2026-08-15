# rid_wifi_monitor.awk -- run as:
#   tcpdump -i wlan0mon -n -l -xx type mgt | awk -f rid_common.awk -f rid_wifi_monitor.awk
#
# Parses tcpdump 4.99.5's `-xx` text hex-dump format, confirmed against a
# real capture from this device: a one-line-per-packet summary (starts with
# an HH:MM:SS timestamp, no leading whitespace) followed by hex lines
# "        0xNNNN:  XXXX XXXX ... " (8 leading spaces, offset, then 2-byte
# groups). -xx includes the radiotap link-layer header and omits the ASCII
# column, which is exactly what's needed here and simplest to parse (no
# interleaved ASCII to skip over).
#
# Radiotap-stripping and the 802.11 mgmt-header field offsets below were
# hand-verified byte-by-byte against a real captured beacon from this
# device: it_len=56 landed exactly on frame_control=0x0080 (Beacon), and
# offset dot11+10 landed exactly on the real source MAC (see conversation).
#
# Looks for two Open Drone ID WiFi transports (byte offsets cited in
# rid_common.awk's header against opendroneid-core-c):
#   - Beacon method: vendor-specific IE (221) with OUI FA:0B:BC, type 0x0D
#   - NAN method: Public Action frame carrying a NAN Service Descriptor
#     attribute for the "org.opendroneid.remoteid" service ID

BEGIN {
    npkt = 0
    started = 0
}

/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\./ {
    if (started && npkt > 0) process_wifi_packet()
    started = 1
    npkt = 0
    next   # summary line carries no packet bytes
}

/^[ \t]*0x[0-9A-Fa-f]+:/ {
    if (!started) next
    line = $0
    sub(/^[ \t]*0x[0-9A-Fa-f]+:[ \t]*/, "", line)
    n = split(line, toks, " ")
    for (k = 1; k <= n; k++) {
        tok = toks[k]
        if (tok ~ /^[0-9A-Fa-f]+$/) {
            tl = length(tok)
            for (p = 1; p <= tl; p += 2) {
                b = substr(tok, p, 2)
                if (length(b) == 2) { npkt++; pkt[npkt] = b }
            }
        }
    }
    next
}

{ next }   # ignore tcpdump's startup banner / trailing capture-stats lines

END {
    if (started && npkt > 0) process_wifi_packet()
}

# ies: 802.11 information-element list, TYPE-FIRST-THEN-LENGTH (element_id,
# length, data[length]) -- the reverse of a BLE AD structure's length-first
# layout. Mixing these two up (which the first, python version of this
# payload did) silently breaks multi-message vendor IEs, so this is called
# out explicitly rather than sharing a helper with the BLE side.
function scan_wifi_beacon_ies(arr, start, end, mac,    i, elemid, elen, o1, o2, o3, ouitype, svcbase) {
    i = start
    while (i + 1 <= end) {
        elemid = hex2dec(arr[i])
        elen = hex2dec(arr[i + 1])
        if (elemid == 221 && elen >= 5) {   # 0xDD vendor-specific
            o1 = toupper(arr[i + 2]); o2 = toupper(arr[i + 3]); o3 = toupper(arr[i + 4])
            ouitype = hex2dec(arr[i + 5])
            if (o1 == "FA" && o2 == "0B" && o3 == "BC" && ouitype == 13) {
                svcbase = i + 6   # message_counter byte; pack starts right after it
                emit_message_pack("wifi_beacon", mac, arr, svcbase + 1)
            }
        }
        i += 2 + elen
        if (elen == 0) break   # malformed IE, avoid an infinite loop
    }
}

function scan_wifi_nan(arr, start, end, mac,    category, action_code, o1, o2, o3, ouitype, \
                        i, attrid, attrlen, svcid_ok, svcinfolen, svcbase) {
    if (start + 5 > end) return
    category = hex2dec(arr[start])
    action_code = hex2dec(arr[start + 1])
    o1 = toupper(arr[start + 2]); o2 = toupper(arr[start + 3]); o3 = toupper(arr[start + 4])
    ouitype = hex2dec(arr[start + 5])
    if (category != 4 || action_code != 9) return
    if (!(o1 == "50" && o2 == "6F" && o3 == "9A" && ouitype == 19)) return

    i = start + 6
    while (i + 2 <= end) {
        attrid = hex2dec(arr[i])
        attrlen = hex2dec(arr[i + 1]) + hex2dec(arr[i + 2]) * 256
        if (attrid == 3 && attrlen >= 10) {
            svcid_ok = 1
            if (toupper(arr[i + 3]) != "88" || toupper(arr[i + 4]) != "69" || \
                toupper(arr[i + 5]) != "19" || toupper(arr[i + 6]) != "9D" || \
                toupper(arr[i + 7]) != "92" || toupper(arr[i + 8]) != "09") svcid_ok = 0
            if (svcid_ok) {
                svcinfolen = hex2dec(arr[i + 12])
                svcbase = i + 13   # message_counter byte
                if (svcinfolen >= 1) {
                    emit_message_pack("wifi_nan", mac, arr, svcbase + 1)
                }
            }
        }
        if (attrlen == 0) break   # malformed attribute, avoid an infinite loop
        i += 3 + attrlen
    }
}

function process_wifi_packet(    itlen, dot11_start, b0, ftype, stype, sa, body_start, ies_start) {
    if (npkt < 4) return
    itlen = hex2dec(pkt[3]) + hex2dec(pkt[4]) * 256
    dot11_start = 1 + itlen
    if (dot11_start < 1 || dot11_start + 24 - 1 > npkt) return   # not enough for a full mgmt header

    b0 = hex2dec(pkt[dot11_start])
    ftype = int(b0 / 4) % 4
    stype = int(b0 / 16) % 16
    if (ftype != 0) return   # management frames only (tcpdump's "type mgt" filter already ensures this)

    sa = mac_str_dot11(pkt, dot11_start + 10)
    body_start = dot11_start + 24

    if (stype == 8) {            # Beacon
        ies_start = body_start + 12   # skip fixed beacon fields (timestamp+interval+capability)
        if (ies_start <= npkt) scan_wifi_beacon_ies(pkt, ies_start, npkt, sa)
    } else if (stype == 13) {    # Action (public action frames carry NAN)
        if (body_start <= npkt) scan_wifi_nan(pkt, body_start, npkt, sa)
    }
}
