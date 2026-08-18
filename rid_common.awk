# rid_common.awk -- Open Drone ID (ASTM F3411 / ASD-STAN) message decoding,
# shared functions only (no BEGIN/END/main rules -- meant to be loaded via
# `awk -f rid_common.awk -f rid_ble_monitor.awk` / `-f rid_wifi_monitor.awk`).
#
# python3 is not available on this device (mipsel_24kc / ramips, no python3
# package in the configured opkg feeds, 30M flash) -- this is a from-scratch
# reimplementation of the same decode logic in POSIX-ish awk (tested against
# both gawk and this device's busybox awk: index/substr/toupper/sprintf/
# fflush all confirmed present). Byte offsets/scale factors are the same
# ones cited in the original python version, taken from the reference
# implementation: https://github.com/opendroneid/opendroneid-core-c
#   libopendroneid/opendroneid.h  (encoded struct layouts, ODID_MESSAGETYPE_*)
#   libopendroneid/opendroneid.c  (LATLON_MULT, ALT_DIV, ALT_ADDER, SPEED_DIV)
#   libopendroneid/odid_wifi.h/.c (vendor IE / NAN OUIs and structure)
# https://github.com/opendroneid/transmitter-linux/blob/main/bluetooth.c
#   (BLE legacy advertising Service Data layout: UUID 0xFFFA / AppCode 0x0D)
#
# All byte arrays here are awk arrays of 2-character hex-string tokens,
# 1-INDEXED (arr[1] is the first byte). A "base" parameter to a decode_*
# function is the 1-indexed array position of that message's byte 0.

function hex2dec(h,    i, c, v, n) {
    n = 0
    h = toupper(h)
    for (i = 1; i <= length(h); i++) {
        c = substr(h, i, 1)
        v = index("0123456789ABCDEF", c) - 1
        if (v < 0) v = 0
        n = n * 16 + v
    }
    return n
}

function sign8(v) {
    if (v >= 128) return v - 256
    return v
}

function sign32(v) {
    if (v >= 2147483648) return v - 4294967296
    return v
}

# Little-endian multi-byte reads. i = 1-indexed position of the field's
# first (least-significant) byte.
function le_u16(arr, i) {
    return hex2dec(arr[i]) + hex2dec(arr[i + 1]) * 256
}

function le_u32(arr, i) {
    return hex2dec(arr[i]) + hex2dec(arr[i + 1]) * 256 \
         + hex2dec(arr[i + 2]) * 65536 + hex2dec(arr[i + 3]) * 16777216
}

function le_i32(arr, i) {
    return sign32(le_u32(arr, i))
}

# Keep only a conservative printable-ASCII allowlist, replacing anything
# else (including '|' and ';', deliberately excluded from the allowlist)
# with '_'. This data comes from an untrusted RF broadcast and gets
# embedded in our own pipe/semicolon-delimited hit-line format that
# payload.sh's bash loop parses and logs, so anything that could corrupt
# that format or inject into a downstream LOG call is neutralized here,
# at the point of decode, rather than trusted to be well-behaved.
function sanitize(s,    i, c, out, allowed) {
    allowed = " !\"#$%&'()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{}~"
    out = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (index(allowed, c) > 0) out = out c
        else out = out "_"
    }
    return out
}

# Decode `len` consecutive hex-byte tokens starting at arr[start] as a
# NUL-terminated ASCII field.
function ascii_from_hex(arr, start, len,    i, v, s) {
    s = ""
    for (i = 0; i < len; i++) {
        v = hex2dec(arr[start + i])
        if (v == 0) break
        if (v >= 32 && v < 127) s = s sprintf("%c", v)
        else s = s "?"
    }
    return sanitize(s)
}

function msg_type_name(t) {
    if (t == 0) return "basic_id"
    if (t == 1) return "location"
    if (t == 2) return "auth"
    if (t == 3) return "self_id"
    if (t == 4) return "system"
    if (t == 5) return "operator_id"
    if (t == 15) return "message_pack"
    return "type_" t
}

function ua_type_name(t) {
    if (t == 0) return "None/Not_declared"
    if (t == 1) return "Aeroplane/Fixed-wing"
    if (t == 2) return "Helicopter/Multirotor"
    if (t == 3) return "Gyroplane"
    if (t == 4) return "Hybrid_VTOL"
    if (t == 5) return "Ornithopter"
    if (t == 6) return "Glider"
    if (t == 7) return "Kite"
    if (t == 8) return "Free_Balloon"
    if (t == 9) return "Captive_Balloon"
    if (t == 10) return "Airship"
    if (t == 11) return "Free_Fall/Parachute"
    if (t == 12) return "Rocket"
    if (t == 13) return "Tethered_powered_aircraft"
    if (t == 14) return "Ground_Obstacle"
    return "Other"
}

function decode_basic_id(arr, base,    b1, ua, idt, uasid) {
    b1 = hex2dec(arr[base + 1])
    ua = b1 % 16
    idt = int(b1 / 16) % 16
    uasid = ascii_from_hex(arr, base + 2, 20)
    return sprintf("ua_type=%s;id_type=%d;uas_id=%s", ua_type_name(ua), idt, uasid)
}

function decode_location(arr, base,    flags, speed_mult, ew_dir, status, \
                          dir_raw, sh_raw, sv_raw, lat_raw, lon_raw, \
                          altb_raw, altg_raw, h_raw, direction, speed_h, \
                          speed_v, alt_baro, alt_geo, height, out) {
    flags = hex2dec(arr[base + 1])
    speed_mult = flags % 2
    ew_dir = int(flags / 2) % 2
    status = int(flags / 16) % 16
    dir_raw = hex2dec(arr[base + 2])
    sh_raw = hex2dec(arr[base + 3])
    sv_raw = sign8(hex2dec(arr[base + 4]))
    lat_raw = le_i32(arr, base + 5)
    lon_raw = le_i32(arr, base + 9)
    altb_raw = le_u16(arr, base + 13)
    altg_raw = le_u16(arr, base + 15)
    h_raw = le_u16(arr, base + 17)

    if (ew_dir) direction = dir_raw + 180
    else direction = dir_raw
    if (speed_mult) speed_h = (sh_raw * 0.75) + (255 * 0.25)
    else speed_h = sh_raw * 0.25
    speed_v = sv_raw * 0.5
    alt_baro = altb_raw * 0.5 - 1000
    alt_geo = altg_raw * 0.5 - 1000
    height = h_raw * 0.5 - 1000

    out = sprintf("status=%d;direction_deg=%.1f;speed_h_mps=%.2f;speed_v_mps=%.2f;alt_baro_m=%.1f;alt_geo_m=%.1f;height_m=%.1f", \
                  status, direction, speed_h, speed_v, alt_baro, alt_geo, height)
    if (lat_raw != 0 || lon_raw != 0) {
        out = out sprintf(";lat=%.7f;lon=%.7f", lat_raw / 10000000.0, lon_raw / 10000000.0)
    }
    return out
}

function decode_system(arr, base,    b1, class_type, oplat_raw, oplon_raw, \
                        opaltgeo_raw, opaltgeo, out) {
    b1 = hex2dec(arr[base + 1])
    class_type = int(b1 / 4) % 8
    oplat_raw = le_i32(arr, base + 2)
    oplon_raw = le_i32(arr, base + 6)
    opaltgeo_raw = le_u16(arr, base + 18)
    opaltgeo = opaltgeo_raw * 0.5 - 1000
    out = sprintf("classification_type=%d;operator_alt_geo_m=%.1f", class_type, opaltgeo)
    if (oplat_raw != 0 || oplon_raw != 0) {
        out = out sprintf(";operator_lat=%.7f;operator_lon=%.7f", oplat_raw / 10000000.0, oplon_raw / 10000000.0)
    }
    return out
}

function decode_operator_id(arr, base,    idtype, opid) {
    idtype = hex2dec(arr[base + 1])
    opid = ascii_from_hex(arr, base + 2, 20)
    return sprintf("operator_id_type=%d;operator_id=%s", idtype, opid)
}

function decode_self_id(arr, base,    dtype, desc) {
    dtype = hex2dec(arr[base + 1])
    desc = ascii_from_hex(arr, base + 2, 23)
    return sprintf("desc_type=%d;desc=%s", dtype, desc)
}

function decode_auth(arr, base,    b1) {
    b1 = hex2dec(arr[base + 1])
    return sprintf("auth_type=%d;data_page=%d", int(b1 / 16) % 16, b1 % 16)
}

function msg_type_of(arr, base) {
    return msg_type_name(int(hex2dec(arr[base]) / 16) % 16)
}

function decode_message_fields(arr, base,    t) {
    t = int(hex2dec(arr[base]) / 16) % 16
    if (t == 0) return decode_basic_id(arr, base)
    if (t == 1) return decode_location(arr, base)
    if (t == 2) return decode_auth(arr, base)
    if (t == 3) return decode_self_id(arr, base)
    if (t == 4) return decode_system(arr, base)
    if (t == 5) return decode_operator_id(arr, base)
    return ""
}

# Emit one "SRC|MAC|MSG_TYPE|k=v;k=v;..." hit line, optionally with a
# trailing "|rssi=N" -- same format the bash driver's handle_rid_line()
# already parses (its $kv just absorbs the extra segment as trailing text,
# same as flock_wifi_monitor.awk's conf=/sig= fields), so payload.sh needed
# no changes on the consuming side. `rssi` is an optional 5th argument --
# existing 4-argument call sites (rid_wifi_monitor.awk, which has no RSSI
# to give; emit_message_pack below) are unaffected and get no rssi suffix.
# 127 is the Bluetooth spec's own "not available" sentinel -- suppressed
# here rather than printed, same reasoning as GPS_TAG staying empty on no
# fix instead of printing "gps=0,0".
function emit_hit(src, mac, arr, base, rssi,    mtype, fields) {
    mtype = msg_type_of(arr, base)
    fields = decode_message_fields(arr, base)
    print src "|" mac "|" mtype "|" fields ((rssi != "" && rssi != 127) ? "|rssi=" rssi : "")
    fflush()
}

# ODID_MessagePack_encoded: header(1) + SingleMessageSize(1) + MsgPackSize(1)
# + up to 9x 25-byte messages. base = 1-indexed position of the header byte.
# rssi is optional (5th arg) and just passed through to each emit_hit() call.
function emit_message_pack(src, mac, arr, base, rssi,    single_size, pack_size, i, msg_base) {
    single_size = hex2dec(arr[base + 1])
    if (single_size == 0) single_size = 25
    pack_size = hex2dec(arr[base + 2])
    if (pack_size > 9) pack_size = 9
    msg_base = base + 3
    for (i = 0; i < pack_size; i++) {
        emit_hit(src, mac, arr, msg_base, rssi)
        msg_base += single_size
    }
}

# 802.11 addresses print in transmission order (no reversal).
function mac_str_dot11(arr, base,    i, s) {
    s = toupper(arr[base])
    for (i = 1; i <= 5; i++) s = s ":" toupper(arr[base + i])
    return s
}

# HCI transmits BD_ADDR least-significant-octet first; reverse for the
# conventional AA:BB:CC:DD:EE:FF display form (matches hcitool/bluetoothctl).
function mac_str_ble(arr, base,    i, s) {
    s = toupper(arr[base + 5])
    for (i = 4; i >= 0; i--) s = s ":" toupper(arr[base + i])
    return s
}

# Sums Length_Data[0..nreports-1] -- the total adv-data bytes across every
# report in one HCI LE Advertising Report event. Added to that event's
# initial adv_start, this gives the offset where the trailing per-report
# RSSI byte array begins (Bluetooth Core Spec Vol 4 Part E 7.7.65.2's
# "structure of arrays" layout: ..., Length_Data[N], Data (concatenated),
# RSSI[N] -- see rid_ble_monitor.awk's header for the fuller citation).
# Shared here since rid_ble_monitor.awk, rogue_tracker_monitor.awk, and
# flock_ble_monitor.awk each walk this same event layout independently.
function ble_total_adv_len(arr, len_start, nreports,    r, total) {
    total = 0
    for (r = 0; r < nreports; r++) total += hex2dec(arr[len_start + r])
    return total
}

# Signed RSSI in dBm for report index r (0-based) once rssi_start (=
# adv_start + ble_total_adv_len(...)) is known, or 127 -- the spec's own
# "value not available" sentinel -- if the capture is truncated and doesn't
# actually contain that byte.
function ble_rssi_for(arr, rssi_start, r, pkt_len) {
    if (rssi_start + r > pkt_len) return 127
    return sign8(hex2dec(arr[rssi_start + r]))
}

# WiFi RSSI (radiotap Antenna Signal, dBm) -- deliberately NOT a general
# radiotap present-flags walk: this device's driver was confirmed live
# (11 real captures, cross-checked byte-for-byte against tcpdump's own
# decoded "-NNdBm signal" line for every single one) to always emit a
# radiotap header in the same fixed 56-byte layout already relied on
# everywhere in this project for dot11_start (itlen==56), and within that
# fixed layout, 0-indexed byte offset 30 is always the Antenna Signal
# field. Deliberately does NOT try to be correct for any other itlen --
# an itlen this project has never actually seen from this hardware would
# mean a different, unconfirmed field layout, and guessing at that is
# worse than just not reporting RSSI: returns 127 (same "not available"
# sentinel as ble_rssi_for()) for anything other than the confirmed case.
function wifi_rssi(arr, itlen, pkt_len) {
    if (itlen != 56) return 127
    if (31 > pkt_len) return 127
    return sign8(hex2dec(arr[31]))
}
