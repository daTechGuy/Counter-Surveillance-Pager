# flock_wifi_addr1_monitor.awk -- detects a Flock camera by its OUI
# appearing as addr1 (the RECEIVER address) on ordinary 802.11 Data frames
# sent BY OTHER DEVICES, run as:
#   tcpdump -i wlan1mon -n -l -xx type data | awk -f rid_common.awk -f flock_wifi_addr1_monitor.awk
#
# UNVERIFIED TECHNIQUE, no reference implementation cross-checked (unlike
# flock_wifi_monitor.awk's OUI list, which was cross-checked against
# multiple independent sources -- see that file's header): sourced from a
# secondhand writeup (simeononsecurity.com's "Flock Finder" article,
# 2026-08-19) crediting a technique to "@NitekryDPaul" with no linked
# source code or original writeup found. Building this anyway because the
# mechanism itself is straightforward 802.11 and doesn't require trusting
# the source's OUI list or any camera-specific claim, just the general
# idea: a camera that never transmits anything itself (flock_wifi_monitor.
# awk's entire Probe-Request/Beacon/Probe-Response approach depends on the
# camera transmitting SOMETHING) can still be caught if some OTHER nearby
# device -- its own AP, an associated client -- addresses a Data frame TO
# it, since addr1 (the receiver address) is unencrypted plaintext in the
# 802.11 MAC header even when the frame body itself is encrypted.
#
# Why this needs its own tcpdump process/filter (type data) rather than
# folding into flock_wifi_monitor.awk: that file's own tcpdump reader is
# filtered to `type mgt` specifically because Probe Request/Beacon/Probe-
# Response are all management frames -- widening that filter to also catch
# data frames would multiply the packet volume through code that doesn't
# need any of them. Same "own reader" reasoning as every other WiFi
# detector already sharing this monitor-mode interface -- see
# flock_wifi_monitor.awk's header for why (rid_wifi_monitor.awk's `next`-
# terminated rules would block anything appended after them in one merged
# awk program either way).
#
# False-positive reasoning: addr1 on a broadcast/multicast Data frame is
# ff:ff:ff:ff:ff:ff or a multicast address, neither of which can
# coincidentally collide with one of the specific unicast vendor OUIs
# below, so a match here means some real nearby device really did address
# a unicast frame at a MAC starting with a known Flock OUI -- not proof
# that device IS a camera (OUI reuse / a coincidental other device on the
# same vendor block is possible, same caveat as the transmitter-side OUI
# list), but not random noise either.
#
# Radiotap-stripping / mgmt-header byte offsets are the same ones verified
# for rid_wifi_monitor.awk (see that file's header) -- addr1 sits at the
# same fixed byte offset (4) in a Data frame's header as it does in every
# other 802.11 frame type that carries one.

BEGIN {
    a1npkt = 0
    a1started = 0

    # Same OUI list as flock_wifi_monitor.awk's flock_oui[] -- duplicated
    # rather than shared since these run as separate awk processes (own
    # tcpdump reader each, see header above), not because the list itself
    # should ever be allowed to drift between the two. Keep in sync with
    # flock_wifi_monitor.awk's BEGIN block if that list changes.
    split("70:c9:4e 3c:91:80 d8:f3:bc 80:30:49 b8:35:32 " \
          "14:5a:fc 74:4c:a1 08:3a:88 9c:2f:9d c0:35:32 " \
          "94:08:53 e4:aa:ea f4:6a:dd 24:b2:b9 " \
          "00:f4:8d d0:39:57 e8:d0:fc e0:4f:43 b8:1e:a4 " \
          "70:08:94 58:8e:81 ec:1b:bd 3c:71:bf 58:00:e3 " \
          "90:35:ea 5c:93:a2 64:6e:69 48:27:ea a4:cf:12 82:6b:f2 " \
          "e0:0a:f6 14:b5:cd " \
          "04:0d:84 f0:82:c0 1c:34:f1 38:5b:44 94:34:69 " \
          "b4:e3:f9 b4:1e:52 d4:11:d6", \
          _flock_ouis_a1, " ")
    for (_a1_i in _flock_ouis_a1) flock_oui_a1[_flock_ouis_a1[_a1_i]] = 1
}

# Same 1st + every-10th throttle pattern as flock_wifi_monitor.awk's
# flock_throttle_ok() -- own state, own process, can't share a counter
# array across two separate awk processes anyway.
function a1_throttle_ok(key,    c) {
    a1count[key]++
    c = a1count[key]
    return (c == 1 || c % 10 == 0)
}

/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\./ {
    if (a1started && a1npkt > 0) process_addr1_packet()
    a1started = 1
    a1npkt = 0
    next
}

/^[ \t]*0x[0-9A-Fa-f]+:/ {
    if (!a1started) next
    line = $0
    sub(/^[ \t]*0x[0-9A-Fa-f]+:[ \t]*/, "", line)
    n = split(line, toks, " ")
    for (k = 1; k <= n; k++) {
        tok = toks[k]
        if (tok ~ /^[0-9A-Fa-f]+$/) {
            tl = length(tok)
            for (p = 1; p <= tl; p += 2) {
                b = substr(tok, p, 2)
                if (length(b) == 2) { a1npkt++; a1pkt[a1npkt] = tolower(b) }
            }
        }
    }
    next
}

END {
    if (a1started && a1npkt > 0) process_addr1_packet()
}

function process_addr1_packet(    itlen, dot11_start, b0, ftype, oui, mac, rssi, rssi_sfx) {
    if (a1npkt < 4) return
    itlen = hex2dec(a1pkt[3]) + hex2dec(a1pkt[4]) * 256
    dot11_start = 1 + itlen
    if (dot11_start < 1 || dot11_start + 24 - 1 > a1npkt) return   # not enough for a full header

    b0 = hex2dec(a1pkt[dot11_start])
    ftype = int(b0 / 4) % 4
    if (ftype != 2) return   # Data frames only -- see header

    # addr1 (receiver address) starts right after Frame Control (2 bytes)
    # + Duration/ID (2 bytes), i.e. byte offset 4 -- same fixed position
    # regardless of Data-frame subtype/QoS variant.
    oui = a1pkt[dot11_start + 4] ":" a1pkt[dot11_start + 5] ":" a1pkt[dot11_start + 6]
    if (!(oui in flock_oui_a1)) return

    mac = mac_str_dot11(a1pkt, dot11_start + 4)
    if (!a1_throttle_ok(mac)) return

    rssi = wifi_rssi(a1pkt, itlen, a1npkt)
    rssi_sfx = (rssi != 127) ? "|rssi=" rssi : ""
    print "wifi_flock|" mac "|addr1_receiver_oui|oui=" oui "|conf=medium" rssi_sfx
    fflush()
}
