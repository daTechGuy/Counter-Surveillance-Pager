# mesh_wifi_monitor.awk -- generalized WiFi OUI/MAC surveillance-device
# matcher, modeled on colonelpanichacks/Esp32-oui-sniffer's "WiFi Probe"
# detection method ("Source MAC from WiFi management frames (promiscuous
# mode)"). Unlike flock_wifi_monitor.awk, this isn't gated to Probe Requests
# or a wildcard SSID or an exact IE signature -- it matches the transmitter
# MAC of ANY 802.11 management frame against a user-supplied target list
# (mesh_detect_targets.conf), same as the upstream firmware's OUI-prefix and
# full-MAC methods. Its "Device Name" method isn't ported here since WiFi
# management frames don't carry a comparable per-device name field -- that
# part is handled BLE-side, directly in payload.sh (reusing the Flock BLE
# scan's own hcitool lescan output, same as name matching there).
#
# Run as:
#   tcpdump -i wlan0mon -n -l -xx type mgt \
#     | awk -v CONFIG_FILE=mesh_detect_targets.conf \
#           -f rid_common.awk -f mesh_wifi_monitor.awk
#
# Its own tcpdump process, same interface, same reasoning as
# flock_wifi_monitor.awk's header comment: rid_wifi_monitor.awk's rules all
# end in `next`, which would block any rule appended after it via a later
# -f in the same merged awk program, so each WiFi consumer gets its own
# reader rather than being folded into one shared awk invocation. Radiotap-
# stripping / mgmt-header byte offsets are the same ones hardware-verified
# for rid_wifi_monitor.awk (see that file's header).

BEGIN {
    mnpkt = 0
    mstarted = 0
    mesh_have_targets = 0

    if (CONFIG_FILE != "") {
        while ((getline cfgline < CONFIG_FILE) > 0) {
            sub(/#.*/, "", cfgline)
            gsub(/^[ \t]+|[ \t]+$/, "", cfgline)
            if (cfgline == "") continue
            if (cfgline ~ /^[Oo][Uu][Ii]:/) {
                v = tolower(substr(cfgline, 5))
                mesh_oui[v] = 1
                mesh_have_targets = 1
            } else if (cfgline ~ /^[Mm][Aa][Cc]:/) {
                v = tolower(substr(cfgline, 5))
                mesh_mac[v] = 1
                mesh_have_targets = 1
            }
            # name: entries are BLE-only (see file header) -- ignored here.
        }
        close(CONFIG_FILE)
    }
}

/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\./ {
    if (mesh_have_targets && mstarted && mnpkt > 0) process_mesh_packet()
    mstarted = 1
    mnpkt = 0
    next
}

/^[ \t]*0x[0-9A-Fa-f]+:/ {
    if (!mesh_have_targets || !mstarted) next
    line = $0
    sub(/^[ \t]*0x[0-9A-Fa-f]+:[ \t]*/, "", line)
    n = split(line, toks, " ")
    for (k = 1; k <= n; k++) {
        tok = toks[k]
        if (tok ~ /^[0-9A-Fa-f]+$/) {
            tl = length(tok)
            for (p = 1; p <= tl; p += 2) {
                b = substr(tok, p, 2)
                if (length(b) == 2) { mnpkt++; mpkt[mnpkt] = tolower(b) }
            }
        }
    }
    next
}

END {
    if (mesh_have_targets && mstarted && mnpkt > 0) process_mesh_packet()
}

function process_mesh_packet(    itlen, dot11_start, b0, ftype, oui, full_mac, mac, matchkind) {
    if (mnpkt < 4) return
    itlen = hex2dec(mpkt[3]) + hex2dec(mpkt[4]) * 256
    dot11_start = 1 + itlen
    if (dot11_start < 1 || dot11_start + 24 - 1 > mnpkt) return   # not enough for a full mgmt header

    b0 = hex2dec(mpkt[dot11_start])
    ftype = int(b0 / 4) % 4
    if (ftype != 0) return   # management frames only (tcpdump's "type mgt" filter already ensures this)

    oui = mpkt[dot11_start + 10] ":" mpkt[dot11_start + 11] ":" mpkt[dot11_start + 12]
    full_mac = oui ":" mpkt[dot11_start + 13] ":" mpkt[dot11_start + 14] ":" mpkt[dot11_start + 15]

    matchkind = ""
    if (full_mac in mesh_mac) matchkind = "mac:" full_mac
    else if (oui in mesh_oui) matchkind = "oui:" oui
    if (matchkind == "") return

    mac = mac_str_dot11(mpkt, dot11_start + 10)
    print "wifi_mesh|" mac "|" matchkind
    fflush()
}
