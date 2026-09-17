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
# Run as part of the shared "type mgt" dispatch process now -- see
# wifi_mgt_dispatch.awk, which owns packet reassembly (once, for every
# detector sharing that stream) and calls process_mesh_packet() below once
# per packet, gated on mesh_have_targets the same way the driver rules that
# used to live in this file already gated it. Config variable renamed
# MESH_CONFIG_FILE (was CONFIG_FILE) since deauth_eviltwin_monitor.awk's own
# config file used the same generic name -- harmless as long as each ran in
# its own separate awk process, a real collision once both share one.
#
# mnpkt/mpkt[] below are still this function's own state, just written by
# the shared driver instead of a driver living in this file.

BEGIN {
    mesh_have_targets = 0

    if (MESH_CONFIG_FILE != "") {
        while ((getline cfgline < MESH_CONFIG_FILE) > 0) {
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
        close(MESH_CONFIG_FILE)
    }
}

function process_mesh_packet(    itlen, dot11_start, b0, ftype, oui, full_mac, mac, matchkind, rssi, out) {
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
    rssi = wifi_rssi(mpkt, itlen, mnpkt)
    out = (MESH_HITS_FILE != "") ? MESH_HITS_FILE : "/dev/stdout"
    print "wifi_mesh|" mac "|" matchkind ((rssi != 127) ? "|rssi=" rssi : "") >> out
    fflush()
}
