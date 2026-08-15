# deauth_eviltwin_monitor.awk -- WiFi deauth/disassoc flood detector +
# rogue "evil twin" AP detector. Run as:
#   tcpdump -i wlan1mon -n -l -xx type mgt \
#     | awk -v CONFIG_FILE=trusted_networks.conf \
#           -f rid_common.awk -f deauth_eviltwin_monitor.awk
#
# TWO UNRELATED CHECKS SHARING ONE READER, both attack-in-progress signals
# rather than passive-presence signals like Flock/Mesh-Detect:
#
#   Deauth/disassoc flood: counts Deauthentication (subtype 12) and
#   Disassociation (subtype 10) management frames per transmitter MAC. A
#   single deauth is normal WiFi churn (a real client actually
#   disconnecting); a rapid burst from one source is the signature of an
#   active deauth attack (aireplay-ng, mdk4, ESP32 "deauther" boards, etc.)
#   -- either to force a target off their real AP toward a rogue one, or
#   pure harassment/DoS. This file only counts and emits a running total
#   per source (throttled, see below); the actual "is this a flood right
#   now" rate decision needs wall-clock time and lives in payload.sh's
#   handle_deauth_line(), same reasoning as rogue_tracker_monitor.awk's
#   persistence logic: busybox awk's systime() support is unconfirmed on
#   this device, bash's `date` is already relied on elsewhere.
#
#   Evil-twin AP: matches Beacon frame SSIDs against trusted_networks.conf.
#   A beacon advertising a trusted SSID name from a BSSID NOT in that
#   name's configured list is flagged -- someone broadcasting your home/
#   work WiFi's name to get your devices to auto-connect to them instead.
#   Probe Response frames (which also carry SSID+BSSID) aren't checked
#   here, only Beacon -- Beacon is the continuous, always-on signal; Probe
#   Response only happens in reply to an active probe, less coverage for
#   comparable complexity. Documented gap, not an oversight.
#
# Own tcpdump process, same interface, same reasoning as flock_wifi_monitor.awk
# / mesh_wifi_monitor.awk's headers: rid_wifi_monitor.awk's rules end in
# `next`, so this isn't a 4th -f on that pipeline. Radiotap-stripping /
# mgmt-header byte offsets are the same ones hardware-verified for
# rid_wifi_monitor.awk (see that file's header).

BEGIN {
    dnpkt = 0
    dstarted = 0

    if (CONFIG_FILE != "") {
        while ((getline cfgline < CONFIG_FILE) > 0) {
            sub(/#.*/, "", cfgline)
            gsub(/^[ \t]+|[ \t]+$/, "", cfgline)
            if (cfgline == "") continue
            if (cfgline ~ /^[Tt][Rr][Uu][Ss][Tt][Ee][Dd]:/) {
                rest = substr(cfgline, 9)             # strip "trusted:"
                pipepos = index(rest, "|")
                if (pipepos > 0) {
                    ssid = substr(rest, 1, pipepos - 1)
                    bssid = tolower(substr(rest, pipepos + 1))
                    trusted[ssid, bssid] = 1
                    has_trusted_ssid[ssid] = 1
                }
            }
        }
        close(CONFIG_FILE)
    }
    HAVE_TRUSTED = 0
    for (_k in has_trusted_ssid) { HAVE_TRUSTED = 1; break }
}

/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\./ {
    if (dstarted && dnpkt > 0) process_deauth_packet()
    dstarted = 1
    dnpkt = 0
    next
}

/^[ \t]*0x[0-9A-Fa-f]+:/ {
    if (!dstarted) next
    line = $0
    sub(/^[ \t]*0x[0-9A-Fa-f]+:[ \t]*/, "", line)
    n = split(line, toks, " ")
    for (k = 1; k <= n; k++) {
        tok = toks[k]
        if (tok ~ /^[0-9A-Fa-f]+$/) {
            tl = length(tok)
            for (p = 1; p <= tl; p += 2) {
                b = substr(tok, p, 2)
                if (length(b) == 2) { dnpkt++; dpkt[dnpkt] = tolower(b) }
            }
        }
    }
    next
}

END {
    if (dstarted && dnpkt > 0) process_deauth_packet()
}

# Emit on the 1st sighting of a key, then every 10th after that -- a
# packet-count throttle (not time-based, see file header), chosen deliberately
# shorter than rogue_tracker_monitor.awk's every-50th: a real flood needs
# frequent updates for payload.sh's rate math to react promptly, and an
# isolated single deauth (the common, non-attack case) only ever emits once.
function deauth_throttle_ok(key,    c) {
    dcount[key]++
    c = dcount[key]
    return (c == 1 || c % 10 == 0)
}

# Walk 802.11 IEs from `start` to `end` looking for the SSID element (tag 0).
# Returns the ASCII SSID string, or "" if not found / zero-length (wildcard/
# hidden SSID beacons aren't useful for trusted-name matching anyway).
function extract_ssid(arr, start, end,    i, id, elen) {
    i = start
    while (i + 1 <= end) {
        id = hex2dec(arr[i]); elen = hex2dec(arr[i + 1])
        if (i + 2 + elen - 1 > end) return ""
        if (id == 0) {
            if (elen == 0) return ""
            return ascii_from_hex(arr, i + 2, elen)
        }
        i += 2 + elen
    }
    return ""
}

function process_deauth_packet(    itlen, dot11_start, b0, ftype, stype, \
                                    src, dst, bssid, ies_start, ssid, key, subtype_name) {
    if (dnpkt < 4) return
    itlen = hex2dec(dpkt[3]) + hex2dec(dpkt[4]) * 256
    dot11_start = 1 + itlen
    if (dot11_start < 1 || dot11_start + 24 - 1 > dnpkt) return   # not enough for a full mgmt header

    b0 = hex2dec(dpkt[dot11_start])
    ftype = int(b0 / 4) % 4
    stype = int(b0 / 16) % 16
    if (ftype != 0) return   # management frames only (tcpdump's "type mgt" filter already ensures this)

    if (stype == 12 || stype == 10) {                # Deauth / Disassoc
        src = mac_str_dot11(dpkt, dot11_start + 10)   # addr2: transmitter
        dst = mac_str_dot11(dpkt, dot11_start + 4)    # addr1: destination
        subtype_name = (stype == 12) ? "deauth" : "disassoc"
        key = src
        if (deauth_throttle_ok(key)) {
            print "deauth|" src "|" dst "|" subtype_name "|" dcount[key]
            fflush()
        }
        return
    }

    if (stype == 8 && HAVE_TRUSTED) {                 # Beacon -- only bother if config has entries
        bssid = mac_str_dot11(dpkt, dot11_start + 16)   # addr3: BSSID
        ies_start = dot11_start + 24 + 12               # skip fixed beacon fields
        if (ies_start > dnpkt) return
        ssid = extract_ssid(dpkt, ies_start, dnpkt)
        if (ssid == "" || !((ssid) in has_trusted_ssid)) return
        if ((ssid, tolower(bssid)) in trusted) return   # known-good BSSID for this SSID
        key = ssid "|" tolower(bssid)
        if (deauth_throttle_ok(key)) {
            print "eviltwin|" bssid "|" ssid "|rogue_bssid"
            fflush()
        }
    }
}
