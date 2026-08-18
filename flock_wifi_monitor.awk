# flock_wifi_monitor.awk -- WiFi wildcard-probe + OUI + IE-signature Flock
# Safety camera detector, run as:
#   tcpdump -i wlan1mon -n -l -xx type mgt | awk -f rid_common.awk -f flock_wifi_monitor.awk
#
# Ports flock-you's current WiFi detection method -- the one that superseded
# its original BLE device-name scan -- onto the Pager's Linux WiFi stack.
# Upstream (colonelpanichacks/flock-you, main.cpp, as of the commit this was
# originally ported from):
#   - 31 target OUIs, matched against the Probe Request transmitter (addr2)
#   - wildcard-SSID (IE tag 0, length 0) Probe Request from a matched OUI
#   - exact match of the remaining IEs against one drive-tested fingerprint
#     ("wifi_wildcard_probe_ie_sig" / FLOCK_PROBE_IE_SIG_PRIMARY upstream)
# See flock-you/main.cpp: target_ouis[], isWildcardProbeIE(),
# fyBuildFlockIeSigFromProbeBody(), FLOCK_PROBE_IE_SIG_PRIMARY. The upstream
# ESP32 code also has a phantom-TLV-overflow workaround for a promiscuous-
# callback buffer quirk specific to that driver -- not ported here, since a
# clean tcpdump/radiotap capture doesn't have that quirk; a malformed TLV
# here just aborts that one signature attempt (see flock_build_ie_sig).
#
# DEVIATION FROM UPSTREAM (field-driven): upstream requires the exact IE
# signature match to fire at all. Confirmed live (drove past real Flock
# cameras, zero hits, zero diagnostic trail) that this is too brittle to be
# the hard gate -- one fingerprint captured from one drive-test doesn't
# necessarily cover every camera model/firmware revision. Detection now
# fires on OUI + wildcard-probe alone; the signature match is reported as a
# confidence tier (conf=high/low) instead of a hard filter, and a
# non-matching hit's actual IE signature is logged (sig=...) so real field
# data can grow FLOCK_SIG_PRIMARY into a confirmed set over time instead of
# staying one static guess.
#
# OUI LIST REFRESH (31 -> 40 entries): flock-you's own main.cpp hadn't yet
# picked up a newer OUI set that colonelpanichacks/oui-spy-unified-blue (his
# own consolidated multi-detector firmware) already had, sourced from
# nitekry/nite-oui-collection's ongoing field-testing tracker
# (groups/flockers/my_tested_flock.md). Cross-checked directly against that
# tracker, not just taken on the fork's word:
#   - REMOVED f8:a2:d6 -- tracker marks it "Removed: Low confidence; hit on
#     Sony Media Player" (false positive).
#   - CONSIDERED AND REJECTED 94:2a:6f, f4:e2:c6 -- tracker marks both
#     "Removed: Nope - Ubiquiti" (false positives). oui-spy-unified-blue's
#     own array still has both, unlike its OUI-list comment claims; the
#     tracker is more current, so they're deliberately left out here.
#   - ADDED, tracker-confirmed: e0:0a:f6 ("Active"), 14:b5:cd ("New finding
#     testing").
#   - ADDED, in both oui-spy-unified-blue's and nite-oui-collection's own
#     live target_ouis[] arrays but NOT yet explicitly confirmed or denied
#     in the curated tracker doc (i.e. same evidentiary tier as several
#     already-existing entries below marked "low confidence" /
#     "WiGLE crowdsource" / "still verifying"): 04:0d:84, f0:82:c0, 1c:34:f1,
#     38:5b:44, 94:34:69, b4:e3:f9, b4:1e:52, d4:11:d6.
#
# Deliberately its OWN tcpdump process rather than a 3rd -f alongside
# rid_wifi_monitor.awk: every one of that file's line rules ends in `next`,
# which (in a single merged awk program) would silently stop any rule
# appended after it -- via a later -f -- from ever running on the same
# line. Splitting into two readers on the same monitor interface avoids
# touching that already hardware-verified file at all. Linux packet sockets
# support multiple simultaneous readers on one interface (e.g. tcpdump and
# Wireshark side by side), so this costs a second, identically-filtered,
# low-rate capture process -- not a second radio.
#
# Radiotap-stripping / mgmt-header byte offsets are the same ones verified
# for rid_wifi_monitor.awk (see that file's header comment) -- same
# tcpdump, same -xx text format, same device.

BEGIN {
    fnpkt = 0
    fstarted = 0

    split("70:c9:4e 3c:91:80 d8:f3:bc 80:30:49 b8:35:32 " \
          "14:5a:fc 74:4c:a1 08:3a:88 9c:2f:9d c0:35:32 " \
          "94:08:53 e4:aa:ea f4:6a:dd 24:b2:b9 " \
          "00:f4:8d d0:39:57 e8:d0:fc e0:4f:43 b8:1e:a4 " \
          "70:08:94 58:8e:81 ec:1b:bd 3c:71:bf 58:00:e3 " \
          "90:35:ea 5c:93:a2 64:6e:69 48:27:ea a4:cf:12 82:6b:f2 " \
          "e0:0a:f6 14:b5:cd " \
          "04:0d:84 f0:82:c0 1c:34:f1 38:5b:44 94:34:69 " \
          "b4:e3:f9 b4:1e:52 d4:11:d6", \
          _flock_ouis, " ")
    for (_flock_i in _flock_ouis) flock_oui[_flock_ouis[_flock_i]] = 1

    FLOCK_SIG_PRIMARY = "2,12,127,221:506f9a16030103,45,191,221:0050f208000000"
}

# Repeat-emission throttle per transmitter MAC, same 1st + every-10th pattern
# as deauth_eviltwin_monitor.awk's -- needed now that a match no longer
# requires the byte-exact signature (see process_flock_packet): a real
# camera sending wildcard probes on its own interval would otherwise get a
# loot-log line (and a physical alert, via payload.sh) every single time.
function flock_throttle_ok(key,    c) {
    fcount[key]++
    c = fcount[key]
    return (c == 1 || c % 10 == 0)
}

/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\./ {
    if (fstarted && fnpkt > 0) process_flock_packet()
    fstarted = 1
    fnpkt = 0
    next
}

/^[ \t]*0x[0-9A-Fa-f]+:/ {
    if (!fstarted) next
    line = $0
    sub(/^[ \t]*0x[0-9A-Fa-f]+:[ \t]*/, "", line)
    n = split(line, toks, " ")
    for (k = 1; k <= n; k++) {
        tok = toks[k]
        if (tok ~ /^[0-9A-Fa-f]+$/) {
            tl = length(tok)
            for (p = 1; p <= tl; p += 2) {
                b = substr(tok, p, 2)
                if (length(b) == 2) { fnpkt++; fpkt[fnpkt] = tolower(b) }
            }
        }
    }
    next
}

END {
    if (fstarted && fnpkt > 0) process_flock_packet()
}

# Returns 1 if the first SSID IE (tag 0) found in [start,end] has length 0
# (wildcard probe), 0 if found with nonzero length (directed probe, not
# ours), -1 if not found before `end` (caller retries with an FCS-trimmed
# end before giving up).
function flock_is_wildcard(arr, start, end,   i, id, elen) {
    i = start
    while (i + 1 <= end) {
        id = hex2dec(arr[i]); elen = hex2dec(arr[i + 1])
        if (i + 2 + elen - 1 > end) return -1
        if (id == 0) return (elen == 0) ? 1 : 0
        i += 2 + elen
    }
    return -1
}

# Comma-joined IE fingerprint over [start,end]: SSID (tag 0) is skipped
# (including a run of empty tag/len pairs), vendor IE 221 is encoded as
# "221:" + up to its first 8 payload bytes in hex, everything else is its
# decimal tag number. Returns "" on any malformed/overflowing TLV -- no
# resync, see file header on why upstream's overflow workaround isn't needed.
function flock_build_ie_sig(arr, start, end,   i, id, elen, sig, part, j, take) {
    i = start
    sig = ""
    while (i + 1 <= end) {
        id = hex2dec(arr[i]); elen = hex2dec(arr[i + 1])
        if (i + 2 + elen - 1 > end) return ""
        i += 2
        if (id == 0) {
            if (elen == 0) {
                while (i + 1 <= end && arr[i] == "00" && arr[i + 1] == "00") i += 2
            } else {
                i += elen
            }
            continue
        }
        if (id == 221 && elen >= 4) {
            take = (elen < 8) ? elen : 8
            part = "221:"
            for (j = 0; j < take; j++) part = part arr[i + j]
        } else {
            part = id ""
        }
        sig = (sig == "") ? part : sig "," part
        i += elen
    }
    return sig
}

# True if either the straight walk from `start`, or the walk starting 2
# bytes in (skipping one leading empty SSID tag/len pair), matches the
# known-good signature -- mirrors upstream's sigA/sigB dual attempt, which
# exists because the leading empty-SSID pair sometimes isn't where a naive
# single walk expects it.
function flock_sig_matches(arr, start, end,   sigA, sigB) {
    sigA = flock_build_ie_sig(arr, start, end)
    if (sigA == FLOCK_SIG_PRIMARY) return 1
    if (start + 1 <= end && arr[start] == "00" && arr[start + 1] == "00") {
        sigB = flock_build_ie_sig(arr, start + 2, end)
        if (sigB == FLOCK_SIG_PRIMARY) return 1
    }
    return 0
}

function process_flock_packet(    itlen, dot11_start, b0, ftype, stype, \
                                   oui, mac, ies_start, r, matched, sig, rssi, rssi_sfx) {
    if (fnpkt < 4) return
    itlen = hex2dec(fpkt[3]) + hex2dec(fpkt[4]) * 256
    dot11_start = 1 + itlen
    if (dot11_start < 1 || dot11_start + 24 - 1 > fnpkt) return   # not enough for a full mgmt header

    b0 = hex2dec(fpkt[dot11_start])
    ftype = int(b0 / 4) % 4
    stype = int(b0 / 16) % 16
    if (ftype != 0 || stype != 4) return   # management/Probe-Request only

    oui = fpkt[dot11_start + 10] ":" fpkt[dot11_start + 11] ":" fpkt[dot11_start + 12]
    if (!(oui in flock_oui)) return

    ies_start = dot11_start + 24   # Probe Request has no fixed params; IEs follow the header directly

    r = flock_is_wildcard(fpkt, ies_start, fnpkt)
    if (r == -1 && fnpkt - 4 >= ies_start) r = flock_is_wildcard(fpkt, ies_start, fnpkt - 4)
    if (r != 1) return

    # OUI + wildcard-probe is now the hard gate; signature is a confidence
    # tier, not a filter -- see file header's DEVIATION FROM UPSTREAM note.
    mac = mac_str_dot11(fpkt, dot11_start + 10)
    if (!flock_throttle_ok(mac)) return

    matched = flock_sig_matches(fpkt, ies_start, fnpkt)
    if (!matched && fnpkt - 4 >= ies_start) matched = flock_sig_matches(fpkt, ies_start, fnpkt - 4)

    rssi = wifi_rssi(fpkt, itlen, fnpkt)
    rssi_sfx = (rssi != 127) ? "|rssi=" rssi : ""

    if (matched) {
        print "wifi_flock|" mac "|wildcard_probe_ie_sig|oui=" oui "|conf=high" rssi_sfx
    } else {
        sig = flock_build_ie_sig(fpkt, ies_start, fnpkt)
        if (sig == "" && fnpkt - 4 >= ies_start) sig = flock_build_ie_sig(fpkt, ies_start, fnpkt - 4)
        if (sig == "") sig = "unparseable"
        gsub(/\|/, ";", sig)   # keep "|" as our own field delimiter in the loot line
        print "wifi_flock|" mac "|wildcard_probe_oui_only|oui=" oui "|conf=low|sig=" sig rssi_sfx
    }
    fflush()
}
