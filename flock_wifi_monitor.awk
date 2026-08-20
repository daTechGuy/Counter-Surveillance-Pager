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
# data can grow FLOCK_SIG_KNOWN into a confirmed set over time instead of
# staying one static guess -- already happened once, see
# FLOCK_SIG_FIELD_20260818A below: a second real camera, parked next to at
# close range, turned out to use a signature with a different IE order AND
# set than the original upstream one, not just a minor variation.
#
# DIAGNOSTIC-ONLY LOGGING (added after a session with zero Flock hits at
# all, driving past cameras the user could see): a wildcard-SSID probe from
# an OUI NOT in flock_oui[] below is now also logged, as "wifi_flock_diag"
# lines payload.sh's handle_flock_wifi_diag_line() writes to its own
# separate loot file -- never alerts, never counts as a detection, just a
# field-data trail. See process_flock_packet() for where this branches off
# before the OUI gate.
#
# MANAGEMENT-FRAME OUI MATCHING (field-driven, 2026-08-19, widened further
# 2026-08-20 -- see the follow-up note right after this paragraph): a real drive
# past a known camera produced only 4 wildcard probes total from ANY device
# in 22 minutes, none from a known OUI -- zero Flock hits, but that same day
# a much longer session (4.5hr) at the same OUI list DID produce real
# conf=low hits, so the matching logic itself isn't the problem. The gap is
# that this file only ever looked at Probe Requests, which are sporadic and
# client-initiated -- a camera might send one occasionally, not on any
# guaranteed schedule. mesh_wifi_monitor.awk matches ANY management frame
# (Beacon included, which an AP sends roughly 10x/sec) against its OUI list,
# and that's exactly the mechanism that caught OUI 9c:2f:9d reliably. Ported
# that same idea in here directly, so Flock's own (much larger, 40-entry)
# OUI list benefits too instead of only whatever a user manually copies into
# mesh_detect_targets.conf. Beacon/Probe-Response hits skip the wildcard/IE-
# signature machinery entirely (those fixed-parameter fields differ from a
# Probe Request's and aren't needed for a pure OUI match) and are tiered as
# conf=medium: an OUI match on a periodic frame is real signal, but weaker
# than a wildcard-probe + exact known IE signature (conf=high) since it
# doesn't cross-check the payload contents at all. No diagnostic-log branch
# for non-matching OUIs on this path -- unlike wildcard probes, beacons are
# sent by every AP in range constantly, so logging every unmatched one would
# be pure noise, not a useful field-data trail.
#
# FOLLOW-UP (2026-08-20): the Beacon/Probe-Response restriction above turned
# out to still be too narrow. Parked next to a real, RSSI-confirmed camera
# on OUI 9c:2f:9d, mesh_wifi_monitor.awk (unrestricted to ANY management
# subtype) caught it 3 times with a clean proximity RSSI trend (-49/-39/
# -38dBm as the device got closer) in the same session where THIS file's
# then-Beacon(8)/Probe-Response(5)-only gate matched nothing on that OUI at
# all. Rather than keep guessing which specific subtype(s) a given camera
# model actually uses (already wrong once), the gate now accepts ANY
# management subtype other than Probe Request (which keeps its own
# wildcard/IE-signature path) -- matching mesh_wifi_monitor.awk's already
# field-proven permissive approach directly. The matched line now also
# carries the raw subtype number (stype=N) specifically so future field
# data can show which subtype(s) real cameras actually use, instead of
# staying a guess.
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

    # Known-good IE signatures -- a match against ANY of these earns
    # conf=high; anything else stays conf=low (OUI+wildcard-probe matched,
    # signature didn't) per this file's own field-driven design above.
    # Starts as one guess, grows as real captures come in -- see each
    # entry's own citation.
    FLOCK_SIG_UPSTREAM = "2,12,127,221:506f9a16030103,45,191,221:0050f208000000"
    # ^ flock-you's own original published fingerprint (main.cpp,
    # FLOCK_PROBE_IE_SIG_PRIMARY) -- see this file's header.
    FLOCK_SIG_KNOWN[FLOCK_SIG_UPSTREAM] = 1

    FLOCK_SIG_FIELD_20260818A = "1,50,45,191,255,70,127,221:506f9a16030103"
    # ^ Captured live 2026-08-18: OUI 9c:2f:9d (the Bosch-radio-module OUI
    # already cross-referenced in mesh_detect_targets.conf), RSSI -22 to
    # -31dBm parked directly next to the camera -- unambiguous proximity,
    # not a coincidental nearby device on the same OUI. Different IE order
    # AND set than FLOCK_SIG_UPSTREAM (only "127" and the vendor IE
    # "221:506f9a16030103" are shared) -- confirms different camera
    # hardware/firmware revisions produce genuinely different wildcard-
    # probe signatures, exactly the divergence conf=low + sig= logging
    # exists to surface. This is that captured data, unmodified.
    FLOCK_SIG_KNOWN[FLOCK_SIG_FIELD_20260818A] = 1
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

# True if the first octet's U/L bit (bit 1, i.e. byte value mod 4 >= 2) is
# set -- the standard IEEE-802 "locally administered" bit, set by every MAC-
# randomization scheme (BLE private addresses, WiFi per-scan/per-network
# randomized MACs) and never set on a real vendor-assigned OUI. Added after
# a live diag log came back with ~540 unmatched-OUI entries in 4.5 hours --
# almost entirely ordinary phones' randomized probe-request MACs, which can
# never be a real Flock camera (fixed hardware, factory OUI) and were
# drowning out the small number of entries actually worth reviewing.
# Deliberately checked BEFORE flock_diag_throttle_ok() (and skips it
# entirely, not just silently returning 0 hits) rather than as another
# throttle tier -- a randomized MAC changes every scan/session anyway, so
# "throttled" vs "not" is meaningless for it; there's nothing to throttle,
# it's just not diagnostically useful data at all.
function is_locally_admin_mac(byte0hex,   v) {
    v = hex2dec(byte0hex)
    return (v % 4) >= 2
}

# Same 1st + every-10th pattern as flock_throttle_ok above -- NOT first-
# sighting-only-forever, which is what this used to be. Confirmed live why
# that was wrong: field-testing near two different real cameras on
# 2026-08-19, a real (non-randomized) OUI kept showing up while parked near
# one of them -- but with a first-ever-only throttle, it only logged ONCE
# for the whole session, making it impossible to tell "still here" from
# "already throttled" on a later check without restarting. Losing exactly
# the persistence signal that distinguishes a real lead from one-off noise
# defeated the point. Every-10th still cuts the genuinely high volume of
# ordinary phones/laptops sending wildcard probes, just without going
# permanently silent on a single OUI worth watching.
function flock_diag_throttle_ok(oui) {
    fdiag_count[oui]++
    return (fdiag_count[oui] == 1 || fdiag_count[oui] % 10 == 0)
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
    if (sigA in FLOCK_SIG_KNOWN) return 1
    if (start + 1 <= end && arr[start] == "00" && arr[start + 1] == "00") {
        sigB = flock_build_ie_sig(arr, start + 2, end)
        if (sigB in FLOCK_SIG_KNOWN) return 1
    }
    return 0
}

function process_flock_packet(    itlen, dot11_start, b0, ftype, stype, \
                                   oui, mac, ies_start, r, matched, sig, rssi, rssi_sfx, msgtype) {
    if (fnpkt < 4) return
    itlen = hex2dec(fpkt[3]) + hex2dec(fpkt[4]) * 256
    dot11_start = 1 + itlen
    if (dot11_start < 1 || dot11_start + 24 - 1 > fnpkt) return   # not enough for a full mgmt header

    b0 = hex2dec(fpkt[dot11_start])
    ftype = int(b0 / 4) % 4
    stype = int(b0 / 16) % 16
    # management only: Probe Request (4) gets the full wildcard/IE-sig path
    # below; every OTHER management subtype (Beacon, Probe Response, Auth,
    # Association Response, Action, etc.) gets the OUI-only path -- see
    # this file's header, BEACON / PROBE-RESPONSE MATCHING (now widened to
    # ANY non-Probe-Request management subtype as of 2026-08-20 field data).
    if (ftype != 0) return

    oui = fpkt[dot11_start + 10] ":" fpkt[dot11_start + 11] ":" fpkt[dot11_start + 12]

    if (stype != 4) {
        # Any non-Probe-Request management subtype: pure OUI match, no
        # wildcard/IE-signature concept applies (different fixed-parameter
        # layout per subtype, and several don't even carry an SSID IE at
        # all). Only worth anything against a KNOWN Flock OUI -- see header
        # on why there's no diagnostic-log branch here for unmatched OUIs
        # (unlike wildcard probes, most management subtypes are either rare
        # enough or tied to an existing association that OUI-only logging
        # wouldn't be the noisy firehose a wildcard-probe diagnostic would).
        # Widened from Beacon(8)/Probe-Response(5)-only after live field
        # data (2026-08-20): parked next to a real, RSSI-confirmed camera
        # on OUI 9c:2f:9d, Mesh-Detect's WiFi matcher (which accepts ANY
        # management subtype, no restriction at all) caught it 3x with a
        # clean proximity RSSI trend (-49/-39/-38dBm) while this file's
        # then-Beacon/Probe-Response-only gate matched nothing on that OUI
        # at all in the same session -- rather than keep guessing which
        # specific subtype(s) a given camera model actually uses, matched
        # Mesh-Detect's already-proven permissive approach directly.
        if (!(oui in flock_oui)) return
        mac = mac_str_dot11(fpkt, dot11_start + 10)
        if (!flock_throttle_ok(mac)) return
        rssi = wifi_rssi(fpkt, itlen, fnpkt)
        rssi_sfx = (rssi != 127) ? "|rssi=" rssi : ""
        msgtype = "mgmt_oui_match"
        if (stype == 8) msgtype = "beacon_oui_match"
        else if (stype == 5) msgtype = "probe_resp_oui_match"
        print "wifi_flock|" mac "|" msgtype "|oui=" oui "|conf=medium|stype=" stype rssi_sfx
        fflush()
        return
    }

    ies_start = dot11_start + 24   # Probe Request has no fixed params; IEs follow the header directly

    # Wildcard-probe check now runs BEFORE the OUI gate (moved down from
    # where it used to sit right after that gate) so a wildcard probe from
    # an OUI NOT in flock_oui[] can still be logged diagnostically below,
    # instead of being silently dropped with zero trace. Confirmed live
    # this matters: a session with zero Flock hits at all, driving past
    # cameras the user could see, gave no way to tell "wrong OUI" from
    # "never captured the frame at all" -- this closes that gap.
    r = flock_is_wildcard(fpkt, ies_start, fnpkt)
    if (r == -1 && fnpkt - 4 >= ies_start) r = flock_is_wildcard(fpkt, ies_start, fnpkt - 4)
    if (r != 1) return   # not a wildcard probe at all -- nothing diagnostic to say either

    if (!(oui in flock_oui)) {
        # DIAGNOSTIC ONLY, not a detection: wildcard-SSID probes are common
        # (most phones/laptops send them), so this is expected to be noisy
        # -- never alerts, never counts as a hit, just a field-data trail
        # to review after a drive-by ("what OUI was actually broadcasting
        # near me at the time I remember passing a camera") for growing
        # flock_oui[] above with real evidence instead of a guess. Skips
        # randomized-MAC OUIs entirely first (see is_locally_admin_mac --
        # can't ever be a real camera), then throttles what's left 1st +
        # every-10th per OUI (see flock_diag_throttle_ok()) -- enough to cut
        # the noise from ordinary wildcard-probing phones/laptops without
        # going permanently silent on one worth watching.
        if (is_locally_admin_mac(fpkt[dot11_start + 10])) return
        if (flock_diag_throttle_ok(oui)) {
            mac = mac_str_dot11(fpkt, dot11_start + 10)
            print "wifi_flock_diag|" mac "|oui=" oui
            fflush()
        }
        return
    }

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
