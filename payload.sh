#!/bin/bash
# Title: Counter-Surveillance-Pager - Flock + Mesh-Detect + Drone Remote ID
#   (formerly Flock-Sky-Spy -- renamed once scope grew past just Flock/drones)
# Description: Flock Safety surveillance device detector -- BLE device-name
#              scanning (unmodified logic from Flock-You / Flock_Detect) PLUS
#              a port of flock-you's current WiFi method (OUI-gated
#              wildcard-SSID Probe Request + IE fingerprint, with the same
#              11/6/1 channel hop flock-you uses), since flock-you's main
#              branch moved to WiFi as its primary detection path and the
#              BLE name scan alone was found to miss cameras -- PLUS a
#              generalized BLE+WiFi OUI/MAC/name surveillance-device matcher
#              modeled on Esp32-oui-sniffer (part of the mesh-detect hardware
#              family), config-driven via mesh_detect_targets.conf since that
#              firmware's target list is itself user-configured (there's no
#              baked-in list to port) -- watchlist now also covers smart
#              glasses/AR wearables (Vuzix, Snap Spectacles, Ray-Ban Meta by
#              name; see mesh_detect_targets.conf's own header for why Meta/
#              Amazon/Razer's OUIs are TIER 2, opt-in, not active by default)
#              -- PLUS an experimental, explicitly UNVERIFIED BLE signature
#              for Flock cameras (16-bit Service UUID 0x09C8, see
#              flock_ble_monitor.awk's header) -- combined with an Open Drone ID
#              (ASTM F3411) detector covering all three broadcast transports:
#              BLE legacy advertising, WiFi Beacon, and WiFi NAN -- ported
#              from the Sky-Spy ESP32 firmware's detection approach onto the
#              Pager's Linux BLE/WiFi stack, since no Linux/bash build of
#              Sky-Spy exists upstream.
# Credit: All detection concepts this payload combines originate with
#   colonelpanichacks (Colonel Panic):
#   - Flock-You (https://github.com/colonelpanichacks/flock-you) -- the BLE
#     scan loop and name-match logic (unmodified), and the WiFi OUI list /
#     wildcard-probe / IE-fingerprint algorithm (ported to awk/bash for this
#     device's Linux WiFi stack -- see flock_wifi_monitor.awk header for
#     exactly what was ported and why phantom-TLV handling was dropped).
#   - Sky-Spy (https://github.com/colonelpanichacks/Sky-Spy) -- the drone
#     Remote ID detection *approach* this payload ports. Sky-Spy itself is
#     ESP32 firmware with no Linux build, so the port is a from-scratch
#     reimplementation against the ASTM F3411 spec -- see rid_common.awk for
#     exactly what was reimplemented and why.
#   - mesh-detect / Esp32-oui-sniffer (https://github.com/colonelpanichacks/mesh-detect,
#     https://github.com/colonelpanichacks/Esp32-oui-sniffer) -- the
#     BLE-name / OUI-prefix / full-MAC surveillance-device detection
#     *methods* this payload's generic matcher ports (see
#     mesh_wifi_monitor.awk and mesh_detect_targets.conf headers). NOT
#     ported: mesh-detect's Meshtastic LoRa alert relay (needs LoRa hardware
#     this device doesn't have).
#   All credit for the underlying detection concepts and the original
#   Flock-You code belongs to Colonel Panic; this payload is a derivative work.
# Rogue BLE tracker detection (rogue_tracker_monitor.awk) is NOT a Colonel
# Panic port -- it's new here, structurally matching Apple Find My / Tile /
# Samsung SmartTag / Google Find My Device Network beacons (all engineered
# to defeat static OUI/MAC watchlists like Mesh-Detect's, via rotating
# addresses -- see that file's header for exactly why this needed a
# different detection approach). Byte-level formats sourced from and
# verified against: seemoo-lab/openhaystack (Apple), Heinrich et al.'s
# "Privacy Analysis of Samsung's Crowd-Sourced Bluetooth Location Tracking
# System" (arXiv:2210.14702) plus community reverse-engineering (Samsung,
# Tile), and Google's own public Find Hub Network Accessory Specification
# (FMDN). See rogue_tracker_monitor.awk's header for exact citations
# and what wasn't decoded.
# Deauth-flood + evil-twin AP detection (deauth_eviltwin_monitor.awk) is
# also NOT a port -- standard, widely-documented WiFi attack signatures
# (repeated Deauthentication/Disassociation frames; a Beacon advertising a
# known SSID from an unrecognized BSSID), not something needing a specific
# upstream reference implementation the way the tracker protocols did. See
# that file's header for the detection logic and trusted_networks.conf's
# header for the evil-twin config format.
# Original Flock-You Contributors: colonelpanichacks, Claude (Anthropic), Grok (xAI), Brandon Starkweather
# Remote ID spec/byte-offset sources (see rid_common.awk header for citations):
#   opendroneid/opendroneid-core-c, opendroneid/transmitter-linux
# Category: Reconnaissance
#
# The Remote ID decoders and the WiFi Flock/mesh detectors are plain
# POSIX-ish awk (rid_common.awk + rid_ble_monitor.awk + rid_wifi_monitor.awk
# + flock_wifi_monitor.awk + mesh_wifi_monitor.awk), not python3: this
# device (mipsel_24kc / ramips, 30M flash) has no python3 in its opkg feeds
# at all, confirmed live against the actual hardware -- awk was confirmed
# present with the specific functions needed
# (index/substr/toupper/sprintf/fflush/getline-from-file).
# The Remote ID awk parsers were verified against this exact device's real
# hcidump 5.72 / tcpdump 4.99.5 text-output formats, including hand-decoding
# a real capture byte-by-byte to confirm the framing, before being wired in
# here. flock_wifi_monitor.awk and mesh_wifi_monitor.awk reuse that same
# verified tcpdump -xx framing; their detection logic itself was validated
# against synthetic packets (matching + non-matching cases for each), not
# yet against real camera/device captures -- see KNOWN LIMITATIONS.
#
# ============================================================================
# REQUIRES, PER DETECTOR (each is independently optional -- missing tools
# just disable that one piece and are reported at startup, everything else
# still runs):
#   Flock BLE scan    : hciconfig, hcitool               (stock on Flock-You)
#   Flock WiFi scan    : + awk, iw, tcpdump, a second radio (phy1/wlan1mon)
#                        -- shares its capture radio/channel-hop with Drone
#                        WiFi scan
#   Mesh-Detect BLE scan: none beyond Flock BLE scan above -- reuses its
#                        hcitool lescan output, only runs once
#                        mesh_detect_targets.conf has an oui:/mac:/name: entry
#   Mesh-Detect WiFi scan: + awk, iw, tcpdump, a second radio (phy1/wlan1mon)
#                        -- same shared radio/channel-hop, only runs once
#                        mesh_detect_targets.conf has an oui:/mac: entry
#   Rogue tracker BLE scan: + awk, hcidump (own reader, alongside Drone BLE
#                        scan's) -- no config needed to be active, but see
#                        tracker_allowlist.conf re: your own trackers
#   Flock BLE UUID scan: + awk, hcidump (own reader, alongside the above) --
#                        UNVERIFIED signature (16-bit Service UUID 0x09C8),
#                        see flock_ble_monitor.awk's header. No config needed
#                        to be active.
#   Smart-glasses BLE scan: + awk, hcidump (own reader, alongside the above)
#                        -- UNVERIFIED company-ID signatures (Meta Ray-Ban/
#                        Snap Spectacles/Bose Frames/Vuzix/XREAL), see
#                        glasses_ble_monitor.awk's header. Own menu toggle
#                        (WANT_GLASSES) -- mesh_detect_targets.conf's own
#                        glasses OUI/name entries are still separately
#                        covered under WANT_MESH regardless of this one.
#   Drone BLE scan    : + awk, hcidump
#   Drone WiFi scan   : + awk, iw, tcpdump, a second radio (phy1/wlan1mon)
#   Deauth flood scan : + awk, iw, tcpdump, a second radio (phy1/wlan1mon)
#                        -- same shared radio/channel-hop, works standalone,
#                        no config needed
#   Evil-twin AP scan : same as deauth flood (same detector file/process) --
#                        no-op until trusted_networks.conf has a trusted:
#                        entry
# ============================================================================
#
# CROSS-CUTTING FEATURES (not tied to one detector):
#   "What to detect" menu: a LIST_PICKER toggle screen at startup (WANT_FLOCK/
#     WANT_MESH/WANT_TRACKER/WANT_DEAUTH/WANT_DRONE), same idea as the picker
#     cncartistsec/BluePine-WiFi-Pineapple-Pager shows before scanning --
#     difference is this payload runs every enabled category concurrently
#     for the whole session (BluePine scans one at a time), so it's a
#     persistent per-category toggle, not a single pick. Defaults to
#     everything on; falls back to all-on silently if LIST_PICKER isn't
#     available (e.g. run outside the Pager's own UI).
#   GPS tagging: every hit line gets an optional "| gps=LAT,LON" suffix via
#     the Pager's own GPS_GET command (a thin wrapper over pineapd's HTTP
#     API -- same platform-builtin convention as LOG/LED/RINGTONE, not
#     gpsd/gpspipe talked to directly). No-op with no GPS hardware attached
#     (GPS_GET's own "0 0 0 0" no-fix sentinel), starts tagging
#     automatically once a GPS source (dongle or mobile2gps) exists -- see
#     get_gps_fix()'s comment for the confirmed-live details.
#   RSSI (signal strength): every hit line also gets an optional
#     "|rssi=N" (dBm) -- BLE via the HCI LE Advertising Report's own
#     trailing per-report RSSI byte (rid_common.awk's ble_rssi_for()), WiFi
#     via a hardware-confirmed fixed radiotap byte offset (wifi_rssi()) --
#     see both functions' comments for exactly how each was verified. Lets
#     you tell "right next to me" from "a block away" without needing GPS.
#   export_gps_kml.sh / export_gps_kml.awk: standalone companion tool (not
#     run automatically) that turns a session's GPS-tagged hits into a KML
#     file for Google Earth/My Maps, color-coded by category. Run it
#     manually after a session once GPS hardware is attached and has
#     actually recorded fixes -- see that script's own header.
#   Bookmarks: press RIGHT any time to flag the current moment (timestamp +
#     GPS if available) to bookmarks_<timestamp>.txt, for anything you
#     notice that the detectors should have caught (or just want to mark
#     for review) -- see bookmark_watcher()'s comment for why this runs as
#     its own background loop rather than inside the main one.
# ============================================================================
#
# WIFI RADIO: phy1/wlan1mon -- confirmed live on hardware (drove past a real
# Flock camera, got no hit) that this is the Pager's own default-configured
# primary recon interface (/etc/config/pineapd: `bands '2,5'`, `hop '1'`,
# `hopspeed 'fast'`, auto-started at boot by pineapd --recon=true), which
# was actively fighting this payload's own channel-hop loop for control of
# that interface -- observed as wifi_hop.log filling with continuous
# "Resource busy (-16)" and wlan1mon's actual channel drifting onto 5GHz
# (44, 144) that this payload's own hop set never sets, meaning none of the
# WiFi detectors were reliably on the 2.4GHz channels they need to be on.
#
# phy0/wlan0mon was tried as an alternative radio and ruled out: confirmed
# live that channel-set on wlan0mon fails 100% of the time (Resource busy),
# even completely alone with zero capture load attached -- phy0 also hosts
# wlan0 and wlan0cli (both `managed` type, controlled by hostapd/
# wpa_supplicant), and that appears to lock the phy's channel outright
# regardless of whether those interfaces are actively connected to
# anything. wlan1mon, by contrast, channel-sets successfully 100% of the
# time in isolation -- its only problem was losing the race against
# pineapd's own active hopping when both were running at once.
#
# THE ACTUAL FIX was a scoped device config change, not a radio switch:
# `uci set pineapd.wlan1mon.hop='0' && uci commit pineapd`, then
# `/etc/init.d/pineapd restart`. This stops pineapd from actively
# channel-hopping wlan1mon itself, without disabling pineapd or its recon
# logging on any other interface -- confirmed live afterward that wlan1mon's
# channel stays put (no drift) and manual channel-set succeeds 100% of the
# time even with pineapd running. This is a persistent change to
# /etc/config/pineapd on the device itself, NOT something this repo's files
# can carry -- if you're setting this payload up on a fresh Pager, you need
# to make this same uci change yourself first, or expect the same
# intermittent-to-severe WiFi detection failures depending on how actively
# pineapd's own recon happens to be hopping at the time.
#
# WIFI_CHANNELS below is deliberately still 2.4GHz-only (11/6/1), matching
# flock-you's own hop set, since the devices this payload targets are
# overwhelmingly 2.4GHz; wider per-cycle coverage would mean less dwell time
# on the channels that actually matter. KNOWN RISK: if the Pager's native
# AP/hotspot features ever get used on phy1 while this payload is running,
# that could still collide with wlan1mon -- not observed, not guaranteed to
# never happen, and disabling pineapd's *hop* doesn't touch anything else
# that might contend for the interface.
# KNOWN LIMITATIONS -- read before relying on this in the field:
#  - Drone BLE detection only sees advertisements during Flock-You's own
#    ~12-of-15s hcitool lescan windows (it piggybacks on that scan rather
#    than running a separate one) -- NOT continuous like the ESP32 Sky-Spy.
#    Rogue tracker BLE detection has the exact same limitation, for the
#    exact same reason (its hcidump reader is equally passive).
#  - All three WiFi detectors (Flock probe + Mesh-Detect + drone Remote ID)
#    now share one hopped radio (channels 11/6/1, 250ms dwell, matching
#    flock-you's own CUSTOM hop set) instead of drone detection's old fixed
#    channel 6. A drone beaconing Remote ID only on 5GHz, or on a 2.4GHz
#    channel outside 11/6/1, will still be missed -- same for a Mesh-Detect
#    target whose beacon/probe traffic never lands on one of those channels.
#  - Rogue tracker detection's persistence heuristic (see
#    handle_tracker_line() below) is still purely time/sighting-count-based,
#    not location-diversity-based, and so still can't tell "this tracker has
#    followed me across locations" from "this tracker has sat 15+ minutes
#    near wherever the Pager itself is sitting" -- it's the same class of
#    heuristic Apple/Android's own on-device detection uses, just without
#    their location-diversity refinement. GPS tagging (added since this
#    limitation was first written) DOES now log a lat/lon with every
#    sighting in TRACKER_LOG_FILE -- so the raw data to add real location-
#    diversity exists once GPS hardware is attached -- but the live
#    eligibility decision in handle_tracker_line() doesn't consume it yet.
#    A tracker in a stationary neighboring apartment/vehicle you're not near
#    could still false-positive if you stay put nearby for the persistence
#    window; a tracker that boards a fast-moving vehicle you're not in but
#    happens to sit near the Pager only briefly could still false-negative.
#  - Rogue tracker allowlisting (tracker_allowlist.conf) needs periodic
#    maintenance for the three protocols with rotating MACs (Apple/Samsung/
#    Google) -- see that file's header for why there's no "add once, forget
#    forever" option available here. Tile's MAC doesn't rotate, so a Tile
#    allowlist entry is permanent.
#  - rogue_tracker_monitor.awk only checks the AD-type + company/service-ID
#    + protocol-type-byte header for each of the four protocols, not deeper
#    payload fields (Apple's status-byte bits, Samsung's aging counter/
#    battery fields, FMDN's hashed-flags byte) -- see that file's header for
#    why. This is enough to identify the protocol, not to decode e.g.
#    battery level.
#  - mesh_detect_targets.conf ships pre-populated with ~50 active + ~20
#    commented-out OUI entries -- see that file's header for sourcing and
#    the false-positive-risk tiering. It is NOT empty by default anymore
#    (it was, in an earlier version of this payload, before real sourced
#    data was found to seed it with).
#  - Mesh-Detect's WiFi matcher (mesh_wifi_monitor.awk) matches the
#    transmitter MAC of ANY management frame (beacon, probe request/response,
#    etc.) against your OUI/MAC list, same as Esp32-oui-sniffer's WiFi Probe
#    method -- broader and noisier than the Flock detector's tightly-gated
#    wildcard-probe+IE check, by design: it's a general OUI/MAC watchlist,
#    not a single-vendor fingerprint.
#  - flock_wifi_monitor.awk's detection logic (OUI match, wildcard-probe
#    check, IE-signature match) has been verified against synthetic packets
#    built to flock-you's own documented signature, and its tcpdump-framing
#    code reuses the byte offsets already hardware-verified for
#    rid_wifi_monitor.awk. CONFIRMED LIVE this was previously a real problem:
#    drove past actual Flock cameras, got zero hits and zero diagnostic
#    trail, because detection required an exact match against flock-you's
#    one published fingerprint constant -- see flock_wifi_monitor.awk's
#    "DEVIATION FROM UPSTREAM" header note for the fix (OUI+wildcard-probe is
#    now the hard gate, IE-signature is a reported confidence tier, and
#    non-matching hits log their actual signature for field tuning). Still
#    "field-driven, not yet re-confirmed on the exact cameras that missed" --
#    the next drive-by is what validates it.
#  - mesh_wifi_monitor.awk's matching logic (OUI/MAC lookup, config-file
#    parsing) is likewise only unit-tested against synthetic packets and a
#    synthetic config file, not run on-device yet -- same "ported and
#    unit-tested, not field-confirmed" caveat applies.
#  - rogue_tracker_monitor.awk has been checked against synthetic packets
#    for all four protocols (positive match per protocol, two negative
#    cases, and the packet-count emit-throttle) with gawk -- not yet against
#    a real AirTag/Tile/SmartTag/FMDN accessory or on-device. Same "unit-
#    tested, not field-confirmed" caveat as the WiFi detectors above.
#  - deauth_eviltwin_monitor.awk / handle_deauth_line()'s rate math was
#    checked with synthetic packets (throttle behavior) and standalone bash
#    scenarios (real flood, normal single disconnect, slow trickle, cooldown
#    suppression, evil-twin positive/negative/unrelated-SSID) -- not yet
#    against a real deauth attack tool or a real rogue AP, and the
#    DEAUTH_FLOOD_RATE=3/DEAUTH_FLOOD_MIN_DELTA=5 thresholds are reasoned
#    defaults, not calibrated against a real attack's actual frame rate.
#    Same "unit-tested, not field-confirmed" caveat.
#  - Evil-twin detection only checks Beacon frames, not Probe Response
#    (which also carries SSID+BSSID) -- see deauth_eviltwin_monitor.awk's
#    header for why. A rogue AP that only replies to probes and never
#    beacons would be missed.
#  - trusted_networks.conf ships EMPTY -- evil-twin detection is a no-op
#    until you add your own network's SSID+BSSID(s). No vendor list applies
#    here the way it did for Mesh-Detect; only you know your own network.
#  - BLE Extended/Long-Range advertising (Bluetooth 5) Remote ID is not
#    decoded, only Legacy advertising -- covers the common case. Rogue
#    tracker detection has the same gap: a tracker that only ever uses BT5
#    extended advertising (not confirmed either way for any of the four
#    protocols covered) would be invisible to hcidump's legacy-advertising
#    capture the same way.
#  - Still unverified: real-world timing/coverage against an actual
#    Remote-ID-broadcasting drone, which wasn't available during development.
#    Everything up to that point (wire formats, byte offsets, framing) has
#    been checked against real captures from this specific device.

# NOTE: deliberately NOT `dirname "$0"` -- the Pager's payload runner stages/
# invokes payload.sh in a way that leaves $0 pointing at /tmp (confirmed live:
# a $0-based SCRIPT_DIR resolved to /tmp, breaking the companion .awk lookups
# below), even though it does set the working directory to the payload's own
# folder before running it. Matches the convention other multi-file payloads
# in this repo already rely on (e.g. bt-bluepine sources "./include/*.sh").
# Still probing a couple of fallbacks rather than hardcoding just "." --
# the $0 bug above means this runner's invocation semantics aren't fully
# pinned down, and a silent wrong guess here fails exactly the same
# unhelpful way (background awk exits immediately, nothing shows in LOG).
SCRIPT_DIR="."
for _candidate in "." "/root/payloads/user/reconnaissance/Counter_Surveillance_Pager" "$(dirname "$0" 2>/dev/null)"; do
    if [ -n "$_candidate" ] && [ -f "$_candidate/rid_common.awk" ]; then
        SCRIPT_DIR="$_candidate"
        break
    fi
done
LOOT_DIR="/root/loot/counter_surveillance_pager"
WORK_DIR="/tmp/counter_surveillance_pager"
mkdir -p "$LOOT_DIR" "$WORK_DIR"
rm -f "$WORK_DIR"/*.log "$WORK_DIR"/*.fifo 2>/dev/null

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# Renamed from flock_you_<ts>.txt: this file now carries Flock AND
# Mesh-Detect hits, not just Flock. (Drone Remote ID keeps its own separate
# log below, unchanged.)
LOG_FILE="${LOOT_DIR}/surveillance_${TIMESTAMP}.txt"
DRONE_LOG_FILE="${LOOT_DIR}/drone_rid_${TIMESTAMP}.txt"
# Created (truncating) here, before any of the capability-detection commands
# below start appending (2>>) diagnostic output to LOG_FILE -- writing this
# with `>` again later would silently wipe out those first-run diagnostics
# right when they're most useful (e.g. did `iw ... type monitor` fail?).
echo "Counter-Surveillance-Pager started at $(date)" > "$LOG_FILE"
echo "Drone Remote ID log started at $(date)" > "$DRONE_LOG_FILE"

BLE_HITS="$WORK_DIR/ble_rid_hits.log"
WIFI_HITS="$WORK_DIR/wifi_rid_hits.log"
FLOCK_WIFI_HITS="$WORK_DIR/flock_wifi_hits.log"
MESH_WIFI_HITS="$WORK_DIR/mesh_wifi_hits.log"
TRACKER_HITS="$WORK_DIR/tracker_hits.log"
FLOCK_BLE_HITS="$WORK_DIR/flock_ble_hits.log"
GLASSES_BLE_HITS="$WORK_DIR/glasses_ble_hits.log"
DEAUTH_HITS="$WORK_DIR/deauth_eviltwin_hits.log"
touch "$BLE_HITS" "$WIFI_HITS" "$FLOCK_WIFI_HITS" "$MESH_WIFI_HITS" "$TRACKER_HITS" "$FLOCK_BLE_HITS" "$GLASSES_BLE_HITS" "$DEAUTH_HITS"
BLE_FIFO="$WORK_DIR/ble_raw.fifo"
WIFI_FIFO="$WORK_DIR/wifi_raw.fifo"
FLOCK_WIFI_FIFO="$WORK_DIR/flock_wifi_raw.fifo"
MESH_WIFI_FIFO="$WORK_DIR/mesh_wifi_raw.fifo"
TRACKER_FIFO="$WORK_DIR/tracker_raw.fifo"
FLOCK_BLE_FIFO="$WORK_DIR/flock_ble_raw.fifo"
GLASSES_BLE_FIFO="$WORK_DIR/glasses_ble_raw.fifo"
DEAUTH_FIFO="$WORK_DIR/deauth_raw.fifo"
rm -f "$BLE_FIFO" "$WIFI_FIFO" "$FLOCK_WIFI_FIFO" "$MESH_WIFI_FIFO" "$TRACKER_FIFO" "$FLOCK_BLE_FIFO" "$GLASSES_BLE_FIFO" "$DEAUTH_FIFO"

MESH_CONFIG_FILE="$SCRIPT_DIR/mesh_detect_targets.conf"
TRACKER_ALLOWLIST_FILE="$SCRIPT_DIR/tracker_allowlist.conf"
# Time-bounded, not permanent like tracker_allowlist.conf -- see
# snooze_tracker.sh and load_tracker_snooze() below. Lives in WORK_DIR
# (session-scoped /tmp), not SCRIPT_DIR, since a snooze is a reactive
# "I know about this one right now" decision, not a saved config -- it's
# managed entirely by the standalone snooze_tracker.sh CLI tool, never
# written by this script itself.
TRACKER_SNOOZE_FILE="$WORK_DIR/tracker_snooze.txt"
TRACKER_LOG_FILE="${LOOT_DIR}/rogue_trackers_${TIMESTAMP}.txt"
echo "Rogue BLE tracker log started at $(date)" > "$TRACKER_LOG_FILE"
# Diagnostic-only, never alerts -- see flock_wifi_monitor.awk's header and
# handle_flock_wifi_diag_line() below. Separate file from LOG_FILE/
# surveillance.txt on purpose: this is expected to be noisy (most nearby
# phones/laptops send wildcard probes too), and keeping it out of the main
# detection log means it doesn't have to be scrolled past to review real
# hits.
FLOCK_DIAG_LOG_FILE="${LOOT_DIR}/flock_wifi_diag_${TIMESTAMP}.txt"
echo "Flock WiFi diagnostic log (unmatched-OUI wildcard probes, never alerts) started at $(date)" > "$FLOCK_DIAG_LOG_FILE"
# Manual "flag this moment for later analysis" -- see bookmark_watcher()
# below. Confirmed live which DuckyScript button-name string this device's
# RIGHT button reports (WAIT_FOR_INPUT returns "RIGHT", same command the
# stock BUTTON_COMBO example payload uses in its own background loop).
BOOKMARK_LOG_FILE="${LOOT_DIR}/bookmarks_${TIMESTAMP}.txt"
echo "Bookmark log (RIGHT button = flag this moment) started at $(date)" > "$BOOKMARK_LOG_FILE"
# Persistence heuristic thresholds -- see handle_tracker_line() and this
# file's KNOWN LIMITATIONS section on why these are time-window-based, not
# GPS-based, and what that does and doesn't catch.
TRACKER_PERSISTENCE_SECONDS=900      # 15 min -- how long a tracker must keep
                                      # being seen before it's treated as
                                      # "following", not "nearby once"
TRACKER_PERSISTENCE_MIN_SIGHTINGS=3  # also require this many distinct hit
                                      # lines (rogue_tracker_monitor.awk's own
                                      # throttle already spaces these out)
TRACKER_ALERT_COOLDOWN=300           # 5 min between repeat UI alerts for the
                                      # same still-present tracker (loot log
                                      # is never throttled)

TRUSTED_NETWORKS_FILE="$SCRIPT_DIR/trusted_networks.conf"
DEAUTH_LOG_FILE="${LOOT_DIR}/deauth_eviltwin_${TIMESTAMP}.txt"
echo "Deauth/evil-twin log started at $(date)" > "$DEAUTH_LOG_FILE"
# Deauth-flood rate thresholds -- see handle_deauth_line(). Cross-multiplied
# (delta_count >= RATE * delta_time) rather than divided, since plain bash
# arithmetic is integer-only and division would round small rates to 0.
DEAUTH_FLOOD_RATE=3        # frames/sec sustained to count as an active flood,
                            # not one real client actually disconnecting
DEAUTH_FLOOD_MIN_DELTA=5   # also require at least this many frames in the
                            # current sample so a tiny delta_time doesn't
                            # trigger off just 1-2 frames
DEAUTH_ALERT_COOLDOWN=60   # seconds between repeat UI alerts for the same
                            # still-flooding source / still-present rogue AP
                            # (loot log is never throttled)

WIFI_IFACE="wlan1mon"
# Channel hop set/order/dwell matches flock-you's own CUSTOM mode (main.cpp:
# customChannels[] / CHANNEL_DWELL_MS) -- credited there to nsm_barri's
# observation that the cameras hop channels in ascending order roughly every
# 125ms, so a 250ms dwell (2x that) catches each channel at least once per
# camera hop cycle. Drives both WiFi detectors below since they share this
# one monitor-mode radio.
WIFI_CHANNELS="11 6 1"
WIFI_CHANNEL_DWELL="0.25"
ALERT_COOLDOWN=10   # seconds between repeat drone UI alerts for the same MAC (loot log is never throttled)

HCIDUMP_PID=""
BLE_MON_PID=""
TCPDUMP_PID=""
WIFI_MON_PID=""
FLOCK_TCPDUMP_PID=""
FLOCK_WIFI_MON_PID=""
MESH_TCPDUMP_PID=""
MESH_WIFI_MON_PID=""
TRACKER_HCIDUMP_PID=""
TRACKER_MON_PID=""
FLOCK_BLE_HCIDUMP_PID=""
FLOCK_BLE_MON_PID=""
GLASSES_BLE_HCIDUMP_PID=""
GLASSES_BLE_MON_PID=""
DEAUTH_TCPDUMP_PID=""
DEAUTH_MON_PID=""
WIFI_HOP_PID=""
BOOKMARK_WATCHER_PID=""
WIFI_IFACE_CREATED=0

cleanup() {
    for p in "$HCIDUMP_PID" "$BLE_MON_PID" "$TCPDUMP_PID" "$WIFI_MON_PID" \
             "$FLOCK_TCPDUMP_PID" "$FLOCK_WIFI_MON_PID" \
             "$MESH_TCPDUMP_PID" "$MESH_WIFI_MON_PID" \
             "$TRACKER_HCIDUMP_PID" "$TRACKER_MON_PID" \
             "$FLOCK_BLE_HCIDUMP_PID" "$FLOCK_BLE_MON_PID" \
             "$GLASSES_BLE_HCIDUMP_PID" "$GLASSES_BLE_MON_PID" \
             "$DEAUTH_TCPDUMP_PID" "$DEAUTH_MON_PID" "$WIFI_HOP_PID" \
             "$BOOKMARK_WATCHER_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    rm -f "$BLE_FIFO" "$WIFI_FIFO" "$FLOCK_WIFI_FIFO" "$MESH_WIFI_FIFO" "$TRACKER_FIFO" "$FLOCK_BLE_FIFO" "$GLASSES_BLE_FIFO" "$DEAUTH_FIFO"
    if [ "$WIFI_IFACE_CREATED" = "1" ]; then
        iw dev "$WIFI_IFACE" del 2>/dev/null
    fi
}
# Trapping INT/TERM via a plain `trap cleanup EXIT INT TERM` runs cleanup()
# on those signals but does NOT terminate the process afterward -- a bash
# trap handler just returns to whatever was interrupted unless it calls
# `exit` itself, so that form left payload.sh silently resuming its main
# loop after a kill/Ctrl-C, with every capture pipeline dead and never
# relaunched (only launched once, before the loop). Confirmed live on
# hardware: SIGTERM ran cleanup and killed every hcidump/tcpdump/awk child
# as expected, but the outer while loop kept going regardless, orphaned,
# until force-killed. EXIT alone needs no explicit exit (the shell is
# already exiting by definition when that pseudo-signal fires); INT/TERM
# do. cleanup() running twice (once from the INT/TERM trap, once more from
# EXIT firing as that trap's own `exit` unwinds) is harmless -- every
# action in it is already idempotent (kill/rm -f on already-gone
# PIDs/files, iw dev del with stderr suppressed).
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Loads mesh_detect_targets.conf into three bash arrays for the BLE matching
# pass below (see handle_ble_line in the main loop). The WiFi matcher
# (mesh_wifi_monitor.awk) parses the same file itself, independently -- kept
# duplicated rather than shared, since one's bash and the other's awk and
# there's no clean way to pass parsed arrays between them.
declare -a MESH_OUI_TARGETS=()
declare -a MESH_MAC_TARGETS=()
declare -a MESH_NAME_TARGETS=()
load_mesh_targets() {
    local raw
    while IFS= read -r raw || [ -n "$raw" ]; do
        raw="${raw%%#*}"                                  # strip comments
        raw="${raw#"${raw%%[![:space:]]*}"}"               # trim leading ws
        raw="${raw%"${raw##*[![:space:]]}"}"               # trim trailing ws
        [ -z "$raw" ] && continue
        case "$raw" in
            [Oo][Uu][Ii]:*) MESH_OUI_TARGETS+=("$(echo "${raw#*:}" | tr 'A-Z' 'a-z')") ;;
            [Mm][Aa][Cc]:*) MESH_MAC_TARGETS+=("$(echo "${raw#*:}" | tr 'A-Z' 'a-z')") ;;
            [Nn][Aa][Mm][Ee]:*) MESH_NAME_TARGETS+=("${raw#*:}") ;;
        esac
    done < "$MESH_CONFIG_FILE"
}
MESH_BLE_OK=0
if [ -f "$MESH_CONFIG_FILE" ]; then
    load_mesh_targets
    if [ ${#MESH_OUI_TARGETS[@]} -gt 0 ] || [ ${#MESH_MAC_TARGETS[@]} -gt 0 ] || [ ${#MESH_NAME_TARGETS[@]} -gt 0 ]; then
        MESH_BLE_OK=1
    fi
fi

# Loads tracker_allowlist.conf (mac: lines only) into an associative set --
# MACs here are never counted as sightings at all, so they can't cross the
# persistence threshold or trigger fmdn_unwanted's immediate alert either.
declare -A TRACKER_ALLOWLIST=()
load_tracker_allowlist() {
    local raw
    while IFS= read -r raw || [ -n "$raw" ]; do
        raw="${raw%%#*}"
        raw="${raw#"${raw%%[![:space:]]*}"}"
        raw="${raw%"${raw##*[![:space:]]}"}"
        [ -z "$raw" ] && continue
        case "$raw" in
            [Mm][Aa][Cc]:*) TRACKER_ALLOWLIST["$(echo "${raw#*:}" | tr 'A-Z' 'a-z')"]=1 ;;
        esac
    done < "$TRACKER_ALLOWLIST_FILE"
}
[ -f "$TRACKER_ALLOWLIST_FILE" ] && load_tracker_allowlist

# Cycles the shared monitor-mode radio through WIFI_CHANNELS forever. Backgrounded
# only once a usable monitor interface is confirmed (see capability detection below).
wifi_channel_hop() {
    while true; do
        for _ch in $WIFI_CHANNELS; do
            iw dev "$WIFI_IFACE" set channel "$_ch" 2>>"$WORK_DIR/wifi_hop.log"
            sleep "$WIFI_CHANNEL_DWELL"
        done
    done
}

# ---------------------------------------------------------------------------
# Detection category selection -- "what to detect", same idea as the picker
# cncartistsec/BluePine-WiFi-Pineapple-Pager shows before it scans. The
# difference: BluePine runs ONE category per scan, so a single-pick LIST_
# PICKER is enough there. This payload runs every enabled category
# concurrently in the background for the whole session, so this is a
# persistent on/off toggle screen instead -- select an item to flip it,
# "Start scanning" when done. Defaults to everything ON, so hitting "Start
# scanning" immediately (without touching anything) reproduces this
# payload's original always-everything-on behavior exactly; this menu only
# narrows what runs, it can't be used to enable something this hardware/
# config can't already support (every WANT_* flag below is just one more
# condition ANDed onto the existing capability gates further down, not a
# replacement for them).
# ---------------------------------------------------------------------------
WANT_FLOCK=1
WANT_MESH=1
WANT_TRACKER=1
WANT_DEAUTH=1
WANT_DRONE=1
WANT_SKIMMER=1
WANT_GLASSES=1

# STEALTH_MODE: 0 off (default), 1 stealth+vibrate (LED/RINGTONE/ALERT_RINGTONE
# suppressed, vibrator still pulses so a detection can still be felt without
# looking at the screen), 2 stealth+silent (all physical feedback suppressed,
# only the on-screen LOG and loot files still show a detection happened).
# Idea from cncartistsec/BluePine-WiFi-Pineapple-Pager's Stealth Mode ("Sound
# Effects, LEDS, Payload LED Actions Disabled") -- vibrate is deliberately its
# own tier here rather than folded into "everything off": BluePine's own
# description never mentions vibrate at all, and unlike a blink or a
# ringtone, a vibrate pulse isn't visible/audible to anyone else nearby, so
# keeping it as an optional silent alert channel is a genuine third state,
# not just a compromise between the other two -- left as the user's choice
# via the menu below instead of picking one on their behalf.
STEALTH_MODE=0

# Wraps the raw vibrate+LED-brightness blink pair used by several
# detectors' soft/medium alerts. STEALTH_MODE 1: LED blink suppressed,
# vibrate kept. STEALTH_MODE 2: both suppressed. Local var name deliberately
# not `LED` (unlike the sysfs-path variable of that name already used
# inline elsewhere in this file) to avoid any shadowing of the `LED`
# platform builtin that stealth_alert() below calls directly.
#
# BUG FIX while porting this to a shared function (confirmed live against
# the real device, unrelated to stealth mode itself): the original inline
# blocks at every one of this function's call sites used
# `LED=$(ls /sys/class/leds/* | head -1)`. On this device's actual
# /sys/class/leds/ (16 entries: a/b-button-led, buzzer, 4 directional LEDs
# x3 colors, mt76-phy0), that glob expands to multiple directory arguments,
# so BusyBox ls prints a "/sys/class/leds/a-button-led:" HEADER line before
# each directory's contents -- `head -1` was capturing that header, colon
# included, not a usable path, so every `echo 1 > "${LED}/brightness"`
# write silently failed (redirect error swallowed by 2>/dev/null). The LED
# half of this blink has likely never actually lit up on real hardware.
# Fixed with `ls -d .../*/ ` (trailing slash suppresses descending into
# each match, so it lists directory names themselves, one per line, no
# header) -- confirmed live this returns a clean
# "/sys/class/leds/a-button-led/" path.
stealth_blink() {
    if [ "$STEALTH_MODE" != "2" ] && [ -f /sys/class/gpio/vibrator/value ]; then
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.15
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
    fi
    if [ "$STEALTH_MODE" = "0" ]; then
        local _led_path
        _led_path=$(ls -d /sys/class/leds/*/ 2>/dev/null | head -1)
        if [ -n "$_led_path" ]; then
            echo 1 > "${_led_path}brightness" 2>/dev/null
            sleep 0.3
            echo 0 > "${_led_path}brightness" 2>/dev/null
        fi
    fi
}

# Wraps the LED RED / RINGTONE warning / ALERT_RINGTONE / LED OFF sequence
# used by the hard-alert detectors (rogue tracker, deauth flood, evil-twin,
# drone). Both STEALTH_MODE 1 and 2 suppress this whole sequence -- LED and
# RINGTONE/ALERT_RINGTONE are both visible/audible tells with no vibrate-only
# path through the platform builtins, so there's no meaningful difference
# between the two stealth tiers here (unlike stealth_blink's raw sysfs
# vibrate, which stealth can address independently of the LED/sound).
stealth_alert() {
    local title="$1" body="$2"
    if [ "$STEALTH_MODE" = "0" ]; then
        LED RED
        RINGTONE warning
        ALERT_RINGTONE "$title" "$body"
        LED OFF
    fi
}

detection_menu_item() {
    local key="$1" name="$2" val
    case "$key" in
        flock) val="$WANT_FLOCK" ;;
        mesh) val="$WANT_MESH" ;;
        tracker) val="$WANT_TRACKER" ;;
        deauth) val="$WANT_DEAUTH" ;;
        drone) val="$WANT_DRONE" ;;
        skimmer) val="$WANT_SKIMMER" ;;
        glasses) val="$WANT_GLASSES" ;;
    esac
    if [ "$val" = "1" ]; then echo "[X] $name"; else echo "[ ] $name"; fi
}

stealth_menu_item() {
    case "$STEALTH_MODE" in
        0) echo "[ ] Stealth Mode (off)" ;;
        1) echo "[X] Stealth Mode (no LED/sound, vibrate stays on)" ;;
        2) echo "[X] Stealth Mode (fully silent, no vibrate either)" ;;
    esac
}

if command -v LIST_PICKER >/dev/null 2>&1; then
    while true; do
        _resp=$(LIST_PICKER "What to detect (select to toggle)" \
            "$(detection_menu_item flock 'Flock Safety cameras')" \
            "$(detection_menu_item mesh 'Mesh-Detect watchlist')" \
            "$(detection_menu_item tracker 'Rogue BLE trackers')" \
            "$(detection_menu_item deauth 'Deauth flood / Evil-Twin AP')" \
            "$(detection_menu_item drone 'Drone Remote ID')" \
            "$(detection_menu_item skimmer 'BLE credit-card skimmers')" \
            "$(detection_menu_item glasses 'Smart glasses (Meta/Snap/Bose/etc.)')" \
            "$(stealth_menu_item)" \
            "Start scanning" \
            "Start scanning")
        case "$_resp" in
            *"Flock Safety cameras") WANT_FLOCK=$((1 - WANT_FLOCK)) ;;
            *"Mesh-Detect watchlist") WANT_MESH=$((1 - WANT_MESH)) ;;
            *"Rogue BLE trackers") WANT_TRACKER=$((1 - WANT_TRACKER)) ;;
            *"Deauth flood / Evil-Twin AP") WANT_DEAUTH=$((1 - WANT_DEAUTH)) ;;
            *"Drone Remote ID") WANT_DRONE=$((1 - WANT_DRONE)) ;;
            *"BLE credit-card skimmers") WANT_SKIMMER=$((1 - WANT_SKIMMER)) ;;
            *"Smart glasses"*) WANT_GLASSES=$((1 - WANT_GLASSES)) ;;
            *"Stealth Mode"*) STEALTH_MODE=$(( (STEALTH_MODE + 1) % 3 )) ;;
            "Start scanning") break ;;
            *) break ;;   # LIST_PICKER unavailable/cancelled mid-loop -- fall through with current WANT_*/STEALTH_MODE values rather than looping forever
        esac
    done
fi

# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------
AWK=$(command -v awk)
HCIDUMP=$(command -v hcidump)
TCPDUMP=$(command -v tcpdump)
IW=$(command -v iw)

BLE_RID_OK=0
WIFI_RID_OK=0
FLOCK_WIFI_OK=0
MESH_WIFI_OK=0
TRACKER_BLE_OK=0
FLOCK_BLE_UUID_OK=0
GLASSES_BLE_OK=0
DEAUTH_OK=0

LOG yellow "Counter-Surveillance-Pager started at $(date)"

AWK_FILES_OK=1
for _f in rid_common.awk rid_ble_monitor.awk rid_wifi_monitor.awk; do
    if [ ! -f "$SCRIPT_DIR/$_f" ]; then
        LOG red "Drone detection: disabled ($_f not found -- looked in $SCRIPT_DIR)"
        AWK_FILES_OK=0
        break
    fi
done

# Checked separately from AWK_FILES_OK above: a missing flock_wifi_monitor.awk
# should only disable the new WiFi Flock detector, not drone detection too.
FLOCK_AWK_FILE_OK=1
if [ ! -f "$SCRIPT_DIR/flock_wifi_monitor.awk" ]; then
    LOG red "Flock WiFi detection: disabled (flock_wifi_monitor.awk not found -- looked in $SCRIPT_DIR)"
    FLOCK_AWK_FILE_OK=0
fi

# Same idea for Mesh-Detect's WiFi matcher: file presence is one gate, but it
# also only makes sense to run if the config actually has an oui:/mac: entry
# (name: entries are BLE-only, see mesh_detect_targets.conf's header).
MESH_AWK_FILE_OK=1
if [ ! -f "$SCRIPT_DIR/mesh_wifi_monitor.awk" ]; then
    LOG red "Mesh-Detect WiFi detection: disabled (mesh_wifi_monitor.awk not found -- looked in $SCRIPT_DIR)"
    MESH_AWK_FILE_OK=0
fi
MESH_WIFI_TARGETS_PRESENT=0
if [ ${#MESH_OUI_TARGETS[@]} -gt 0 ] || [ ${#MESH_MAC_TARGETS[@]} -gt 0 ]; then
    MESH_WIFI_TARGETS_PRESENT=1
fi

# Deauth-flood detection needs no config at all (works standalone); evil-twin
# needs trusted_networks.conf entries, but that's checked awk-side (HAVE_TRUSTED)
# and just no-ops rather than needing a separate bash-side gate here.
DEAUTH_AWK_FILE_OK=1
if [ ! -f "$SCRIPT_DIR/deauth_eviltwin_monitor.awk" ]; then
    LOG red "Deauth/evil-twin detection: disabled (deauth_eviltwin_monitor.awk not found -- looked in $SCRIPT_DIR)"
    DEAUTH_AWK_FILE_OK=0
fi
if [ "$MESH_BLE_OK" = "1" ] && [ "$WANT_MESH" = "0" ]; then
    LOG yellow "Mesh-Detect BLE detection: disabled (not selected in detection menu)"
    MESH_BLE_OK=0
elif [ "$MESH_BLE_OK" = "1" ]; then
    LOG green "Mesh-Detect BLE detection: enabled (${#MESH_OUI_TARGETS[@]} oui, ${#MESH_MAC_TARGETS[@]} mac, ${#MESH_NAME_TARGETS[@]} name target(s))"
else
    LOG yellow "Mesh-Detect BLE detection: no-op (mesh_detect_targets.conf has no oui:/mac:/name: entries yet)"
fi

# No separate _OK/capability gate needed -- same as the Flock-You BLE name
# loop it's modeled on, this only needs the shared hcitool lescan dump
# already captured for that loop and Mesh-Detect BLE, not its own hcidump
# reader or awk file.
if [ "$WANT_SKIMMER" = "0" ]; then
    LOG yellow "BLE skimmer detection: disabled (not selected in detection menu)"
else
    LOG green "BLE skimmer detection: enabled"
fi

if [ "$WANT_DRONE" = "0" ]; then
    LOG yellow "Drone BLE detection: disabled (not selected in detection menu)"
elif [ "$AWK_FILES_OK" = "1" ] && [ -n "$AWK" ] && [ -n "$HCIDUMP" ]; then
    BLE_RID_OK=1
    LOG green "Drone BLE detection: enabled (hcidump found)"
elif [ "$AWK_FILES_OK" = "1" ]; then
    LOG red "Drone BLE detection: disabled (missing$( [ -z "$AWK" ] && echo " awk")$( [ -z "$HCIDUMP" ] && echo " hcidump"))"
fi

# Own file-existence gate (like FLOCK_AWK_FILE_OK / MESH_AWK_FILE_OK above) --
# a missing rogue_tracker_monitor.awk shouldn't take down drone BLE detection.
if [ "$WANT_TRACKER" = "0" ]; then
    LOG yellow "Rogue tracker BLE detection: disabled (not selected in detection menu)"
elif [ -n "$AWK" ] && [ -n "$HCIDUMP" ] && [ -f "$SCRIPT_DIR/rogue_tracker_monitor.awk" ]; then
    TRACKER_BLE_OK=1
    LOG green "Rogue tracker BLE detection: enabled (hcidump found)"
elif [ ! -f "$SCRIPT_DIR/rogue_tracker_monitor.awk" ]; then
    LOG red "Rogue tracker BLE detection: disabled (rogue_tracker_monitor.awk not found -- looked in $SCRIPT_DIR)"
else
    LOG red "Rogue tracker BLE detection: disabled (missing$( [ -z "$AWK" ] && echo " awk")$( [ -z "$HCIDUMP" ] && echo " hcidump"))"
fi

# Own file-existence gate, same pattern as the checks above -- see
# flock_ble_monitor.awk's header for why this is an UNVERIFIED signature
# (only its awk file existing determines whether it runs; it's not gated by
# anything else, same as rogue tracker BLE above).
if [ "$WANT_FLOCK" = "0" ]; then
    LOG yellow "Flock BLE (UUID 0x09C8) detection: disabled (not selected in detection menu)"
elif [ -n "$AWK" ] && [ -n "$HCIDUMP" ] && [ -f "$SCRIPT_DIR/flock_ble_monitor.awk" ]; then
    FLOCK_BLE_UUID_OK=1
    LOG yellow "Flock BLE (UUID 0x09C8) detection: enabled, UNVERIFIED signature (hcidump found)"
elif [ ! -f "$SCRIPT_DIR/flock_ble_monitor.awk" ]; then
    LOG red "Flock BLE (UUID 0x09C8) detection: disabled (flock_ble_monitor.awk not found -- looked in $SCRIPT_DIR)"
else
    LOG red "Flock BLE (UUID 0x09C8) detection: disabled (missing$( [ -z "$AWK" ] && echo " awk")$( [ -z "$HCIDUMP" ] && echo " hcidump"))"
fi

# Own file-existence gate, same pattern as Flock BLE UUID above -- see
# glasses_ble_monitor.awk's header for why this is UNVERIFIED. Own menu
# toggle (WANT_GLASSES), separate from Mesh-Detect -- this used to piggyback
# on WANT_MESH since smart glasses are also in mesh_detect_targets.conf, but
# that meant no way to turn this UNVERIFIED company-ID guesser on/off
# without also toggling the (separately verified) Mesh-Detect watchlist as
# a whole. Note this doesn't change mesh_detect_targets.conf's own glasses
# entries -- those are still matched under WANT_MESH like every other
# watchlist entry in that file, since it's a general OUI/MAC/name
# mechanism, not glasses-specific; this toggle only controls the dedicated
# company-ID detector below.
if [ "$WANT_GLASSES" = "0" ]; then
    LOG yellow "Smart-glasses BLE (company ID) detection: disabled (not selected in detection menu)"
elif [ -n "$AWK" ] && [ -n "$HCIDUMP" ] && [ -f "$SCRIPT_DIR/glasses_ble_monitor.awk" ]; then
    GLASSES_BLE_OK=1
    LOG yellow "Smart-glasses BLE (company ID) detection: enabled, UNVERIFIED signatures (hcidump found)"
elif [ ! -f "$SCRIPT_DIR/glasses_ble_monitor.awk" ]; then
    LOG red "Smart-glasses BLE (company ID) detection: disabled (glasses_ble_monitor.awk not found -- looked in $SCRIPT_DIR)"
else
    LOG red "Smart-glasses BLE (company ID) detection: disabled (missing$( [ -z "$AWK" ] && echo " awk")$( [ -z "$HCIDUMP" ] && echo " hcidump"))"
fi

# The shared wlan1mon radio setup itself is gated on ANY WiFi-side category
# being wanted -- Flock/Mesh/Deauth WiFi and Drone WiFi each still get their
# own individual WANT_* check further down, this just skips bringing up the
# monitor interface at all when every WiFi-side category is turned off.
if { [ "$WANT_DRONE" = "1" ] || [ "$WANT_FLOCK" = "1" ] || [ "$WANT_MESH" = "1" ] || [ "$WANT_DEAUTH" = "1" ]; } \
   && [ "$AWK_FILES_OK" = "1" ] && [ -n "$AWK" ] && [ -n "$IW" ] && [ -n "$TCPDUMP" ] && iw phy phy1 info >/dev/null 2>&1; then
    if ! iw dev "$WIFI_IFACE" info >/dev/null 2>&1; then
        if iw phy phy1 interface add "$WIFI_IFACE" type monitor 2>>"$LOG_FILE"; then
            WIFI_IFACE_CREATED=1
        fi
    fi
    if iw dev "$WIFI_IFACE" info >/dev/null 2>&1; then
        ip link set "$WIFI_IFACE" up 2>>"$LOG_FILE"
        iw dev "$WIFI_IFACE" set channel "${WIFI_CHANNELS%% *}" 2>>"$LOG_FILE"
        wifi_channel_hop &
        WIFI_HOP_PID=$!
        if [ "$WANT_DRONE" = "1" ]; then
            WIFI_RID_OK=1
            LOG green "Drone WiFi detection: enabled ($WIFI_IFACE on phy1, hopping ch $WIFI_CHANNELS)"
        else
            LOG yellow "Drone WiFi detection: disabled (not selected in detection menu)"
        fi
        if [ "$WANT_FLOCK" = "0" ]; then
            LOG yellow "Flock WiFi detection: disabled (not selected in detection menu)"
        elif [ "$FLOCK_AWK_FILE_OK" = "1" ]; then
            FLOCK_WIFI_OK=1
            LOG green "Flock WiFi detection: enabled ($WIFI_IFACE on phy1, hopping ch $WIFI_CHANNELS)"
        fi
        if [ "$WANT_MESH" = "0" ]; then
            LOG yellow "Mesh-Detect WiFi detection: disabled (not selected in detection menu)"
        elif [ "$MESH_AWK_FILE_OK" = "1" ] && [ "$MESH_WIFI_TARGETS_PRESENT" = "1" ]; then
            MESH_WIFI_OK=1
            LOG green "Mesh-Detect WiFi detection: enabled ($WIFI_IFACE on phy1, hopping ch $WIFI_CHANNELS)"
        elif [ "$MESH_AWK_FILE_OK" = "1" ]; then
            LOG yellow "Mesh-Detect WiFi detection: no-op (mesh_detect_targets.conf has no oui:/mac: entries yet)"
        fi
        if [ "$WANT_DEAUTH" = "0" ]; then
            LOG yellow "Deauth/evil-twin detection: disabled (not selected in detection menu)"
        elif [ "$DEAUTH_AWK_FILE_OK" = "1" ]; then
            DEAUTH_OK=1
            LOG green "Deauth/evil-twin detection: enabled ($WIFI_IFACE on phy1, hopping ch $WIFI_CHANNELS)"
        fi
    fi
fi
if [ "$WIFI_RID_OK" = "0" ] && [ "$AWK_FILES_OK" = "1" ] && [ "$WANT_DRONE" = "1" ]; then
    LOG red "Drone WiFi detection: disabled (need awk+iw+tcpdump and a usable phy1)"
fi
if [ "$FLOCK_WIFI_OK" = "0" ] && [ "$FLOCK_AWK_FILE_OK" = "1" ] && [ "$WIFI_RID_OK" = "0" ] && [ "$WANT_FLOCK" = "1" ]; then
    LOG red "Flock WiFi detection: disabled (need awk+iw+tcpdump and a usable phy1)"
fi
if [ "$MESH_WIFI_OK" = "0" ] && [ "$MESH_AWK_FILE_OK" = "1" ] && [ "$MESH_WIFI_TARGETS_PRESENT" = "1" ] && [ "$WIFI_RID_OK" = "0" ] && [ "$WANT_MESH" = "1" ]; then
    LOG red "Mesh-Detect WiFi detection: disabled (need awk+iw+tcpdump and a usable phy1)"
fi
if [ "$DEAUTH_OK" = "0" ] && [ "$DEAUTH_AWK_FILE_OK" = "1" ] && [ "$WIFI_RID_OK" = "0" ] && [ "$WANT_DEAUTH" = "1" ]; then
    LOG red "Deauth/evil-twin detection: disabled (need awk+iw+tcpdump and a usable phy1)"
fi

# ---------------------------------------------------------------------------
# Start background Remote ID monitors
#
# Each pipeline uses an explicit FIFO rather than a shell `cmd | cmd &`
# pipe, specifically so cleanup() can kill the capture tool (hcidump/
# tcpdump) directly by PID instead of relying on it eventually getting
# SIGPIPE on its next write after the awk consumer exits -- with a plain
# pipe, only the last stage's PID is available via $!, so the capture tool
# could linger running (harmlessly, but pointlessly) until its next packet.
# ---------------------------------------------------------------------------
if [ "$BLE_RID_OK" = "1" ]; then
    mkfifo "$BLE_FIFO"
    "$HCIDUMP" -i hci0 --raw > "$BLE_FIFO" 2>"$WORK_DIR/hcidump.log" &
    HCIDUMP_PID=$!
    "$AWK" -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/rid_ble_monitor.awk" \
        < "$BLE_FIFO" >> "$BLE_HITS" 2>"$WORK_DIR/ble_monitor.log" &
    BLE_MON_PID=$!
fi

# Own hcidump process, same adapter, same reasoning as the WiFi detectors'
# own tcpdump processes: rid_ble_monitor.awk's rules end in `next`, so this
# isn't a 3rd -f on that pipeline. HCI monitor sockets support multiple
# simultaneous readers, so this is a second passive listener, not a second
# radio -- and like the drone BLE reader, it only sees advertisements during
# whatever scan window Flock-You's own hcitool lescan cycle has open (hcidump
# doesn't itself enable scanning).
if [ "$TRACKER_BLE_OK" = "1" ]; then
    mkfifo "$TRACKER_FIFO"
    "$HCIDUMP" -i hci0 --raw > "$TRACKER_FIFO" 2>"$WORK_DIR/tracker_hcidump.log" &
    TRACKER_HCIDUMP_PID=$!
    "$AWK" -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/rogue_tracker_monitor.awk" \
        < "$TRACKER_FIFO" >> "$TRACKER_HITS" 2>"$WORK_DIR/tracker_monitor.log" &
    TRACKER_MON_PID=$!
fi

# Own hcidump process, same adapter/reasoning as the tracker BLE reader just
# above -- see flock_ble_monitor.awk's header for the UNVERIFIED-signature
# caveat this detector carries.
if [ "$FLOCK_BLE_UUID_OK" = "1" ]; then
    mkfifo "$FLOCK_BLE_FIFO"
    "$HCIDUMP" -i hci0 --raw > "$FLOCK_BLE_FIFO" 2>"$WORK_DIR/flock_ble_hcidump.log" &
    FLOCK_BLE_HCIDUMP_PID=$!
    "$AWK" -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/flock_ble_monitor.awk" \
        < "$FLOCK_BLE_FIFO" >> "$FLOCK_BLE_HITS" 2>"$WORK_DIR/flock_ble_monitor.log" &
    FLOCK_BLE_MON_PID=$!
fi

# Own hcidump process, same adapter/reasoning as the readers just above --
# see glasses_ble_monitor.awk's header for the UNVERIFIED-signature caveat
# this detector carries.
if [ "$GLASSES_BLE_OK" = "1" ]; then
    mkfifo "$GLASSES_BLE_FIFO"
    "$HCIDUMP" -i hci0 --raw > "$GLASSES_BLE_FIFO" 2>"$WORK_DIR/glasses_ble_hcidump.log" &
    GLASSES_BLE_HCIDUMP_PID=$!
    "$AWK" -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/glasses_ble_monitor.awk" \
        < "$GLASSES_BLE_FIFO" >> "$GLASSES_BLE_HITS" 2>"$WORK_DIR/glasses_ble_monitor.log" &
    GLASSES_BLE_MON_PID=$!
fi

if [ "$WIFI_RID_OK" = "1" ]; then
    mkfifo "$WIFI_FIFO"
    # -l: line-buffer tcpdump's own text output so packets reach the awk
    #     consumer promptly instead of sitting in stdio's pipe-buffering.
    # "type mgt": only beacon/action/etc frames -- we never look at data or
    #     control frames, so filtering them out here saves CPU on both ends.
    "$TCPDUMP" -i "$WIFI_IFACE" -n -l -xx type mgt > "$WIFI_FIFO" 2>"$WORK_DIR/tcpdump.log" &
    TCPDUMP_PID=$!
    "$AWK" -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/rid_wifi_monitor.awk" \
        < "$WIFI_FIFO" >> "$WIFI_HITS" 2>"$WORK_DIR/wifi_monitor.log" &
    WIFI_MON_PID=$!
fi

# Own tcpdump process, same interface, same "type mgt" filter as the drone
# WiFi pipeline above -- deliberately not a 3rd -f on that pipeline's awk
# invocation. See flock_wifi_monitor.awk's header for why: rid_wifi_monitor.awk's
# rules all end in `next`, which would silently block any rule appended
# after it in the same merged awk program. Linux packet sockets support
# multiple simultaneous readers on one interface, so this is a second
# (identically filtered, low-rate) capture process, not a second radio.
if [ "$FLOCK_WIFI_OK" = "1" ]; then
    mkfifo "$FLOCK_WIFI_FIFO"
    "$TCPDUMP" -i "$WIFI_IFACE" -n -l -xx type mgt > "$FLOCK_WIFI_FIFO" 2>"$WORK_DIR/flock_tcpdump.log" &
    FLOCK_TCPDUMP_PID=$!
    "$AWK" -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/flock_wifi_monitor.awk" \
        < "$FLOCK_WIFI_FIFO" >> "$FLOCK_WIFI_HITS" 2>"$WORK_DIR/flock_wifi_monitor.log" &
    FLOCK_WIFI_MON_PID=$!
fi

# Same reasoning as the Flock WiFi pipeline above: its own tcpdump process
# rather than a 4th -f alongside rid_wifi_monitor.awk / flock_wifi_monitor.awk.
if [ "$MESH_WIFI_OK" = "1" ]; then
    mkfifo "$MESH_WIFI_FIFO"
    "$TCPDUMP" -i "$WIFI_IFACE" -n -l -xx type mgt > "$MESH_WIFI_FIFO" 2>"$WORK_DIR/mesh_tcpdump.log" &
    MESH_TCPDUMP_PID=$!
    "$AWK" -v CONFIG_FILE="$MESH_CONFIG_FILE" \
        -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/mesh_wifi_monitor.awk" \
        < "$MESH_WIFI_FIFO" >> "$MESH_WIFI_HITS" 2>"$WORK_DIR/mesh_wifi_monitor.log" &
    MESH_WIFI_MON_PID=$!
fi

# Same reasoning again: its own tcpdump process, 5th reader total on this
# one radio.
if [ "$DEAUTH_OK" = "1" ]; then
    mkfifo "$DEAUTH_FIFO"
    "$TCPDUMP" -i "$WIFI_IFACE" -n -l -xx type mgt > "$DEAUTH_FIFO" 2>"$WORK_DIR/deauth_tcpdump.log" &
    DEAUTH_TCPDUMP_PID=$!
    "$AWK" -v CONFIG_FILE="$TRUSTED_NETWORKS_FILE" \
        -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/deauth_eviltwin_monitor.awk" \
        < "$DEAUTH_FIFO" >> "$DEAUTH_HITS" 2>"$WORK_DIR/deauth_monitor.log" &
    DEAUTH_MON_PID=$!
fi

LOG "Color key:"
LOG yellow   "  FS Ext Battery"
LOG green    "  Penguin"
LOG magenta  "  Pigvision"
LOG cyan     "  Other Flock (BLE name match or WiFi wildcard-probe/IE match)"
LOG yellow   "  Flock? / Flock?? (low-confidence WiFi or UNVERIFIED BLE UUID signature)"
LOG yellow   "  Glasses?? (UNVERIFIED BLE company-ID signature -- Meta/Snap/Bose/Vuzix/XREAL)"
LOG yellow   "  CC Skimmer? (BLE serial-module OUI/name or MAC-embedded manufacture date)"
LOG          "  Mesh-Detect (your OUI/MAC/name watchlist -- uncolored, see mesh_detect_targets.conf)"
LOG red      "  Drone Remote ID / Rogue BLE Tracker / Deauth Flood / Evil-Twin AP (all same color -- distinguished by alert text)"
LOG "----------------------------------"
LOG green    "Press RIGHT any time to flag a device/moment this scan should have caught -- logged to bookmarks_${TIMESTAMP}.txt for later review."
LOG "----------------------------------"

DETECTIONS=0
SEEN_STRONG=""
COUNTER=0

declare -A DRONE_LAST_ALERT
declare -A DRONE_KNOWN
BLE_HITS_OFFSET=0
WIFI_HITS_OFFSET=0
FLOCK_WIFI_HITS_OFFSET=0
MESH_WIFI_HITS_OFFSET=0
TRACKER_HITS_OFFSET=0
FLOCK_BLE_HITS_OFFSET=0
GLASSES_BLE_HITS_OFFSET=0

# Per (mac|protocol) tracker state -- see handle_tracker_line(). Keyed on
# the exact string rogue_tracker_monitor.awk emits as its 3rd field
# (applefindmy/tile/smarttag/fmdn_normal/fmdn_unwanted), so Apple/Samsung/
# Google's MAC rotation naturally starts a fresh persistence count under a
# new key once the MAC changes -- there's no way around that without the
# key-derivation access described in tracker_allowlist.conf's header.
declare -A TRACKER_FIRST_SEEN
declare -A TRACKER_SIGHTINGS
declare -A TRACKER_LAST_ALERT
declare -A TRACKER_SNOOZE
DEAUTH_HITS_OFFSET=0

# Re-read once per main-loop tick (see the while-loop below), same cadence
# as GPS_TAG's own refresh -- so a snooze added via snooze_tracker.sh while
# this session is already running takes effect within one tick, no restart
# needed. Read-only from this process's side; snooze_tracker.sh is the only
# writer, so there's no write/write race to worry about between the two.
# Expired entries are simply never matched (checked at lookup time in
# handle_tracker_line()) -- nothing here prunes the file itself.
load_tracker_snooze() {
    TRACKER_SNOOZE=()
    [ -f "$TRACKER_SNOOZE_FILE" ] || return
    local mac_lc expiry note
    while IFS='|' read -r mac_lc expiry note; do
        [ -z "$mac_lc" ] && continue
        TRACKER_SNOOZE["$mac_lc"]="$expiry"
    done < "$TRACKER_SNOOZE_FILE"
}

# Per-source-MAC deauth-flood rate state (see handle_deauth_line()) and
# per-rogue-BSSID evil-twin alert cooldown state. Both keyed simply (MAC),
# unlike tracker state above -- neither deauth transmitters nor rogue APs
# have a MAC-rotation problem to design around.
declare -A DEAUTH_LAST_COUNT
declare -A DEAUTH_LAST_TIME
declare -A DEAUTH_LAST_ALERT

# Case-insensitive "does haystack contain needle" without a subshell, since
# this runs per BLE-scan-result per cycle and a $(...) fork per check adds up.
mesh_contains_ci() {
    local haystack_lc="${1,,}" needle_lc="${2,,}"
    case "$haystack_lc" in
        *"$needle_lc"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Checks one "MAC NAME" BLE scan result against mesh_detect_targets.conf's
# oui:/mac:/name: lists (already loaded into the MESH_*_TARGETS arrays by
# load_mesh_targets at startup). Echoes "oui:x" / "mac:x" / "name:x" for the
# first match, or nothing.
mesh_ble_match() {
    local mac_lc="${1,,}" name="$2" t
    for t in "${MESH_MAC_TARGETS[@]}"; do
        [ "$mac_lc" = "$t" ] && { echo "mac:$t"; return; }
    done
    local oui_lc="${mac_lc:0:8}"   # "xx:xx:xx"
    for t in "${MESH_OUI_TARGETS[@]}"; do
        [ "$oui_lc" = "$t" ] && { echo "oui:$t"; return; }
    done
    for t in "${MESH_NAME_TARGETS[@]}"; do
        if mesh_contains_ci "$name" "$t"; then echo "name:$t"; return; fi
    done
}

# Checks one "MAC NAME" BLE scan result for the legacy Flock-You BLE-name
# loop below: a name match (now also including "xuntong", the manufacturer
# behind BLE company ID 0x09C8 that flock_ble_monitor.awk treats as an
# UNVERIFIED signature -- a literal advertised-name match on it is a much
# stronger signal than that UUID/company-ID guess, worth catching here even
# though this loop predates that file), OR a known Flock OUI, cross-checked
# against cncartistsec/BluePine-WiFi-Pineapple-Pager's own active
# FLOCKCAM_OUIS list. Kept as its own small array rather than sharing
# flock_wifi_monitor.awk's much larger flock_oui[] (used for 802.11 WiFi
# frames, a different transport this BLE-side loop has no reach into) --
# this loop is deliberately self-contained, "unmodified from Flock-You /
# Flock_Detect" per its own comment below, not wired into the newer awk-
# based system. Deliberately excludes BluePine's own cc:cc:cc entry: every
# other OUI in both lists is a real IEEE registration, cc:cc:cc reads like
# a placeholder/test pattern rather than one, so it's left out here as a
# false-positive risk rather than taken on faith. Echoes "name" or "oui".
flock_ble_match() {
    local mac="$1" name="$2"
    if echo "$name" | grep -qi "fs ext battery\|penguin\|flock\|pigvision\|xuntong"; then
        echo "name"
        return
    fi
    local oui_lc="${mac,,}"
    oui_lc="${oui_lc:0:8}"
    case "$oui_lc" in
        b4:1e:52|58:8e:81|ec:1b:bd|90:35:ea|04:0d:84|f0:82:c0|1c:34:f1|38:5b:44|94:34:69|b4:e3:f9|d4:11:d6)
            echo "oui" ;;
    esac
}

# Checks one "MAC NAME" BLE scan result against known BLE credit-card-
# skimmer signatures -- ported from cncartistsec/BluePine-WiFi-Pineapple-
# Pager's check_bt_ccskimmr(). These are generic HC-05/HC-06-style serial
# Bluetooth modules widely reused as the wireless backend in cheap card
# skimmers -- a name/OUI match alone is a weak signal on its own (the same
# modules show up in countless unrelated hobbyist projects), so this also
# checks whether the MAC's own first 4 octets decode as a plausible
# manufacture date: many of these modules are provisioned from a batch
# whose MAC is assigned from a scheme embedding the date (octet1+octet2 as
# a 4-digit year, octet3 as month, octet4 as day, all read as decimal, not
# hex). Any ONE match (OUI, name, or a valid embedded date) is enough to
# flag, matching upstream. Echoes a short reason string ("oui" / "name:x" /
# "date:YYYY-MM-DD") for the first match, or nothing.
ble_skimmer_match() {
    local mac="$1" name="$2"
    local mac_lc="${mac,,}"
    [ "${mac_lc:0:8}" = "00:06:66" ] && { echo "oui"; return; }
    case "$name" in
        HC-03|HC-05|HC-06|HC-08) echo "name:$name"; return ;;
    esac
    if [[ "$name" == *RNBT* ]]; then
        echo "name:$name"
        return
    fi
    if [[ "$mac" =~ ^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}: ]]; then
        local o1="${mac:0:2}" o2="${mac:3:2}" o3="${mac:6:2}" o4="${mac:9:2}"
        if [[ "$o1$o2" =~ ^[0-9]{4}$ ]] && [[ "$o3" =~ ^[0-9]{2}$ ]] && [[ "$o4" =~ ^[0-9]{2}$ ]]; then
            local year=$((10#$o1$o2)) month=$((10#$o3)) day=$((10#$o4)) curyear
            curyear=$(date +%Y)
            if [ "$year" -ge 2013 ] && [ "$year" -le "$curyear" ] \
               && [ "$month" -ge 1 ] && [ "$month" -le 12 ] \
               && [ "$day" -ge 1 ] && [ "$day" -le 31 ]; then
                echo "date:${o1}${o2}-${o3}-${o4}"
                return
            fi
        fi
    fi
}

# Parse one "wifi_flock_diag|MAC|oui=xx:xx:xx" line from
# flock_wifi_monitor.awk's diagnostic path -- a wildcard-SSID probe from an
# OUI NOT in its known Flock list. Never alerts, never touches SEEN_STRONG/
# DETECTIONS, doesn't even go to the same file as real hits -- purely a
# field-data trail for reviewing after a drive-by ("what OUI was actually
# broadcasting when I remember passing a camera") to catch a real,
# unlisted Flock OUI that flock_wifi_monitor.awk's flock_oui[] should add.
handle_flock_wifi_diag_line() {
    local line="$1"
    local src mac kv
    IFS='|' read -r src mac kv <<< "$line"
    [ -z "$mac" ] && return
    echo "$(date '+%H:%M:%S') | $mac | $kv$GPS_TAG" >> "$FLOCK_DIAG_LOG_FILE"
}

# Parse one "wifi_flock|MAC|wildcard_probe_ie_sig|oui=xx:xx:xx|conf=high" or
# "wifi_flock|MAC|wildcard_probe_oui_only|oui=xx:xx:xx|conf=low|sig=..." line
# from flock_wifi_monitor.awk and LOG/loot/alert it -- same session-lifetime
# dedup (SEEN_STRONG) as the BLE Flock hits below, so a camera caught by both
# radios doesn't double up every cycle.
#
# Physical alert is tiered by confidence (see flock_wifi_monitor.awk's
# DEVIATION FROM UPSTREAM note): conf=high (exact upstream IE signature
# matched) gets the full vibrate+LED. conf=low (OUI+wildcard-probe matched
# but the signature didn't, so it's either a newer/unfingerprinted camera or
# a coincidental OUI hit) still gets logged and counted -- dropping it
# entirely would defeat the point of loosening the match -- but stays
# softer: log line + LOG_FILE entry only, no vibrate/LED, so a low-confidence
# hit doesn't buzz your pocket the same as a confirmed one.
handle_flock_wifi_line() {
    local line="$1"
    local src mac msgtype kv
    IFS='|' read -r src mac msgtype kv <<< "$line"
    [ -z "$mac" ] && return
    if echo "$SEEN_STRONG" | grep -q "$mac WIFI_FLOCK"; then return; fi

    local conf="high"
    case "$kv" in
        *"conf=low"*) conf="low" ;;
        *"conf=medium"*) conf="medium" ;;
    esac

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    if [ "$conf" = "high" ]; then
        ENTRY="DECT: $CURRENT_TIME | $mac | Flock (WiFi $msgtype, $kv)$GPS_TAG"
        LOG cyan "$ENTRY"
    else
        ENTRY="DECT: $CURRENT_TIME | $mac | Flock? (WiFi $msgtype, $kv)$GPS_TAG"
        LOG yellow "$ENTRY"
    fi
    echo "$ENTRY" >> "$LOG_FILE"
    DETECTIONS=$((DETECTIONS + 1))
    COUNTER=$((COUNTER + 1))
    if [ "$conf" = "high" ]; then
        stealth_blink
    fi
    SEEN_STRONG="$SEEN_STRONG $mac WIFI_FLOCK"
}

# Parse one "ble_flock|MAC|uuid_09c8" line from flock_ble_monitor.awk and
# LOG/loot it -- see that file's header for why this signature is UNVERIFIED
# (never demonstrated against a real camera by anyone this was sourced
# from). Log-only: no vibrate/LED at all, even softer than a Flock WiFi
# conf=low hit, since unlike that one this entire detector is an unproven
# lead rather than a real signature with an unmatched fingerprint.
handle_flock_ble_line() {
    local line="$1"
    local src mac msgtype kv
    IFS='|' read -r src mac msgtype kv <<< "$line"
    [ -z "$mac" ] && return
    if echo "$SEEN_STRONG" | grep -q "$mac BLE_FLOCK_UUID"; then return; fi

    # $kv is just "|rssi=N" or "" -- flock_ble_monitor.awk has no other
    # trailing fields on this line, unlike the other handlers that need to
    # split rssi out of a value they'd otherwise use for something else.
    local rssi_sfx=""
    case "$kv" in
        *rssi=*) rssi_sfx=" | rssi=${kv#*rssi=}" ;;
    esac

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    ENTRY="DECT: $CURRENT_TIME | $mac | Flock?? (BLE $msgtype, unverified signature)$rssi_sfx$GPS_TAG"
    LOG yellow "$ENTRY"
    echo "$ENTRY" >> "$LOG_FILE"
    DETECTIONS=$((DETECTIONS + 1))
    COUNTER=$((COUNTER + 1))
    SEEN_STRONG="$SEEN_STRONG $mac BLE_FLOCK_UUID"
}

# Parse one "ble_glasses|MAC|BRAND|cid=0xNNNN|rssi=N" line from
# glasses_ble_monitor.awk and LOG/loot it -- see that file's header for why
# these company-ID-to-brand mappings are UNVERIFIED (sourced from a repo
# that itself cites no source for any of them). Log-only: no vibrate/LED,
# same soft tier as the Flock BLE UUID hits, for the same reason -- this is
# an unproven lead, not a confirmed signature.
handle_glasses_ble_line() {
    local line="$1"
    local src mac brand kv
    IFS='|' read -r src mac brand kv <<< "$line"
    [ -z "$mac" ] && return
    if echo "$SEEN_STRONG" | grep -q "$mac BLE_GLASSES"; then return; fi

    local rssi_sfx=""
    case "$kv" in
        *rssi=*) rssi_sfx=" | rssi=${kv#*rssi=}" ;;
    esac
    local cid="${kv%%|rssi=*}"

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    ENTRY="DECT: $CURRENT_TIME | $mac | Glasses?? ($brand, unverified signature, $cid)$rssi_sfx$GPS_TAG"
    LOG yellow "$ENTRY"
    echo "$ENTRY" >> "$LOG_FILE"
    DETECTIONS=$((DETECTIONS + 1))
    COUNTER=$((COUNTER + 1))
    SEEN_STRONG="$SEEN_STRONG $mac BLE_GLASSES"
}

# Vendor-specific alert labels for select Mesh-Detect OUI/MAC hits (used by
# both the WiFi and BLE hit handlers below). Most hits just show the generic
# "Mesh-Detect (...)" phrasing; a few high-confidence single-vendor OUI
# blocks get a specific name instead -- not exhaustive, and deliberately not
# derived from mesh_detect_targets.conf's inline vendor comments (those are
# stripped at parse time by both the awk and bash loaders, so displaying
# them properly would mean carrying vendor names through the config format
# as real data, not comments -- more than this needed for one vendor). Add
# more entries here as wanted. Takes the raw OUI/MAC value (the part after
# "oui:"/"mac:" in a matchkind string), not the whole matchkind.
mesh_vendor_label() {
    case "${1,,}" in
        00:25:df|00:1f:55|00:0f:13)
            # Axon Enterprise (body cams, Fleet dash cams, Taser 7/10) --
            # OUI 00:25:DF is IEEE-registered to "Axon Enterprise, Inc."
            # (formerly "TASER International, Inc."); 00:1F:55/00:0F:13 are
            # the same vendor's other allocated blocks. Cross-checked
            # against colonelpanichacks/oui-spy-unified-blue's PRESET_AXON
            # (src/raw/detector.cpp) which also lists a BLE Company ID
            # (0x034D) and Service UUID (0xFC81) for this vendor -- not
            # checked here, since that needs raw BLE advertisement parsing
            # (own hcidump reader) that this OUI-only WiFi/BLE lookup
            # doesn't have; see rogue_tracker_monitor.awk for what that
            # kind of check looks like if this ever gets built.
            echo "Axon Cam" ;;
        00:58:28|00:c0:d4|84:70:03)
            # Axon's separate networking-gear OUI block (not body cams --
            # per OSINTI4L/Fuzz_Finder, "Axon OUIs dedicated to them for
            # networking gear"), cross-referenced against
            # cncartistsec/BluePine-WiFi-Pineapple-Pager's own active
            # AXONCAMS_OUI list, which credits the same source.
            echo "Axon Networking Gear" ;;
        *) echo "" ;;
    esac
}

# Parse one "wifi_mesh|MAC|oui:x" or "wifi_mesh|MAC|mac:x" line from
# mesh_wifi_monitor.awk and LOG/loot/vibrate it. Same session dedup pattern
# as the other detectors, keyed separately (WIFI_MESH) so it doesn't collide
# with a Flock or drone hit on the same MAC.
handle_mesh_wifi_line() {
    local line="$1"
    local src mac matchkind
    IFS='|' read -r src mac matchkind <<< "$line"
    [ -z "$mac" ] && return
    if echo "$SEEN_STRONG" | grep -q "$mac WIFI_MESH\|$mac MESH_BLE"; then return; fi

    # wifi_mesh|MAC|matchkind was an exact 3-field fit for the 3 `read` vars
    # above before RSSI was added, so a trailing "|rssi=N" lands INSIDE
    # $matchkind instead of its own field -- split it back out here, since
    # mesh_vendor_label() below does an exact `case` match against
    # matchkind's OUI/MAC and would silently stop matching anything with
    # "|rssi=-45" stuck on the end.
    local rssi=""
    case "$matchkind" in
        *"|rssi="*) rssi="${matchkind#*|rssi=}"; matchkind="${matchkind%%|rssi=*}" ;;
    esac
    local rssi_sfx=""
    [ -n "$rssi" ] && rssi_sfx=" | rssi=$rssi"

    local vendor
    vendor=$(mesh_vendor_label "${matchkind#*:}")

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    if [ -n "$vendor" ]; then
        ENTRY="DECT: $CURRENT_TIME | $mac | $vendor detected (WiFi, $matchkind)$rssi_sfx$GPS_TAG"
    else
        ENTRY="DECT: $CURRENT_TIME | $mac | Mesh-Detect (WiFi, $matchkind)$rssi_sfx$GPS_TAG"
    fi
    LOG "$ENTRY"
    echo "$ENTRY" >> "$LOG_FILE"
    DETECTIONS=$((DETECTIONS + 1))
    COUNTER=$((COUNTER + 1))
    stealth_blink
    SEEN_STRONG="$SEEN_STRONG $mac WIFI_MESH"
}

# Human-readable label per rogue_tracker_monitor.awk protocol tag.
tracker_protocol_label() {
    case "$1" in
        applefindmy)   echo "Apple Find My (AirTag or similar)" ;;
        tile)          echo "Tile" ;;
        smarttag)      echo "Samsung SmartTag" ;;
        fmdn_normal)   echo "Google Find My Device Network" ;;
        fmdn_unwanted) echo "Google Find My Device Network -- device itself flagged unwanted tracking" ;;
        *)             echo "$1" ;;
    esac
}

# Parse one "ble_tracker|MAC|protocol|detail" line from
# rogue_tracker_monitor.awk. Every non-allowlisted sighting is logged
# (loot is never throttled, matching every other detector here), but the
# LED/vibrate/RINGTONE alert only fires once the persistence threshold is
# crossed (or immediately for fmdn_unwanted, which is the device itself
# self-reporting) -- see this file's KNOWN LIMITATIONS on what that
# heuristic does and doesn't catch, and TRACKER_PERSISTENCE_* above for the
# thresholds.
handle_tracker_line() {
    local line="$1"
    local src mac protocol detail
    IFS='|' read -r src mac protocol detail <<< "$line"
    [ -z "$mac" ] && return

    local mac_lc="${mac,,}"
    [ -n "${TRACKER_ALLOWLIST[$mac_lc]:-}" ] && return

    local now
    now=$(date +%s)
    local snooze_until="${TRACKER_SNOOZE[$mac_lc]:-0}"
    [ "$now" -lt "$snooze_until" ] && return

    local key="${mac}|${protocol}"
    [ -z "${TRACKER_FIRST_SEEN[$key]:-}" ] && TRACKER_FIRST_SEEN[$key]=$now
    TRACKER_SIGHTINGS[$key]=$(( ${TRACKER_SIGHTINGS[$key]:-0} + 1 ))

    local label
    label=$(tracker_protocol_label "$protocol")
    echo "$(date '+%H:%M:%S') | $mac | $label | sighting=${TRACKER_SIGHTINGS[$key]} | $detail$GPS_TAG" >> "$TRACKER_LOG_FILE"

    local age=$(( now - TRACKER_FIRST_SEEN[$key] ))
    local eligible=0
    if [ "$protocol" = "fmdn_unwanted" ]; then
        eligible=1
    elif [ "$age" -ge "$TRACKER_PERSISTENCE_SECONDS" ] && [ "${TRACKER_SIGHTINGS[$key]}" -ge "$TRACKER_PERSISTENCE_MIN_SIGHTINGS" ]; then
        eligible=1
    fi
    [ "$eligible" = "0" ] && return

    local last="${TRACKER_LAST_ALERT[$key]:-0}"
    [ $((now - last)) -lt "$TRACKER_ALERT_COOLDOWN" ] && return
    TRACKER_LAST_ALERT[$key]=$now

    local minutes=$(( age / 60 ))
    LOG red "ROGUE TRACKER [$label] $mac - seen ${TRACKER_SIGHTINGS[$key]}x over ${minutes}min"
    stealth_alert "ROGUE TRACKER" "$label\n$mac\nseen ${TRACKER_SIGHTINGS[$key]}x over ${minutes}min"
    DETECTIONS=$((DETECTIONS + 1))
}

# Parse one line from deauth_eviltwin_monitor.awk -- either
# "deauth|SRC|DST|deauth|COUNT" / "...|disassoc|COUNT", or
# "eviltwin|BSSID|SSID|rogue_bssid". Every sighting is logged (loot never
# throttled); the loud LED/vibrate/RINGTONE alert only fires once a real
# flood rate is confirmed (deauth) or immediately (evil-twin -- a rogue AP
# existing at all is already the signal, no rate needed), each cooldown-
# throttled separately so a sustained attack doesn't spam the UI.
handle_deauth_line() {
    local line="$1"
    local kind mac f3 f4 f5
    IFS='|' read -r kind mac f3 f4 f5 <<< "$line"
    [ -z "$mac" ] && return

    local now
    now=$(date +%s)

    # deauth_eviltwin_monitor.awk's deauth line already had 5 pipe-fields
    # (kind,mac,dst,subtype,count) before RSSI was added, an exact fit for
    # the 5 `read` vars above -- so a trailing "|rssi=N" there lands INSIDE
    # $f5 as e.g. "10|rssi=-45" (embedded pipe) instead of a clean count,
    # breaking the arithmetic below. eviltwin's line only had 4 fields
    # before, so its optional rssi gets its own clean 5th field instead
    # ("rssi=-45", no embedded pipe) -- the two branches need different
    # extraction because of that, not one shared one.
    local rssi=""
    if [ "$kind" = "deauth" ]; then
        case "$f5" in
            *"|rssi="*) rssi="${f5#*|rssi=}"; f5="${f5%%|rssi=*}" ;;
        esac
    elif [ "$kind" = "eviltwin" ]; then
        case "$f5" in
            rssi=*) rssi="${f5#rssi=}" ;;
        esac
    fi
    local rssi_sfx=""
    [ -n "$rssi" ] && rssi_sfx=" | rssi=$rssi"

    if [ "$kind" = "deauth" ]; then
        local dst="$f3" subtype="$f4" count="$f5"
        echo "$(date '+%H:%M:%S') | deauth | $mac -> $dst | $subtype | count=$count$rssi_sfx$GPS_TAG" >> "$DEAUTH_LOG_FILE"

        local last_count="${DEAUTH_LAST_COUNT[$mac]:-0}" last_time="${DEAUTH_LAST_TIME[$mac]:-$now}"
        local delta_count=$((count - last_count))
        local delta_time=$((now - last_time))
        DEAUTH_LAST_COUNT[$mac]=$count
        DEAUTH_LAST_TIME[$mac]=$now
        # First-ever sighting for this MAC (last_time defaulted to now) has
        # delta_time=0 -- skip the rate check entirely rather than divide
        # by zero or cross-multiply against a meaningless zero window.
        [ "$delta_time" -le 0 ] && return
        # Cross-multiplied, not divided: delta_count/delta_time >= RATE
        # becomes delta_count >= RATE * delta_time, avoiding bash's
        # integer-only arithmetic rounding a real fractional rate down to 0.
        if [ "$delta_count" -ge "$DEAUTH_FLOOD_MIN_DELTA" ] && [ "$delta_count" -ge "$((DEAUTH_FLOOD_RATE * delta_time))" ]; then
            local last_alert="${DEAUTH_LAST_ALERT[$mac]:-0}"
            [ $((now - last_alert)) -lt "$DEAUTH_ALERT_COOLDOWN" ] && return
            DEAUTH_LAST_ALERT[$mac]=$now
            LOG red "DEAUTH FLOOD [$mac] -> $dst - ${delta_count} ${subtype} frames in ${delta_time}s"
            stealth_alert "DEAUTH FLOOD" "$mac\n${delta_count} ${subtype} in ${delta_time}s"
            DETECTIONS=$((DETECTIONS + 1))
        fi
        return
    fi

    if [ "$kind" = "eviltwin" ]; then
        local ssid="$f3"
        echo "$(date '+%H:%M:%S') | eviltwin | bssid=$mac | ssid=$ssid$rssi_sfx$GPS_TAG" >> "$DEAUTH_LOG_FILE"

        local last_alert="${DEAUTH_LAST_ALERT[$mac]:-0}"
        [ $((now - last_alert)) -lt "$DEAUTH_ALERT_COOLDOWN" ] && return
        DEAUTH_LAST_ALERT[$mac]=$now
        LOG red "EVIL TWIN AP [$ssid] $mac is NOT a known BSSID for this SSID"
        stealth_alert "EVIL TWIN AP" "SSID: $ssid\nRogue BSSID: $mac"
        DETECTIONS=$((DETECTIONS + 1))
    fi
}

# Parse one "SRC|MAC|MSG_TYPE|k=v;k=v;..." line and LOG/alert/loot it.
handle_rid_line() {
    local line="$1"
    local src mac msgtype kv
    IFS='|' read -r src mac msgtype kv <<< "$line"
    [ -z "$mac" ] && return

    # emit_hit()'s optional rssi lands as a trailing "|rssi=N" on $kv --
    # stripped out here BEFORE the grep -o 'field=[^;]*' extractions below,
    # since those have no semicolon after the last field and would
    # otherwise swallow "|rssi=N" straight into lon/operator_lon's value
    # (lon and operator_lon are always the last field in their message
    # types' k=v;k=v;... string -- see decode_location()/decode_system()).
    local rssi=""
    case "$kv" in
        *"|rssi="*) rssi="${kv#*|rssi=}"; kv="${kv%%|rssi=*}" ;;
    esac
    local rssi_sfx=""
    [ -n "$rssi" ] && rssi_sfx=" | rssi=$rssi"

    # $kv's own lat/lon (basic_id/location/system messages) is the DRONE's
    # or its operator's self-reported position via Remote ID -- unrelated to
    # $GPS_TAG below, which is where the Pager itself was standing when it
    # heard it.
    echo "$(date '+%H:%M:%S') | $src | $mac | $msgtype | $kv$rssi_sfx$GPS_TAG" >> "$DRONE_LOG_FILE"

    local summary="$msgtype"
    case "$msgtype" in
        basic_id)
            local uas_id
            uas_id=$(echo "$kv" | grep -o 'uas_id=[^;]*' | cut -d= -f2-)
            [ -n "$uas_id" ] && summary="ID:$uas_id"
            DRONE_KNOWN["$mac|id"]="$uas_id"
            ;;
        location)
            local lat lon
            lat=$(echo "$kv" | grep -o 'lat=[^;]*' | cut -d= -f2-)
            lon=$(echo "$kv" | grep -o 'lon=[^;]*' | cut -d= -f2-)
            if [ -n "$lat" ] && [ -n "$lon" ]; then
                summary="POS:$lat,$lon"
                DRONE_KNOWN["$mac|pos"]="$lat,$lon"
            fi
            ;;
        system)
            local oplat oplon
            oplat=$(echo "$kv" | grep -o 'operator_lat=[^;]*' | cut -d= -f2-)
            oplon=$(echo "$kv" | grep -o 'operator_lon=[^;]*' | cut -d= -f2-)
            [ -n "$oplat" ] && summary="OPERATOR:$oplat,$oplon"
            ;;
    esac

    local now last
    now=$(date +%s)
    last="${DRONE_LAST_ALERT[$mac]:-0}"
    if [ $((now - last)) -ge "$ALERT_COOLDOWN" ]; then
        DRONE_LAST_ALERT["$mac"]=$now
        local known_id="${DRONE_KNOWN[$mac|id]}"
        local label="$mac"
        [ -n "$known_id" ] && label="$mac ($known_id)"
        LOG red "DRONE [$src] $label - $summary"
        stealth_alert "DRONE REMOTE ID" "$label\n$summary\nvia $src"
    fi
}

# Best-effort GPS fix via the Pager's own GPS_GET command (/usr/bin/GPS_GET,
# a thin wrapper over pineapd's HTTP API -- same platform-builtin convention
# already used for LOG/LED/RINGTONE/ALERT_RINGTONE elsewhere in this file,
# rather than reinventing GPS handling by talking to gpsd/gpspipe directly).
# Confirmed live: prints "LAT LON ALT SPEED", space-separated, and "0 0 0 0"
# when there's no hardware or no fix yet -- the same no-fix sentinel another
# Pager Bluetooth payload (cncartistsec/BluePine) already checks for, so
# this isn't a guessed convention. `timeout` guards it regardless: confirmed
# live GPS_GET's own runtime varies (roughly 2-3s with no fix in testing)
# rather than failing instantly like a dead socket would. No GPS hardware /
# no fix is the expected, common case, not an error -- prints nothing and
# every call site below just omits the tag. Called once per main-loop tick
# (below), not per hit, so a burst of several detections in one tick shares
# one GPS_GET call instead of one each.
get_gps_fix() {
    local out lat lon
    out=$(timeout 3 GPS_GET 2>/dev/null)
    [ -z "$out" ] && return
    [ "$out" = "0 0 0 0" ] && return
    read -r lat lon _ <<< "$out"
    [ -z "$lat" ] && return
    [ -z "$lon" ] && return
    echo "$lat,$lon"
}

# Manual "flag this moment for later analysis" -- press RIGHT on the Pager
# any time you notice something the detectors should have caught (or just
# want to mark for review), and it gets logged with a timestamp and GPS fix
# (if available) to BOOKMARK_LOG_FILE. Confirmed live: WAIT_FOR_INPUT
# returns "RIGHT" for this device's RIGHT button (same command the stock
# BUTTON_COMBO example payload already runs in its own background loop --
# this isn't a new pattern for this platform, just the same one applied
# here).
#
# Runs as its OWN background loop, separate from the main detection loop
# below, so a WAIT_FOR_INPUT call (which blocks until a button is pressed)
# never stalls detection. Calls get_gps_fix() itself rather than reading
# the main loop's $GPS_TAG -- this function is forked once at startup, so
# it would otherwise only ever see whatever $GPS_TAG held at that exact
# moment (bash background jobs don't see the parent's later variable
# updates), not a fresh fix at the time of the actual button press.
#
# Double vibrate pulse (not the single pulse a real detection uses)
# specifically so a bookmark press feels different from a detection alert
# -- confirms the press registered without having to look at the screen.
bookmark_watcher() {
    local pressed n gps_fix gps_sfx
    n=0
    while true; do
        pressed=$(WAIT_FOR_INPUT 2>/dev/null)
        if [ "$pressed" = "RIGHT" ]; then
            n=$((n + 1))
            gps_fix=$(get_gps_fix)
            gps_sfx=""
            [ -n "$gps_fix" ] && gps_sfx=" | gps=$gps_fix"
            echo "$(date '+%H:%M:%S') | bookmark #$n$gps_sfx" >> "$BOOKMARK_LOG_FILE"
            if [ -f /sys/class/gpio/vibrator/value ]; then
                echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
                sleep 0.12
                echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
                sleep 0.1
                echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
                sleep 0.12
                echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
            fi
        fi
    done
}
if command -v WAIT_FOR_INPUT >/dev/null 2>&1; then
    bookmark_watcher &
    BOOKMARK_WATCHER_PID=$!
    LOG green "Bookmark: enabled (press RIGHT to flag a moment for later analysis)"
else
    LOG red "Bookmark: disabled (WAIT_FOR_INPUT not found)"
fi

while true; do
    # Refreshed once per tick; GPS_TAG is what every hit logged this tick
    # appends to its line (" | gps=LAT,LON", or nothing without a fix) --
    # see get_gps_fix() above.
    GPS_FIX=$(get_gps_fix)
    GPS_TAG=""
    [ -n "$GPS_FIX" ] && GPS_TAG=" | gps=$GPS_FIX"

    load_tracker_snooze

    # hcitool lescan is the shared scan-enabler every hcidump-based BLE
    # detector piggybacks on (Flock BLE name match below, Mesh-Detect BLE
    # below, and the independent Drone/Tracker/Flock-UUID hcidump readers
    # started earlier -- hcidump alone never enables scanning, see this
    # file's KNOWN LIMITATIONS). Skipped entirely when no BLE-side category
    # is wanted -- the loop's own `sleep 3` at the bottom still paces it, so
    # this doesn't turn into a busy-loop, it just iterates faster and spends
    # that time draining WiFi-side hits instead.
    if [ "$WANT_FLOCK" = "1" ] || [ "$WANT_MESH" = "1" ] || [ "$WANT_TRACKER" = "1" ] || [ "$WANT_DRONE" = "1" ] || [ "$WANT_SKIMMER" = "1" ]; then
    # --- Flock Safety BLE scan cycle (unmodified from Flock-You / Flock_Detect) ---
    hciconfig hci0 down 2>>"$LOG_FILE"
    hciconfig hci0 reset 2>>"$LOG_FILE"
    hciconfig hci0 up 2>>"$LOG_FILE"
    timeout 18 hcitool lescan --duplicates > /tmp/hci_scan.txt 2>>"$LOG_FILE" &
    PID=$!
    sleep 12
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    if [ "$WANT_FLOCK" = "1" ] && [ -s /tmp/hci_scan.txt ]; then
        while read -r full_line; do
            MAC=$(echo "$full_line" | awk '{print $1}')
            NAME=$(echo "$full_line" | cut -d' ' -f2-)
            [ -z "$MAC" ] && continue
            if echo "$SEEN_STRONG" | grep -q "$MAC $NAME"; then continue; fi
            MATCH=$(flock_ble_match "$MAC" "$NAME")
            [ -z "$MATCH" ] && continue
            CURRENT_TIME=$(date '+%H:%M:%S')
            ENTRY="DECT: $CURRENT_TIME | $MAC | $NAME$GPS_TAG"
            if echo "$NAME" | grep -qi "fs ext battery"; then
                LOG yellow "$ENTRY"
            elif echo "$NAME" | grep -qi "penguin"; then
                LOG green "$ENTRY"
            elif echo "$NAME" | grep -qi "pigvision"; then
                LOG magenta "$ENTRY"
            elif echo "$NAME" | grep -qi "flock\|xuntong"; then
                LOG cyan "$ENTRY"
            elif [ "$MATCH" = "oui" ]; then
                # No recognized name, but the OUI itself matched
                # FLOCKCAM_OUIS -- same "Other Flock" tier as a bare "flock"
                # name match above, just reached via the MAC instead.
                LOG cyan "$ENTRY"
            else
                LOG "$ENTRY"
            fi
            echo "$ENTRY" >> "$LOG_FILE"
            DETECTIONS=$((DETECTIONS + 1))
            COUNTER=$((COUNTER + 1))
            if [ $((COUNTER % 10)) -eq 0 ]; then
                LOG " "
                LOG yellow   "FS Ext Battery"
                LOG green    "Penguin"
                LOG magenta  "Pigvision"
                LOG cyan     "Other Flock"
                LOG " "
            fi
            stealth_blink
            SEEN_STRONG="$SEEN_STRONG $MAC $NAME"
        done < <(sort -u /tmp/hci_scan.txt)
    fi

    # --- Mesh-Detect BLE scan: reuse the same hcitool lescan dump above, ---
    # --- checked against mesh_detect_targets.conf instead of Flock names ---
    # Process substitution (not a `cmd | while` pipe), same reasoning as the
    # WiFi drains below, so SEEN_STRONG updates persist in this shell.
    if [ "$MESH_BLE_OK" = "1" ] && [ -s /tmp/hci_scan.txt ]; then
        while read -r full_line; do
            MAC=$(echo "$full_line" | awk '{print $1}')
            NAME=$(echo "$full_line" | cut -d' ' -f2-)
            [ -z "$MAC" ] && continue
            if echo "$SEEN_STRONG" | grep -q "$MAC WIFI_MESH\|$MAC MESH_BLE"; then continue; fi
            MATCH=$(mesh_ble_match "$MAC" "$NAME")
            [ -z "$MATCH" ] && continue
            CURRENT_TIME=$(date '+%H:%M:%S')
            VENDOR=$(mesh_vendor_label "${MATCH#*:}")
            if [ -n "$VENDOR" ]; then
                ENTRY="DECT: $CURRENT_TIME | $MAC | $VENDOR detected (BLE \"$NAME\", $MATCH)$GPS_TAG"
            else
                ENTRY="DECT: $CURRENT_TIME | $MAC | Mesh-Detect (BLE \"$NAME\", $MATCH)$GPS_TAG"
            fi
            LOG "$ENTRY"
            echo "$ENTRY" >> "$LOG_FILE"
            DETECTIONS=$((DETECTIONS + 1))
            COUNTER=$((COUNTER + 1))
            stealth_blink
            SEEN_STRONG="$SEEN_STRONG $MAC MESH_BLE"
        done < <(sort -u /tmp/hci_scan.txt)
    fi

    # --- BLE skimmer scan: reuse the same hcitool lescan dump above, ---
    # --- checked against ble_skimmer_match() instead of Flock/Mesh names ---
    if [ "$WANT_SKIMMER" = "1" ] && [ -s /tmp/hci_scan.txt ]; then
        while read -r full_line; do
            MAC=$(echo "$full_line" | awk '{print $1}')
            NAME=$(echo "$full_line" | cut -d' ' -f2-)
            [ -z "$MAC" ] && continue
            if echo "$SEEN_STRONG" | grep -q "$MAC BLE_SKIMMER"; then continue; fi
            MATCH=$(ble_skimmer_match "$MAC" "$NAME")
            [ -z "$MATCH" ] && continue
            CURRENT_TIME=$(date '+%H:%M:%S')
            ENTRY="DECT: $CURRENT_TIME | $MAC | CC Skimmer? (BLE \"$NAME\", $MATCH)$GPS_TAG"
            LOG yellow "$ENTRY"
            echo "$ENTRY" >> "$LOG_FILE"
            DETECTIONS=$((DETECTIONS + 1))
            COUNTER=$((COUNTER + 1))
            stealth_blink
            SEEN_STRONG="$SEEN_STRONG $MAC BLE_SKIMMER"
        done < <(sort -u /tmp/hci_scan.txt)
    fi
    fi   # closes the WANT_FLOCK/WANT_MESH/WANT_TRACKER/WANT_DRONE/WANT_SKIMMER BLE-scan gate above

    # --- Flock Safety WiFi scan: drain whatever flock_wifi_monitor.awk found ---
    # Uses process substitution (not a `cmd | while` pipe) so the SEEN_STRONG
    # update inside handle_flock_wifi_line persists in *this* shell -- see the
    # comment on the drone RID drains below for why a plain pipe would lose it.
    if [ "$FLOCK_WIFI_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$FLOCK_WIFI_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$FLOCK_WIFI_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    case "$line" in
                        wifi_flock_diag\|*) handle_flock_wifi_diag_line "$line" ;;
                        *) handle_flock_wifi_line "$line" ;;
                    esac
                fi
            done < <(tail -c "+$((FLOCK_WIFI_HITS_OFFSET + 1))" "$FLOCK_WIFI_HITS")
            FLOCK_WIFI_HITS_OFFSET=$NEW_SIZE
        fi
    fi

    # --- Mesh-Detect WiFi scan: drain whatever mesh_wifi_monitor.awk found ---
    if [ "$MESH_WIFI_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$MESH_WIFI_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$MESH_WIFI_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_mesh_wifi_line "$line"
            done < <(tail -c "+$((MESH_WIFI_HITS_OFFSET + 1))" "$MESH_WIFI_HITS")
            MESH_WIFI_HITS_OFFSET=$NEW_SIZE
        fi
    fi

    # --- Rogue BLE tracker: drain whatever rogue_tracker_monitor.awk found ---
    if [ "$TRACKER_BLE_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$TRACKER_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$TRACKER_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_tracker_line "$line"
            done < <(tail -c "+$((TRACKER_HITS_OFFSET + 1))" "$TRACKER_HITS")
            TRACKER_HITS_OFFSET=$NEW_SIZE
        fi
    fi

    # --- Flock BLE (UUID 0x09C8): drain whatever flock_ble_monitor.awk found,
    # --- see that file's header for why this is an UNVERIFIED signature ---
    if [ "$FLOCK_BLE_UUID_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$FLOCK_BLE_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$FLOCK_BLE_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_flock_ble_line "$line"
            done < <(tail -c "+$((FLOCK_BLE_HITS_OFFSET + 1))" "$FLOCK_BLE_HITS")
            FLOCK_BLE_HITS_OFFSET=$NEW_SIZE
        fi
    fi

    # --- Smart-glasses BLE (company ID): drain whatever glasses_ble_
    # --- monitor.awk found, see that file's header for why this is an
    # --- UNVERIFIED signature set ---
    if [ "$GLASSES_BLE_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$GLASSES_BLE_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$GLASSES_BLE_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_glasses_ble_line "$line"
            done < <(tail -c "+$((GLASSES_BLE_HITS_OFFSET + 1))" "$GLASSES_BLE_HITS")
            GLASSES_BLE_HITS_OFFSET=$NEW_SIZE
        fi
    fi

    # --- Deauth/evil-twin: drain whatever deauth_eviltwin_monitor.awk found ---
    if [ "$DEAUTH_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$DEAUTH_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$DEAUTH_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_deauth_line "$line"
            done < <(tail -c "+$((DEAUTH_HITS_OFFSET + 1))" "$DEAUTH_HITS")
            DEAUTH_HITS_OFFSET=$NEW_SIZE
        fi
    fi

    # --- Drone Remote ID: drain whatever the background monitors found ---
    # Size is snapshotted and the offset advanced in *this* shell, not inside
    # the process substitution below (which runs in a subshell -- a variable
    # updated there would be lost when it exits). That keeps this O(new
    # bytes) per cycle instead of silently reprocessing the whole file
    # forever, which is what happens if the offset update lives in the subshell.
    if [ "$BLE_RID_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$BLE_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$BLE_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_rid_line "$line"
            done < <(tail -c "+$((BLE_HITS_OFFSET + 1))" "$BLE_HITS")
            BLE_HITS_OFFSET=$NEW_SIZE
        fi
    fi
    if [ "$WIFI_RID_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$WIFI_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$WIFI_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_rid_line "$line"
            done < <(tail -c "+$((WIFI_HITS_OFFSET + 1))" "$WIFI_HITS")
            WIFI_HITS_OFFSET=$NEW_SIZE
        fi
    fi

    sleep 3
done
exit 0
