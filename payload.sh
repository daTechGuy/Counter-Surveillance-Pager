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
# Original Flock-You Contributors: colonelpanichacks, Grok (xAI), Brandon Starkweather
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
#     for review) -- see do_bookmark()'s comment for why this is a menu
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
# Date-based, bumped by hand in the VERSION file alongside each dated git
# tag (e.g. v2026.08.19) -- not read from git itself, since the deployed
# copy on the device is a plain file transfer (pscp), not a git checkout,
# so there's no .git directory here to ask. Missing file (e.g. an older
# deploy from before this existed) falls back to "unknown" rather than
# failing -- this is purely informational, never gates anything.
SCRIPT_VERSION="unknown"
[ -f "$SCRIPT_DIR/VERSION" ] && SCRIPT_VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null)
[ -z "$SCRIPT_VERSION" ] && SCRIPT_VERSION="unknown"

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
echo "Counter-Surveillance-Pager v$SCRIPT_VERSION started at $(date)" > "$LOG_FILE"
echo "Drone Remote ID log started at $(date)" > "$DRONE_LOG_FILE"

BLE_HITS="$WORK_DIR/ble_rid_hits.log"
WIFI_HITS="$WORK_DIR/wifi_rid_hits.log"
FLOCK_WIFI_HITS="$WORK_DIR/flock_wifi_hits.log"
FLOCK_ADDR1_HITS="$WORK_DIR/flock_addr1_hits.log"
MESH_WIFI_HITS="$WORK_DIR/mesh_wifi_hits.log"
TRACKER_HITS="$WORK_DIR/tracker_hits.log"
FLOCK_BLE_HITS="$WORK_DIR/flock_ble_hits.log"
GLASSES_BLE_HITS="$WORK_DIR/glasses_ble_hits.log"
DEAUTH_HITS="$WORK_DIR/deauth_eviltwin_hits.log"
touch "$BLE_HITS" "$WIFI_HITS" "$FLOCK_WIFI_HITS" "$FLOCK_ADDR1_HITS" "$MESH_WIFI_HITS" "$TRACKER_HITS" "$FLOCK_BLE_HITS" "$GLASSES_BLE_HITS" "$DEAUTH_HITS"
# BLE_FIFO is now shared by all 4 BLE hcidump detectors (Drone RID/Rogue
# Trackers/Flock BLE UUID/Smart Glasses), same as MGT_RAW_FIFO below is
# shared by the WiFi ones -- TRACKER_FIFO/FLOCK_BLE_FIFO/GLASSES_BLE_FIFO
# are gone, each of those detectors' own FIFO before that merge. See the
# BLE pipeline's own comment, near where it starts, for the full story.
BLE_FIFO="$WORK_DIR/ble_raw.fifo"
FLOCK_ADDR1_FIFO="$WORK_DIR/flock_addr1_raw.fifo"
# Drone WiFi RID/Flock WiFi/Mesh-Detect WiFi/Deauth used to each get their
# own FIFO here (WIFI_FIFO/FLOCK_WIFI_FIFO/MESH_WIFI_FIFO/DEAUTH_FIFO) --
# removed once those four were merged into one shared "type mgt" capture
# AND decode process reading directly from MGT_RAW_FIFO below (see that
# pipeline's own comment, near where it starts, for the full story). No
# `tee`/fan-out involved any more: one awk process now calls all four
# detectors' own process_*_packet() functions directly per packet.
MGT_RAW_FIFO="$WORK_DIR/mgt_raw.fifo"
rm -f "$BLE_FIFO" "$FLOCK_ADDR1_FIFO"

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
# Separate file from TRACKER_LOG_FILE on purpose, even though both are fed
# by the same rogue_tracker_monitor.awk process -- these are a different
# category (stationary retail beacons, not stalking trackers, see
# handle_beacon_line()) and keeping them out of the tracker log means that
# file stays exclusively "things that might be following me."
BEACON_LOG_FILE="${LOOT_DIR}/retail_beacons_${TIMESTAMP}.txt"
echo "Retail BLE beacon log started at $(date)" > "$BEACON_LOG_FILE"
# Diagnostic-only, never alerts -- see flock_wifi_monitor.awk's header and
# handle_flock_wifi_diag_line() below. Separate file from LOG_FILE/
# surveillance.txt on purpose: this is expected to be noisy (most nearby
# phones/laptops send wildcard probes too), and keeping it out of the main
# detection log means it doesn't have to be scrolled past to review real
# hits.
FLOCK_DIAG_LOG_FILE="${LOOT_DIR}/flock_wifi_diag_${TIMESTAMP}.txt"
echo "Flock WiFi diagnostic log (unmatched-OUI wildcard probes, never alerts) started at $(date)" > "$FLOCK_DIAG_LOG_FILE"
# Manual "flag this moment for later analysis" -- see do_bookmark()
# below. Confirmed live which DuckyScript button-name string this device's
# RIGHT button reports (WAIT_FOR_INPUT returns "RIGHT", same command the
# stock BUTTON_COMBO example payload uses in its own background loop).
# Stats-screen source data, rebuilt each main-loop cycle and read by
# the menu when a stats screen is drawn. Work dir, not loot: it is a
# snapshot of live state, not session evidence, and it lives on tmpfs.
DASH_STATE_FILE="${WORK_DIR}/dash_state"

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
# MGT_TCPDUMP_PID/MGT_AWK_PID together are the one shared "type mgt"
# capture+decode pair (Drone WiFi RID/Flock WiFi/Mesh-Detect WiFi/Deauth
# all read from it now, in one merged awk process) -- see that pipeline's
# own comment, near where it starts, for the full story. No separate
# WIFI_MON_PID/FLOCK_WIFI_MON_PID/MESH_WIFI_MON_PID/DEAUTH_MON_PID anymore:
# those were each detector's own awk reader PID before that merge: dead
# weight now that there's nothing separate left to track.
MGT_TCPDUMP_PID=""
MGT_AWK_PID=""
FLOCK_ADDR1_TCPDUMP_PID=""
FLOCK_ADDR1_MON_PID=""
# TRACKER_HCIDUMP_PID/TRACKER_MON_PID/FLOCK_BLE_HCIDUMP_PID/
# FLOCK_BLE_MON_PID/GLASSES_BLE_HCIDUMP_PID/GLASSES_BLE_MON_PID are gone the
# same way the WiFi side's per-detector PIDs are (see above): Drone RID
# BLE/Rogue Trackers/Flock BLE UUID/Smart Glasses now share ONE hcidump +
# ONE merged awk process, tracked by the existing HCIDUMP_PID/BLE_MON_PID
# below -- see that pipeline's own comment, near where it starts.
WIFI_HOP_PID=""
DETECTION_PID=""
WIFI_IFACE_CREATED=0

cleanup() {
    for p in "$HCIDUMP_PID" "$BLE_MON_PID" "$MGT_TCPDUMP_PID" "$MGT_AWK_PID" \
             "$FLOCK_ADDR1_TCPDUMP_PID" "$FLOCK_ADDR1_MON_PID" \
             "$WIFI_HOP_PID" \
             "$DETECTION_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    rm -f "$BLE_FIFO" "$FLOCK_ADDR1_FIFO" "$MGT_RAW_FIFO"
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
# On by default, unlike Retail Beacons below -- a rogue Pineapple/pentest
# device nearby is squarely this payload's own threat model (someone
# running the same class of hardware against you), not ambient noise.
WANT_PINEAPPLE=1
# Off by default, unlike every WANT_* above -- this piggybacks entirely on
# the Rogue BLE trackers' scan process (rogue_tracker_monitor.awk's iBeacon/
# Eddystone-UID/Eddystone-URL branches, see that file's header), so it's
# inert unless WANT_TRACKER=1 too (a LOG line at startup says so if you
# enable this without that). Default-off because stationary retail beacons
# aren't a "following you" threat the way a rogue tracker is -- this is
# ambient environmental info (which stores/venues are running proximity
# marketing), not a security detection -- and in a mall or big-box store it
# can be genuinely noisy. See handle_beacon_line().
WANT_RETAIL_BEACONS=0

# ALWAYS_ALERT: 0 off (default), 1 on. Off preserves this payload's original
# behavior -- SEEN_STRONG dedup means each MAC only alerts once per category
# per session, so a camera you pass repeatedly (stopped at the same light,
# driving the same route daily) doesn't buzz every single time. On disables
# that dedup check entirely (SEEN_STRONG itself still gets updated/consulted
# elsewhere unaffected -- only the early-return "already alerted this
# session" guards are skipped), so the same device alerts again every time
# it's re-detected. User-requested after a live session where the same
# confirmed camera predictably needed a payload restart between passes to
# alert twice -- this is the alternative to restarting: driving the same
# route repeatedly and wanting every pass to alert, not just the first.
ALWAYS_ALERT=0


# STEALTH_MODE: 0 off (default), 1 stealth+vibrate (LED and RINGTONE
# suppressed, vibrator still pulses so a detection can still be felt without
# looking at the screen), 2 stealth+silent (all physical feedback suppressed,
# only the stats screen and loot files still show a detection happened).
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

# Physical feedback ONLY -- deliberately no modal.
#
# This used to call ALERT_RINGTONE, whose own usage string reads "Raise a
# modal alert": it takes over the screen. That was harmless while this
# payload was a single loop printing to the log, and became a real fault the
# moment the detection loop was backgrounded so the menu could own the
# screen. Two processes then raise modal UI at each other -- the loop an
# alert, the foreground a LIST_PICKER -- and the display flips between them
# for as long as anything keeps detecting. On the device that read as the
# menu "flashing over a second screen", and one AirTag sitting nearby,
# re-alerting on its cooldown, was enough to do it continuously.
#
# LED, RINGTONE and VIBRATE draw nothing -- checked against each command's
# own usage text -- so they are what a background process may use. The
# detail the modal carried is not lost: it is in the loot file and on the
# stats screen, which is the better place for it anyway, since a modal
# dismissed while driving tells you nothing afterwards.
# Callers still pass a title and body. They are accepted and not displayed:
# the caller already writes the same text to its loot file, and the stats
# screen reads from there. Keeping them at the call sites keeps those
# reading as "alert, about this" rather than a bare buzz.
#
# UPDATE, confirmed live: "draws nothing" wasn't the whole story for LED
# specifically. Live-tested with a standalone line/width test payload and a
# controlled toggle-everything-off/on comparison: with every detector
# disabled (background process calling neither this function nor
# stealth_blink() at all), the foreground menu's WAIT_FOR_INPUT/LIST_PICKER
# held rock solid, no flashing. Re-enabled, real detections firing this
# function every few seconds reproduced the exact symptom this comment
# already describes above -- meaning the platform's own hak5cmd `LED`
# command, called from the backgrounded process, still contends with the
# foreground's picker/input state despite its usage text, on this specific
# hardware. Fixed the same way stealth_blink() already was: bypass hak5cmd's
# LED entirely and write the sysfs brightness file directly. Reuses that
# function's own already-confirmed-live path-discovery fix (a bare `ls
# /sys/class/leds/*` prints a BusyBox header per match and breaks `head -1`
# -- see stealth_blink()'s header for the full story); duplicated rather
# than factored out since this is the only other call site and a shared
# helper wasn't worth it for two lines.
#
# UPDATE 2, also confirmed live: fixing LED alone reduced the flashing but
# did not eliminate it -- `RINGTONE`, the remaining hak5cmd call in this
# function, is also implicated, not just an audio-subsystem command as
# first assumed. Fixed the same way: bypass hak5cmd and drive the buzzer
# directly. It's a real PWM device exposed through the LED sysfs class
# alongside the visible LEDs above (`/sys/class/leds/buzzer/`, confirmed via
# `device -> ../../../buzzer_pwm`), with its own `frequency` and `volume`
# files in addition to `brightness` -- confirmed live to produce an audible
# beep with frequency=2000 (Hz), volume=128, brightness 0->1->0. Vibrate
# was never suspect (see stealth_blink() below, which already writes it
# directly to sysfs, no hak5cmd involved) and stays as-is.
stealth_alert() {
    if [ "$STEALTH_MODE" = "0" ]; then
        local _led_path
        _led_path=$(ls -d /sys/class/leds/*/ 2>/dev/null | head -1)
        [ -n "$_led_path" ] && echo 1 > "${_led_path}brightness" 2>/dev/null
        if [ -f /sys/class/leds/buzzer/brightness ]; then
            echo 2000 > /sys/class/leds/buzzer/frequency 2>/dev/null
            echo 128 > /sys/class/leds/buzzer/volume 2>/dev/null
            echo 1 > /sys/class/leds/buzzer/brightness 2>/dev/null
            sleep 0.3
            echo 0 > /sys/class/leds/buzzer/brightness 2>/dev/null
            echo 0 > /sys/class/leds/buzzer/volume 2>/dev/null
        fi
        [ -n "$_led_path" ] && echo 0 > "${_led_path}brightness" 2>/dev/null
    fi
    # Felt, not seen, and kept in STEALTH_MODE 1: a pulse is not visible or
    # audible to anyone else, unlike the LED and the ringtone.
    if [ "$STEALTH_MODE" != "2" ] && [ -f /sys/class/gpio/vibrator/value ]; then
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.25
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
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
        pineapple) val="$WANT_PINEAPPLE" ;;
        retail_beacons) val="$WANT_RETAIL_BEACONS" ;;
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

always_alert_menu_item() {
    if [ "$ALWAYS_ALERT" = "1" ]; then
        echo "[X] Always Alert (re-alert on every pass, no dedup)"
    else
        echo "[ ] Always Alert (re-alert on every pass, no dedup)"
    fi
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
            "$(detection_menu_item pineapple 'Rogue Pineapple / pentest device')" \
            "$(detection_menu_item retail_beacons 'Retail beacons (iBeacon/Eddystone, needs Rogue BLE trackers on)')" \
            "$(stealth_menu_item)" \
            "$(always_alert_menu_item)" \
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
            *"Rogue Pineapple"*) WANT_PINEAPPLE=$((1 - WANT_PINEAPPLE)) ;;
            *"Retail beacons"*) WANT_RETAIL_BEACONS=$((1 - WANT_RETAIL_BEACONS)) ;;
            *"Stealth Mode"*) STEALTH_MODE=$(( (STEALTH_MODE + 1) % 3 )) ;;
            *"Always Alert"*) ALWAYS_ALERT=$((1 - ALWAYS_ALERT)) ;;
            "Start scanning") break ;;
            *) break ;;   # LIST_PICKER unavailable/cancelled mid-loop -- fall through with current WANT_*/STEALTH_MODE/ALWAYS_ALERT values rather than looping forever
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

# Shadows the platform's own LOG (a PATH-found external command, symlink to
# hak5cmd -- see show_dash_screen()'s header) with a same-named bash
# function truncating the message to a safe width before ever reaching it.
#
# The payload-log screen's own max_chars is 50 -- already documented and
# verified two screens down, where the ASCII banner was deliberately kept
# under it (see that comment, just above `LOG cyan ' _____ ___ ___'`). That
# same 50-char limit was never applied to the ~40 capability-detection
# messages below, several running 60-157 characters -- confirmed via a
# standalone line/width test payload that overflowing a line doesn't just
# wrap oddly, it leaves the screen's render buffer in a state that
# resurfaces later as unrelated-looking flashing/garbled screens, reported
# from the field as exactly that: fragments of an old screen flashing back
# during normal menu use, long after the line that actually overflowed had
# scrolled off. Every one of those messages fires in a burst on every
# single launch, right before the menu loop even starts.
#
# A function of the same name wins over the PATH-found command in bash's
# lookup order, so this covers all ~90 existing `LOG "text"` / `LOG colour
# "text"` call sites with no changes anywhere else in the file, and covers
# any added later automatically. `command LOG` inside it explicitly bypasses
# this function to reach the real one -- that builtin exists precisely for
# wrapping a command under its own name without infinite recursion.
LOG_MAX_WIDTH=49
LOG() {
    if [ "$#" -eq 0 ]; then
        command LOG
        return
    fi
    local last="${@: -1}"
    if [ "${#last}" -gt "$LOG_MAX_WIDTH" ]; then
        last="${last:0:$((LOG_MAX_WIDTH - 1))}…"
    fi
    if [ "$#" -eq 1 ]; then
        command LOG "$last"
    else
        command LOG "$1" "$last"
    fi
}

BLE_RID_OK=0
WIFI_RID_OK=0
FLOCK_WIFI_OK=0
MESH_WIFI_OK=0
TRACKER_BLE_OK=0
FLOCK_BLE_UUID_OK=0
GLASSES_BLE_OK=0
BTCLASSIC_OK=0
DEAUTH_OK=0

# Bluetooth Classic inquiry needs nothing the BLE side doesn't already
# have -- no awk decoder, no second radio, just hcitool and the adapter.
# So it is available whenever hcitool is, which is also why it has no
# WANT_ toggle of its own: it rides the same scan cycle.
if command -v hcitool >/dev/null 2>&1; then
    BTCLASSIC_OK=1
    LOG green "BT Classic inquiry: enabled (7s per cycle, bt-bluepine's method)"
else
    BTCLASSIC_OK=0
    LOG red "BT Classic inquiry: disabled (hcitool not found)"
fi

# Payload-scoped "branding" -- deliberately not a device theme change (see
# git history for why: this platform's payload-log screen background is
# one fixed theme-wide asset shared by every payload, no per-payload
# override field exists in its own JSON schema, confirmed by reading it
# directly). An ASCII banner printed via LOG, by contrast, genuinely is
# scoped to just this payload -- it's our own script's output, appears in
# the same console the rest of this file already logs to, costs nothing
# to add/remove, and needs zero device firmware files touched. Kept under
# the payload-log screen's own max_chars: 50 -- verified before picking
# this design, not assumed.
LOG cyan   ' _____ ___ ___'
LOG cyan   '|  ___/ __/ __|'
LOG cyan   '| |__ \__ \__ \'
LOG cyan   '|_____|___/___/  Counter-Surveillance-Pager'

LOG yellow "Counter-Surveillance-Pager v$SCRIPT_VERSION started at $(date)"

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
# Own file-existence check, not its own FLOCK_AWK_FILE_OK-style hard gate --
# see flock_wifi_addr1_monitor.awk's header for the UNVERIFIED addr1/
# receiver-address technique this is. Missing this file only drops that one
# extra signal, doesn't touch the main Flock WiFi detector above at all.
if [ -f "$SCRIPT_DIR/flock_wifi_addr1_monitor.awk" ]; then
    LOG yellow "Flock WiFi addr1 (receiver-address) detection: enabled, UNVERIFIED technique"
else
    LOG yellow "Flock WiFi addr1 (receiver-address) detection: disabled (flock_wifi_addr1_monitor.awk not found -- looked in $SCRIPT_DIR)"
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

# Retail beacon detection (iBeacon/Eddystone-UID/Eddystone-URL) has no radio
# or awk-file gate of its own -- it shares rogue_tracker_monitor.awk's scan
# process entirely (see that file's header), so it's only ever as available
# as Rogue BLE trackers already is. This just tells you when the toggle
# you picked won't actually do anything.
if [ "$WANT_RETAIL_BEACONS" = "1" ] && [ "$TRACKER_BLE_OK" != "1" ]; then
    LOG yellow "Retail beacon (iBeacon/Eddystone) detection: enabled in menu but inert -- Rogue BLE trackers (which it shares a scan process with) is disabled or unavailable"
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
# Shared BLE capture AND decode -- one hcidump feeding one merged awk
# process instead of up to 4 of each (Drone Remote ID BLE, Rogue Trackers,
# Flock BLE UUID, Smart Glasses used to each run their own `hcidump -i hci0
# --raw` AND their own independent packet-reassembly pass over the
# identical HCI event stream). Same change, same reasoning, as the WiFi
# "type mgt" consolidation below -- see that pipeline's own comment for the
# fuller story (confirmed live this session: redundant capture+decode
# across several simultaneous detectors drove system load high enough on
# this embedded MIPS hardware to glitch the foreground menu). See
# ble_dispatch.awk's own header for the full per-file breakdown of what
# changed and why it was safe to merge (each detector already used
# uniquely-prefixed state/array/function names).
#
# Each detector's hits still land in its own separate loot file
# (BLE_HITS/TRACKER_HITS/FLOCK_BLE_HITS/GLASSES_BLE_HITS) -- only how those
# files get WRITTEN changed, same as the WiFi side: an explicit `>> file`
# inside each process_*_packet() function now that several share one
# process's stdout, instead of a shell-level `>>` per process.
#
# Reuses BLE_FIFO/HCIDUMP_PID/BLE_MON_PID directly rather than introducing
# new names -- those already meant "the hcidump capture" and "its awk
# reader" for rid_ble_monitor.awk alone; they mean the same thing for the
# shared pipeline now, just with more readers behind that one awk process.
if [ "$BLE_RID_OK" = "1" ] || [ "$TRACKER_BLE_OK" = "1" ] || [ "$FLOCK_BLE_UUID_OK" = "1" ] || [ "$GLASSES_BLE_OK" = "1" ]; then
    mkfifo "$BLE_FIFO"
    "$HCIDUMP" -i hci0 --raw > "$BLE_FIFO" 2>"$WORK_DIR/hcidump.log" &
    HCIDUMP_PID=$!
    "$AWK" -v WANT_RID_BLE="$BLE_RID_OK" -v WANT_TRACKER="$TRACKER_BLE_OK" \
        -v WANT_FLOCK_BLE="$FLOCK_BLE_UUID_OK" -v WANT_GLASSES="$GLASSES_BLE_OK" \
        -v RID_HITS_FILE="$BLE_HITS" -v TRACKER_HITS_FILE="$TRACKER_HITS" \
        -v FLOCK_BLE_HITS_FILE="$FLOCK_BLE_HITS" -v GLASSES_HITS_FILE="$GLASSES_BLE_HITS" \
        -f "$SCRIPT_DIR/rid_common.awk" \
        -f "$SCRIPT_DIR/rid_ble_monitor.awk" -f "$SCRIPT_DIR/rogue_tracker_monitor.awk" \
        -f "$SCRIPT_DIR/flock_ble_monitor.awk" -f "$SCRIPT_DIR/glasses_ble_monitor.awk" \
        -f "$SCRIPT_DIR/ble_dispatch.awk" \
        < "$BLE_FIFO" 2>"$WORK_DIR/ble_dispatch.log" &
    BLE_MON_PID=$!
fi

# Own tcpdump process, "type data" instead of "type mgt" -- see
# flock_wifi_addr1_monitor.awk's header for the technique (addr1/receiver-
# address OUI match on Data frames, catches a camera that never transmits
# anything itself) and its UNVERIFIED status. Gated on the same
# FLOCK_WIFI_OK as the main Flock WiFi detector below -- this is another
# signal for the same "is a Flock camera nearby" question, not a separate
# menu toggle. Stays its own separate tcpdump+awk pair: genuinely different
# traffic (data frames, not management), so there's nothing to consolidate
# it with.
if [ "$FLOCK_WIFI_OK" = "1" ] && [ -f "$SCRIPT_DIR/flock_wifi_addr1_monitor.awk" ]; then
    mkfifo "$FLOCK_ADDR1_FIFO"
    "$TCPDUMP" -i "$WIFI_IFACE" -n -l -xx type data > "$FLOCK_ADDR1_FIFO" 2>"$WORK_DIR/flock_addr1_tcpdump.log" &
    FLOCK_ADDR1_TCPDUMP_PID=$!
    "$AWK" -f "$SCRIPT_DIR/rid_common.awk" -f "$SCRIPT_DIR/flock_wifi_addr1_monitor.awk" \
        < "$FLOCK_ADDR1_FIFO" >> "$FLOCK_ADDR1_HITS" 2>"$WORK_DIR/flock_addr1_monitor.log" &
    FLOCK_ADDR1_MON_PID=$!
fi

# Shared "type mgt" capture AND decode -- one tcpdump feeding one awk
# process instead of up to 4 of each (Drone WiFi RID, Flock WiFi, Mesh-
# Detect WiFi, and Deauth used to each run their own tcpdump AND their own
# independent packet-reassembly pass over the identical management-frame
# stream off wlan1mon). Confirmed live this session: with several WiFi
# detectors enabled together, system load on this embedded MIPS hardware
# climbed into the teens and the foreground menu's WAIT_FOR_INPUT/
# LIST_PICKER started flashing/glitching under that contention -- isolated
# by testing every detector alone (all 8 clean individually) and by
# combination (flashing scaled with detector COUNT, not any specific one).
# An earlier pass here consolidated just the tcpdump capture (`tee`'d to 4
# FIFOs, one independent reassembly pass still per awk process); load
# stayed high and flashing persisted, tracing the real cost to the awk
# DECODE work itself -- 8-9 parallel awk processes actively decoding real
# traffic, not the packet capture layer. This consolidates that too: one
# reassembly pass, in-process, calling each detector's own
# process_*_packet() function directly. See wifi_mgt_dispatch.awk's own
# header for the full per-file breakdown of what changed and why it was
# safe to merge (each detector already used uniquely-prefixed state/array/
# function names -- there was nothing here that collided).
#
# Each detector's hits still land in its own separate loot file
# (WIFI_HITS/FLOCK_WIFI_HITS/MESH_WIFI_HITS/DEAUTH_HITS) -- the bash side's
# file-reading/draining logic further down is unchanged; only how those
# files get WRITTEN changed, from a shell-level `>>` per process to an
# explicit `>> file` inside each process_*_packet() function now that
# several share one process's stdout. MESH_CONFIG_FILE/DEAUTH_CONFIG_FILE
# replace the plain CONFIG_FILE each used before (harmless as separate
# processes; a real collision once merged, since awk `-v` names are global
# to the whole merged program and both need a config file).
if [ "$WIFI_RID_OK" = "1" ] || [ "$FLOCK_WIFI_OK" = "1" ] || [ "$MESH_WIFI_OK" = "1" ] || [ "$DEAUTH_OK" = "1" ]; then
    mkfifo "$MGT_RAW_FIFO"
    # -l: line-buffer tcpdump's own text output so packets reach the awk
    #     consumer promptly instead of sitting in stdio's pipe-buffering.
    # "type mgt": only beacon/action/etc frames -- we never look at data or
    #     control frames, so filtering them out here saves CPU on both ends.
    "$TCPDUMP" -i "$WIFI_IFACE" -n -l -xx type mgt > "$MGT_RAW_FIFO" 2>"$WORK_DIR/tcpdump.log" &
    MGT_TCPDUMP_PID=$!
    "$AWK" -v WANT_WIFI_RID="$WIFI_RID_OK" -v WANT_FLOCK_WIFI="$FLOCK_WIFI_OK" \
        -v WANT_MESH_WIFI="$MESH_WIFI_OK" -v WANT_DEAUTH="$DEAUTH_OK" \
        -v RID_HITS_FILE="$WIFI_HITS" -v FLOCK_HITS_FILE="$FLOCK_WIFI_HITS" \
        -v MESH_HITS_FILE="$MESH_WIFI_HITS" -v DEAUTH_HITS_FILE="$DEAUTH_HITS" \
        -v MESH_CONFIG_FILE="$MESH_CONFIG_FILE" -v DEAUTH_CONFIG_FILE="$TRUSTED_NETWORKS_FILE" \
        -f "$SCRIPT_DIR/rid_common.awk" \
        -f "$SCRIPT_DIR/rid_wifi_monitor.awk" -f "$SCRIPT_DIR/flock_wifi_monitor.awk" \
        -f "$SCRIPT_DIR/mesh_wifi_monitor.awk" -f "$SCRIPT_DIR/deauth_eviltwin_monitor.awk" \
        -f "$SCRIPT_DIR/wifi_mgt_dispatch.awk" \
        < "$MGT_RAW_FIFO" 2>"$WORK_DIR/wifi_mgt_dispatch.log" &
    MGT_AWK_PID=$!
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

# ---------------------------------------------------------------------------
# Live on-screen dashboard
# ---------------------------------------------------------------------------
# The stats screen is drawn on demand, by LEFT, and nothing else ever
# paints. Both halves of that matter, and both were learned the hard way.
#
# It is styled and drawn after hak5's own bt-bluepine, whose Info screen
# does exactly this: magenta section rules with the title right-aligned
# against a trailing " ====", coloured "Key: val | Key: val" facts between
# them, and a short sleep between sections rather than dumping every line
# at once. jbohack/nyanBOX reaches its stats the same way, from a menu.
#
# Why nothing paints on a timer: the log is append-only. LOG is a symlink
# to /usr/bin/hak5cmd, a compiled binary that hands each line to the UI
# over /tmp/api.sock and writes zero bytes to its own stdout, so the
# shell's `clear` goes somewhere the screen never reads, and none of
# hak5cmd's 68 verbs clears the view. A panel painted on a heartbeat
# therefore just accumulates, and one that fills the 14-line window tears
# against the view's own 0.75s repaint timer (payload_log.json
# "refresh_interval") -- on the device that looked like the screen
# flipping between the log and a half-drawn second panel. Instrumenting
# every paint proved the payload was not double-rendering: 91 paints over
# two hours, one process, never two close together. The tearing was the
# view's. Painting only when asked, while nothing else prints, is what
# bt-bluepine does and is what avoids it.
#
# The main loop therefore only refreshes the screen's source data into a
# state file, and the foreground menu reads that file to draw. They are
# separate processes -- the detection loop is backgrounded so the menu can
# own the screen -- so the file is the only way the menu can see live
# numbers at all.
SESSION_START=$(date +%s)

# Unique-device bookkeeping behind the counts.
#
# DETECTED_DEVICES is keyed on the device key alone -- a MAC, for every
# detector here -- so it counts DISTINCT DEVICES rather than alerts: a tracker that re-alerts every cooldown, or
# a camera caught on both the WiFi and BLE paths, moves the total once and
# then stops. CAT_SEEN is keyed on "category|key" instead, so that same
# camera still shows up under both the categories that found it. The
# tradeoff of MAC-keying is that BLE MAC rotation (AirTag/SmartTag/FMDN,
# see TRACKER_FIRST_SEEN's header) reads as a new device, which nothing on
# this hardware can fix.
declare -A DETECTED_DEVICES
declare -A CAT_SEEN
declare -A CAT_COUNT

# Order the dashboard lists categories in. Kept as a space-separated
# string rather than an associative array so the display order is fixed
# and readable; the panel only prints the ones actually enabled.
DASH_CATS="flock drone tracker mesh deauth skimmer glasses pineapple"

dash_cat_label() {
    case "$1" in
        flock)   echo "Flock" ;;
        drone)   echo "Drone" ;;
        tracker) echo "Tracker" ;;
        mesh)    echo "Mesh" ;;
        deauth)  echo "Deauth" ;;
        skimmer) echo "Skimmer" ;;
        glasses) echo "Glasses" ;;
        pineapple) echo "Pineapple" ;;
    esac
}


# Whether a category actually came up, as opposed to merely being wanted.
# The two differ whenever a radio or tool is missing, and that gap is the
# thing worth seeing in the field. A category with more than one path
# (Flock is BLE and WiFi, drone Remote ID likewise) counts as live if
# either path did.
dash_cat_live() {
    case "$1" in
        flock)   [ "$FLOCK_BLE_UUID_OK" = "1" ] || [ "$FLOCK_WIFI_OK" = "1" ] && echo 1 ;;
        drone)   [ "$BLE_RID_OK" = "1" ] || [ "$WIFI_RID_OK" = "1" ] && echo 1 ;;
        tracker) [ "$TRACKER_BLE_OK" = "1" ] && echo 1 ;;
        mesh)    [ "$MESH_WIFI_OK" = "1" ] || [ "$MESH_BLE_OK" = "1" ] && echo 1 ;;
        deauth)  [ "$DEAUTH_OK" = "1" ] && echo 1 ;;
        glasses) [ "$GLASSES_BLE_OK" = "1" ] && echo 1 ;;
        # Skimmer matching runs over the shared hcitool lescan dump rather
        # than a reader of its own, so it is up whenever that cycle is.
        skimmer) [ "$BTCLASSIC_OK" = "1" ] && echo 1 ;;
        # Same reasoning as skimmer: pineapple_match() runs over the shared
        # BT Classic scan and hcitool lescan dump, no reader of its own.
        pineapple) [ "$BTCLASSIC_OK" = "1" ] && echo 1 ;;
    esac
}

# Whether a category's detector was actually turned on for this run -- a
# disabled detector's permanent 0 is noise on a screen this small, so the
# panel leaves it out rather than showing a zero that can never move.
dash_cat_enabled() {
    case "$1" in
        flock)   [ "$WANT_FLOCK" = "1" ] ;;
        drone)   [ "$WANT_DRONE" = "1" ] ;;
        tracker) [ "$WANT_TRACKER" = "1" ] ;;
        mesh)    [ "$WANT_MESH" = "1" ] ;;
        deauth)  [ "$WANT_DEAUTH" = "1" ] ;;
        skimmer) [ "$WANT_SKIMMER" = "1" ] ;;
        glasses) [ "$WANT_GLASSES" = "1" ] ;;
        pineapple) [ "$WANT_PINEAPPLE" = "1" ] ;;
        *)       false ;;
    esac
}

# One compact "label status count" slot for a detector, e.g. "Flock     run 3"
# -- 17 characters fixed width, two of these plus a separating space (35
# chars) comfortably fits the display's own hard ~50-char line limit (see
# LOG_MAX_WIDTH's header), which is what makes packing two per line safe
# rather than a guess. Labels over 9 characters truncate (the "10.9" in
# %-10.9s: pad to 10, but never take more than 9 of the source) rather than
# wrap or push the second slot off-screen -- only "BT Classic" is affected,
# reading as "BT Classi" here; the truncate-to-9/pad-to-10 split (not just
# %-9.9s) is deliberate so even a fully-9-character label like "Pineapple"
# still gets one trailing space before the next field, instead of running
# straight into "run"/"off" with nothing between them.
dash_cat_entry() {
    local cat="$1" n label status
    n=${CAT_COUNT[$cat]:-0}
    label=$(dash_cat_label "$cat")
    if ! dash_cat_enabled "$cat"; then
        status="off"; n="-"
    elif [ "$(dash_cat_live "$cat")" = "1" ]; then
        status="run"
    else
        status="N/A"; n="-"
    fi
    printf '%-10.9s%-4s%-3s' "$label" "$status" "$n"
}

# The one-line "how is this rig configured right now" strip under the
# title: GPS fix if there is one, and stealth state, since both change
# what you should expect the device to do and neither is visible anywhere
# else once the startup banner is cleared.
dash_status_line() {
    local gps stealth
    if [ -n "$GPS_FIX" ]; then gps="gps"; else gps="nogps"; fi
    case "$STEALTH_MODE" in
        1) stealth="vib" ;;
        2) stealth="silent" ;;
        *) stealth="alerts" ;;
    esac
    echo "$gps $stealth"
}

# Repaints the whole screen. Fixed-height block, so it lands the same way
# every time instead of drifting down the display as counts change.
# Section rule in bt-bluepine's house style: "=" padding with the section
# title right-aligned against a trailing " ====", the whole thing a fixed
# width. Theirs are hard-coded strings (LOG magenta
# "================================ Device Info ===="); building it means
# the titles here can change without anyone counting "=" by hand.
DASH_RULE_W=48
dash_rule() {
    local tail=" $1 ====" n eq
    n=$(( DASH_RULE_W - ${#tail} ))
    [ "$n" -lt 4 ] && n=4
    eq=$(printf "%${n}s" "" | tr ' ' '=')
    echo "$eq$tail"
}

# Rebuilds the stats screen into $DASH_STATE_FILE as "colour|text" lines.
# Cheap enough to run every main-loop cycle: some string appends and one
# small write to tmpfs, and crucially NOTHING to the screen -- the screen
# is only ever drawn by show_dash_screen(), on LEFT.
write_dash_state() {
    local up_s up_h up_m cat tag n row i entry txt gps stealth pending btc
    local -a out=()
    up_s=$(( $(date +%s) - SESSION_START ))
    up_h=$(printf '%02d' $(( up_s / 3600 )))
    up_m=$(printf '%02d' $(( (up_s % 3600) / 60 )))

    _o() { out+=("$1|$2"); }

    if [ -n "$GPS_FIX" ]; then gps="yes"; else gps="no"; fi
    case "$STEALTH_MODE" in
        1) stealth="vibrate only" ;;
        2) stealth="silent" ;;
        *) stealth="on" ;;
    esac

    _o magenta "$(dash_rule 'Session Info')"
    _o cyan    "Uptime: $up_h:$up_m | GPS: $gps | Alerts: $stealth"
    if [ "$DETECTIONS" = "0" ]; then
        _o green "Unique Devices: 0 -- nothing detected yet"
    else
        _o red   "Unique Devices: $DETECTIONS"
    fi

    _o magenta "$(dash_rule 'Detections')"
    # Two detectors per line instead of one -- cuts this section from 9
    # rows to 5. "off" means you did not select it; "N/A" means you did but
    # it could not start (missing radio or tool), which is the case worth
    # seeing in the field and was previously only on a second screen.
    # dash_cat_entry() builds one fixed-width slot; paired here two at a
    # time via $pending, flushed as a combined line once the second slot of
    # a pair is ready.
    pending=""
    for cat in $DASH_CATS; do
        if [ -z "$pending" ]; then
            pending=$(dash_cat_entry "$cat")
        else
            _o "" "$pending $(dash_cat_entry "$cat")"
            pending=""
        fi
    done
    # No WANT_ toggle of its own -- it rides the BLE cycle whenever hcitool
    # is present, so it isn't in DASH_CATS and doesn't go through
    # dash_cat_entry(); folded in as one more slot here instead of always
    # getting its own trailing line. DASH_CATS has an even count (8), so
    # $pending is always empty going into this -- BT Classic lands alone on
    # the last line every time, not paired with a leftover from above.
    if [ "$BTCLASSIC_OK" = "1" ]; then
        btc="$(printf '%-10.9s%-4s%-3s' "BT Classic" "run" "")"
    else
        btc="$(printf '%-10.9s%-4s%-3s' "BT Classic" "N/A" "-")"
    fi
    if [ -z "$pending" ]; then
        _o "" "$btc"
    else
        _o "" "$pending $btc"
    fi

    # Written whole then moved into place, so the watcher can never read a
    # half-written file -- it runs in its own process and is not
    # synchronised with this one in any way.
    : > "$DASH_STATE_FILE.tmp"
    for txt in "${out[@]}"; do printf '%s\n' "$txt" >> "$DASH_STATE_FILE.tmp"; done
    mv -f "$DASH_STATE_FILE.tmp" "$DASH_STATE_FILE" 2>/dev/null
    unset -f _o
}

# Paints the stats screen, bt-bluepine style: magenta section rules,
# coloured facts between them, a footer rule saying which button does what.
#
# Painted into the log rather than raised as a LIST_PICKER, which is what
# this used before. BluePine's own Info screen is painted the same way
# (payload.sh's "Device Info"/"Scan Info"/"Scan Settings" block), and it
# holds still for the same reason it will here: nothing else is printing.
# The main loop paints nothing at all now, so once this lands it is the
# last thing on the screen until you press something.
#
# Reads $DASH_STATE_FILE rather than the counters directly: those live in
# detection_loop's process, which is not this one.
show_dash_screen() {
    local line col txt shown=0
    if [ ! -s "$DASH_STATE_FILE" ]; then
        LOG red "Stats: still starting up, nothing to show yet"
        return
    fi
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        col="${line%%|*}"
        txt="${line#*|}"
        if [ -n "$col" ]; then LOG "$col" "$txt"; else LOG "$txt"; fi
        shown=$((shown + 1))
        # bt-bluepine paces its Info screen with a sleep between sections
        # rather than dumping every line at once; a rule is where a section
        # starts, so that is where the pause goes.
        case "$txt" in ====*) sleep 0.2 ;; esac
    done < "$DASH_STATE_FILE"
}

# Records one detection and repaints. $1 category, $2 device key, $3 the
# short "what/who" text the dashboard's Recent panel shows for it.
#
# MUST be called before the caller's own LOG line, because it sets
# Loot lines are written by the callers exactly as before, byte for byte:
# export_gps_kml.awk anchors its " | gps=LAT,LON" match to end-of-line, so
# anything appended to a persisted line would silently drop every
# GPS-tagged hit from the KML export, and summarize_session.sh reads the
# same file positionally.
#
# Called by every real detection across every category (Flock, drone
# Remote ID, Mesh-Detect, rogue trackers, deauth/evil-twin, skimmers,
# glasses) -- NOT by handle_beacon_line(), which
# deliberately isn't a security detection, see that function's own header
# for why.

bump_counter() {
    local cat="$1" key hit now
    key=$(echo "$2" | tr 'A-Z' 'a-z')

    if [ -n "$key" ] && [ -z "${DETECTED_DEVICES[$key]}" ]; then
        DETECTED_DEVICES["$key"]=1
        DETECTIONS=$((DETECTIONS + 1))
    fi
    if [ -n "$key" ] && [ -z "${CAT_SEEN[$cat|$key]}" ]; then
        CAT_SEEN["$cat|$key"]=1
        CAT_COUNT["$cat"]=$(( ${CAT_COUNT[$cat]:-0} + 1 ))
    fi

    # Deliberately draws nothing. The stats screen is raised by LEFT, and
    # the physical alert (vibrate/LED/ringtone) is what tells you a hit
    # happened without looking. The main loop refreshes the state file on
    # its next cycle, within about 3 seconds.
}

declare -A DRONE_LAST_ALERT
declare -A DRONE_KNOWN
BLE_HITS_OFFSET=0
WIFI_HITS_OFFSET=0
FLOCK_WIFI_HITS_OFFSET=0
FLOCK_ADDR1_HITS_OFFSET=0
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
# d4:11:d6 was pulled at the same time as the rest of this list but has
# since been removed: direct IEEE OUI lookup shows it's registered to
# ShotSpotter, Inc. (now SoundThinking) -- an acoustic gunshot-detection
# vendor, not Flock Safety. Re-added correctly, as ShotSpotter, in
# mesh_detect_targets.conf's BLE-matching pass instead -- see that file's
# header for the same sourcing note as flock_wifi_monitor.awk's.
flock_ble_match() {
    local mac="$1" name="$2"
    if echo "$name" | grep -qi "fs ext battery\|penguin\|flock\|pigvision\|xuntong"; then
        echo "name"
        return
    fi
    local oui_lc="${mac,,}"
    oui_lc="${oui_lc:0:8}"
    case "$oui_lc" in
        b4:1e:52|58:8e:81|ec:1b:bd|90:35:ea|04:0d:84|f0:82:c0|1c:34:f1|38:5b:44|94:34:69|b4:e3:f9)
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

# Checks one "MAC NAME" BT scan result (Classic or BLE, same as
# ble_skimmer_match() above) against Hak5's own registered OUI and the
# generic Bluetooth names its stock/community firmware advertises under --
# ported from cncartistsec/BluePine-WiFi-Pineapple-Pager's
# check_bt_pineapps(). Matches this payload's own threat model directly:
# someone else running a Pineapple/pentest rig against you is exactly what
# a counter-surveillance tool should flag, the same way a rogue tracker or
# an evil-twin AP is flagged.
#
# 00:13:37 is Hak5 LLC's IEEE-registered OUI -- confirmed as the exact
# prefix this device's own radios carry (eth0/br-lan/wlan0mon all show
# 00:13:37:xx:xx:xx locally). This only ever matches an OTHER device's
# advertisement, never this one's own: hcitool scan/lescan report
# addresses they hear FROM other devices, not the local scanning
# adapter's own address, so there is nothing to exclude here.
#
# Name match is "pine"/"pager" (case-insensitive) -- narrower than
# upstream's own check_bt_pineapps(), which also matches "bluez". That
# third arm is dropped here: "bluez" is the default Bluetooth stack name
# on essentially any stock Linux BT adapter, not something specific to
# Hak5 hardware, so on its own it would flag ordinary laptops/phones/IoT
# devices broadcasting BlueZ's own generic default rather than anything
# resembling a Pineapple. "pine"/"pager" are still broad (a real product
# name containing either would also match) but at least point at this
# specific hardware family; the OUI match above is the strong signal
# regardless, and the name match exists only to catch a Pineapple running
# non-default/USB Bluetooth hardware whose adapter MAC won't carry the
# 00:13:37 prefix at all.
pineapple_match() {
    local mac="$1" name="$2"
    local mac_lc="${mac,,}"
    [ "${mac_lc:0:8}" = "00:13:37" ] && { echo "oui"; return; }
    case "${name,,}" in
        *pine*|*pager*) echo "name:$name"; return ;;
    esac
}

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
    if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$mac WIFI_FLOCK"; then return; fi

    local conf="high"
    case "$kv" in
        *"conf=low"*) conf="low" ;;
        *"conf=medium"*) conf="medium" ;;
    esac

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    bump_counter flock "$mac" "$mac W/$conf"
    if [ "$conf" = "high" ]; then
        ENTRY="DECT: $CURRENT_TIME | $mac | Flock (WiFi $msgtype, $kv)$GPS_TAG"
    else
        ENTRY="DECT: $CURRENT_TIME | $mac | Flock? (WiFi $msgtype, $kv)$GPS_TAG"
    fi
    echo "$ENTRY" >> "$LOG_FILE"
    # conf=medium now gets a physical alert too, not just conf=high --
    # field-confirmed live 2026-08-20 (parked next to a real camera on OUI
    # 9c:2f:9d, RSSI trending -49/-39/-38dBm as proximity increased) that
    # conf=medium hits (Beacon/Probe-Response/addr1/any-management-frame
    # OUI matches) are real signal on a real camera, not noise -- silent-
    # only was the right call before any of those paths had live
    # confirmation, staying silent now that one has would mean driving
    # past a real hit with nothing but an easy-to-miss yellow screen line.
    # conf=low (OUI+wildcard-probe WITHOUT a signature match) stays soft-
    # only -- no live confirmation yet that tier specifically is reliable.
    if [ "$conf" = "high" ] || [ "$conf" = "medium" ]; then
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
    if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$mac BLE_FLOCK_UUID"; then return; fi

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
    bump_counter flock "$mac" "$mac B?"
    echo "$ENTRY" >> "$LOG_FILE"
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
    if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$mac BLE_GLASSES"; then return; fi

    local rssi_sfx=""
    case "$kv" in
        *rssi=*) rssi_sfx=" | rssi=${kv#*rssi=}" ;;
    esac
    local cid="${kv%%|rssi=*}"

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    ENTRY="DECT: $CURRENT_TIME | $mac | Glasses?? ($brand, unverified signature, $cid)$rssi_sfx$GPS_TAG"
    bump_counter glasses "$mac" "$mac $brand"
    echo "$ENTRY" >> "$LOG_FILE"
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
    if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$mac WIFI_MESH\|$mac MESH_BLE"; then return; fi

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
    bump_counter mesh "$mac" "$mac W"
    echo "$ENTRY" >> "$LOG_FILE"
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
    bump_counter tracker "$mac" "$mac $label"
    stealth_alert "ROGUE TRACKER" "$label\n$mac\nseen ${TRACKER_SIGHTINGS[$key]}x over ${minutes}min"
}

# Human-readable label per ble_beacon protocol tag emitted by
# rogue_tracker_monitor.awk's generic-beacon branches -- separate from
# tracker_protocol_label() above since iBeacon/Eddystone-UID/Eddystone-URL
# aren't stalking-tracker protocols, see that file's header.
beacon_protocol_label() {
    case "$1" in
        ibeacon)       echo "iBeacon" ;;
        eddystone_uid) echo "Eddystone-UID" ;;
        eddystone_url) echo "Eddystone-URL" ;;
        *)             echo "$1" ;;
    esac
}

# Parse one "ble_beacon|MAC|protocol|detail" line from
# rogue_tracker_monitor.awk's generic-beacon branches. Deliberately soft,
# same tier as handle_flock_ble_line()'s unverified-signature hits:
# BEACON_LOG_FILE only, no vibrate/LED, no persistence window, and NOT
# passed to bump_counter() -- so it stays out of the dashboard's counts
# and its Recent panel both. This isn't a security detection the way a
# rogue tracker or a camera is, it's ambient environmental info. Still
# respects TRACKER_ALLOWLIST/TRACKER_SNOOZE since it shares
# rogue_tracker_monitor.awk's MAC space -- a beacon you've allowlisted or
# snoozed as a tracker stays suppressed here too. Gated on
# WANT_RETAIL_BEACONS itself (not just at the awk-process level) since the
# awk process it shares with rogue trackers may be running for tracker
# detection alone with this toggle off.
handle_beacon_line() {
    [ "$WANT_RETAIL_BEACONS" = "1" ] || return
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

    local label
    label=$(beacon_protocol_label "$protocol")
    echo "$(date '+%H:%M:%S') | $mac | $label | $detail$GPS_TAG" >> "$BEACON_LOG_FILE"
    # No screen line: beacons are the noisiest source here by a wide
    # margin, and the one category deliberately not counted either.
    # BEACON_LOG_FILE still gets every one of them, unchanged.
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
            bump_counter deauth "$mac" "$mac flood"
            stealth_alert "DEAUTH FLOOD" "$mac\n${delta_count} ${subtype} in ${delta_time}s"
        fi
        return
    fi

    if [ "$kind" = "eviltwin" ]; then
        local ssid="$f3"
        echo "$(date '+%H:%M:%S') | eviltwin | bssid=$mac | ssid=$ssid$rssi_sfx$GPS_TAG" >> "$DEAUTH_LOG_FILE"

        local last_alert="${DEAUTH_LAST_ALERT[$mac]:-0}"
        [ $((now - last_alert)) -lt "$DEAUTH_ALERT_COOLDOWN" ] && return
        DEAUTH_LAST_ALERT[$mac]=$now
        bump_counter deauth "$mac" "$mac twin"
        stealth_alert "EVIL TWIN AP" "SSID: $ssid\nRogue BSSID: $mac"
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
        bump_counter drone "$mac" "$mac"
        stealth_alert "DRONE REMOTE ID" "$label\n$summary\nvia $src"
    fi
}

# Best-effort GPS fix via the Pager's own GPS_GET command (/usr/bin/GPS_GET,
# a thin wrapper over pineapd's HTTP API -- same platform-builtin convention
# already used for LOG/LED/RINGTONE elsewhere in this file,
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

# Sets GPS_FIX/GPS_TAG from a fresh get_gps_fix() call. GPS_TAG is what
# every hit logged appends to its line (" | gps=LAT,LON", or nothing
# without a fix).
#
# Called twice per detection_loop tick, not once: that loop blocks for
# ~19s across two scan windows (7s BT Classic + 12s BLE lescan), and a
# single fix taken at the top used to tag every hit from BOTH windows.
# Moving at 60mph, a hit logged near the end of the BLE window was
# carrying a position from up to ~19s (and the loop's own trailing sleep 3
# from the PREVIOUS tick pushes worst case toward ~22s) earlier -- upwards
# of 600m of drift on the loot file's own coordinates. The second call
# sits right after the BLE window closes and before any of its results
# are processed, so the larger window's hits get a fix taken close to
# when they actually happened rather than one taken up to 19s before them.
# Still not per-hit precision -- GPS_GET itself costs another ~2-3s each
# call, so tagging every single hit individually would meaningfully slow
# the loop for marginal gain over two calls -- this halves the worst-case
# error, it doesn't eliminate it.
refresh_gps_tag() {
    GPS_FIX=$(get_gps_fix)
    GPS_TAG=""
    [ -n "$GPS_FIX" ] && GPS_TAG=" | gps=$GPS_FIX"
}

# Read-only GPS diagnostics for the menu's GPS Status screen below -- ported
# from this project's own sibling payload, alpr-gps-alert/payload.sh (whose
# header explains the three independent things that have to line up: gpsd
# running, the configured device path actually present, and a fix). Kept
# read-only here deliberately, same stance as that file: GPS is device
# configuration, done in Settings > GPS in the Pager UI, not this payload's
# job to change -- only to report accurately, since GPS_GET's "0 0 0 0" is
# indistinguishable between "gpsd isn't running" and "cold receiver, no
# lock yet" without checking gpsd itself.
gpsd_running() {
    # NOT `pgrep -x gpsd` -- BusyBox pgrep's -x matches the whole command
    # line, not the process name, so it false-negatives on a running gpsd.
    # See alpr-gps-alert/payload.sh's gpsd_running() for the confirmed-live
    # detail (ps showed gpsd running, `pgrep -x gpsd` still said no match).
    pgrep -f "/usr/sbin/gpsd" >/dev/null 2>&1
}
gps_device_path()  { uci get gpsd.core.device 2>/dev/null; }
gps_device_speed() { uci get gpsd.core.speed 2>/dev/null; }

# Menu leaf screen: gpsd process state, configured device path (present or
# missing on disk), baud, and a fresh fix via get_gps_fix() -- called
# directly here rather than through detection_loop's GPS_FIX, since this
# runs in the foreground menu process and that variable only exists in the
# backgrounded one (same reason show_menu_banner() reads $DASH_STATE_FILE
# instead of touching GPS_FIX directly -- see menu_status_line()'s header).
# do_bookmark() already calls get_gps_fix() fresh from this same foreground
# process, so this isn't a new pattern.
screen_gps() {
    local dev fix
    LOG magenta "$(dash_rule 'GPS Status')"
    if gpsd_running; then LOG green "gpsd: running"; else LOG red "gpsd: NOT RUNNING"; fi
    dev=$(gps_device_path)
    if [ -z "$dev" ]; then
        LOG red "Device: not configured"
    elif [ -e "$dev" ]; then
        LOG green "Device: OK ($(basename "$dev"))"
    else
        LOG red "Device: MISSING ($(basename "$dev"))"
    fi
    LOG cyan "Baud: $(gps_device_speed)"
    fix=$(get_gps_fix)
    if [ -n "$fix" ]; then
        LOG green "Fix: $fix"
    else
        LOG yellow "No fix yet (cold start can take 15-30m)"
    fi
    LOG magenta "$(dash_rule 'GPS Status')"
}

# Manual "flag this moment for later analysis" -- a menu action rather
# than a button watcher. A background process parked in WAIT_FOR_INPUT
# would compete with the foreground menu for the D-pad (only one reader
# can win a button press), which is why bt-bluepine has no such watcher
# either: everything it does goes through its menu.
#
# Calls get_gps_fix() itself rather than reading the detection loop's
# $GPS_TAG -- that loop is a separate process now, so its variables are
# not visible here at all.
#
# Double vibrate pulse (not the single pulse a real detection uses)
# specifically so a bookmark feels different from a detection alert.
BOOKMARK_N=0
do_bookmark() {
    local gps_fix gps_sfx
    BOOKMARK_N=$((BOOKMARK_N + 1))
    gps_fix=$(get_gps_fix)
    gps_sfx=""
    [ -n "$gps_fix" ] && gps_sfx=" | gps=$gps_fix"
    echo "$(date '+%H:%M:%S') | bookmark #$BOOKMARK_N$gps_sfx" >> "$BOOKMARK_LOG_FILE"
    if [ -f /sys/class/gpio/vibrator/value ]; then
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.12
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.1
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.12
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
    fi
    LOG magenta "$(dash_rule 'Bookmark')"
    LOG green "Bookmark #$BOOKMARK_N saved$gps_sfx"
    LOG "Logged to $(basename "$BOOKMARK_LOG_FILE")"
}

# The detection engine, moved off the foreground so the menu can own the
# screen. Everything in here is silent: hits go to their loot files, real
# alerts go to the vibrator/LED/ringtone, and the numbers the menu screens
# read go to $DASH_STATE_FILE. Nothing it does prints, which is what makes
# a menu screen stay put once drawn -- the whole reason bt-bluepine's
# interface feels settled and the old always-on log did not.
detection_loop() {
while true; do
    # See refresh_gps_tag()'s own header (defined above, next to
    # get_gps_fix()) for why this is called twice per tick instead of once.
    refresh_gps_tag


    load_tracker_snooze

    # hcitool lescan is the shared scan-enabler every hcidump-based BLE
    # detector piggybacks on (Flock BLE name match below, Mesh-Detect BLE
    # below, and the independent Drone/Tracker/Flock-UUID hcidump readers
    # started earlier -- hcidump alone never enables scanning, see this
    # file's KNOWN LIMITATIONS). Skipped entirely when no BLE-side category
    # is wanted -- the loop's own `sleep 3` at the bottom still paces it, so
    # this doesn't turn into a busy-loop, it just iterates faster and spends
    # that time draining WiFi-side hits instead.
    if [ "$WANT_FLOCK" = "1" ] || [ "$WANT_MESH" = "1" ] || [ "$WANT_TRACKER" = "1" ] || [ "$WANT_DRONE" = "1" ] || [ "$WANT_SKIMMER" = "1" ] || [ "$WANT_PINEAPPLE" = "1" ]; then
    # --- Bluetooth Classic inquiry -------------------------------------
    # Everything else on the Bluetooth side here is BLE: hcitool lescan and
    # the hcidump readers that piggyback on it only ever see advertising
    # packets. Classic inquiry reaches a different population entirely --
    # older speakers and headsets, car kits, and body-worn cameras that
    # never advertise over BLE -- so without this those devices are not
    # merely missed, they are invisible to every detector in this payload.
    #
    # Command and duration are bt-bluepine's, observed live on this device
    # rather than read from its source: it runs
    #   timeout --signal=SIGINT 7s hcitool -i hci0 scan --length=7
    # inside a btmon capture window, alternating Classic then LE at 7s
    # each. SIGINT rather than SIGTERM matters: hcitool leaves the
    # controller mid-inquiry on a hard kill, and the next scan then starts
    # against a busy adapter.
    #
    # btmon is deliberately NOT used. BluePine needs it because it wants
    # RSSI and class-of-device out of the Extended Inquiry Result events,
    # which hcitool's own stdout does not carry. The matchers here
    # (flock_ble_match / mesh_ble_match / ble_skimmer_match) take a MAC and
    # a name, which is exactly what that stdout gives, and adding a btmon
    # decoder would mean new unverified parsing for data nothing consumes.
    #
    # This ADDS ~7s to the cycle rather than taking it from the LE window.
    # Shortening the existing 12s lescan would degrade every BLE detector
    # that piggybacks on it (Flock BLE, drone Remote ID, trackers, glasses,
    # skimmers, Mesh-Detect) to buy this one, which is not a trade worth
    # making silently.
    : > /tmp/hci_classic.txt
    timeout --signal=SIGINT 7s hcitool -i hci0 scan --length=7 \
        > /tmp/hci_classic.txt 2>>"$LOG_FILE"
    killall hcitool 2>/dev/null

    # hcitool scan prints a "Scanning ..." banner then tab-indented
    # "MAC\tname" rows; the banner has no colon in it, which is what the
    # case below filters on.
    if [ -s /tmp/hci_classic.txt ]; then
        while read -r full_line; do
            MAC=$(echo "$full_line" | awk '{print $1}')
            case "$MAC" in *:*:*) ;; *) continue ;; esac
            NAME=$(echo "$full_line" | cut -f2-)
            [ "$NAME" = "$full_line" ] && NAME=""
            if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$MAC BTCLASSIC"; then continue; fi

            CURRENT_TIME=$(date '+%H:%M:%S')
            MATCH=""
            CAT=""
            if [ "$WANT_FLOCK" = "1" ]; then
                MATCH=$(flock_ble_match "$MAC" "$NAME"); [ -n "$MATCH" ] && CAT=flock
            fi
            if [ -z "$CAT" ] && [ "$MESH_BLE_OK" = "1" ]; then
                MATCH=$(mesh_ble_match "$MAC" "$NAME"); [ -n "$MATCH" ] && CAT=mesh
            fi
            if [ -z "$CAT" ] && [ "$WANT_SKIMMER" = "1" ]; then
                MATCH=$(ble_skimmer_match "$MAC" "$NAME"); [ -n "$MATCH" ] && CAT=skimmer
            fi
            if [ -z "$CAT" ] && [ "$WANT_PINEAPPLE" = "1" ]; then
                MATCH=$(pineapple_match "$MAC" "$NAME"); [ -n "$MATCH" ] && CAT=pineapple
            fi
            [ -z "$CAT" ] && continue

            ENTRY="DECT: $CURRENT_TIME | $MAC | ${NAME:-(no name)} (BT Classic, $MATCH)$GPS_TAG"
            bump_counter "$CAT" "$MAC" "$MAC BTC"
            echo "$ENTRY" >> "$LOG_FILE"
            stealth_blink
            SEEN_STRONG="$SEEN_STRONG $MAC BTCLASSIC"
        done < <(sort -u /tmp/hci_classic.txt)
    fi

    # --- Flock Safety BLE scan cycle (unmodified from Flock-You / Flock_Detect) ---
    hciconfig hci0 down 2>>"$LOG_FILE"
    hciconfig hci0 reset 2>>"$LOG_FILE"
    hciconfig hci0 up 2>>"$LOG_FILE"
    # `timeout 18` is a dead-man's-switch, not the intended scan length: the
    # real stop signal is `kill $PID` below, at 12s. The 6s of headroom
    # between them exists so hcitool still gets killed (by its own timeout,
    # SIGTERM) if `kill $PID` ever fails to land -- a wedged process or a
    # PID that already exited -- rather than running unbounded and eating
    # into the next tick's BT Classic window. Left at upstream's original
    # value (see the "unmodified from" note above) rather than trimmed
    # closer to 12s, since this hasn't been re-verified live and shortening
    # a safety margin on unverified grounds is the wrong direction to guess.
    timeout 18 hcitool lescan --duplicates > /tmp/hci_scan.txt 2>>"$LOG_FILE" &
    PID=$!
    sleep 12
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    # Second fix of this tick -- see refresh_gps_tag()'s header for why.
    # Everything below reading /tmp/hci_scan.txt (Flock/Mesh/Skimmer/
    # Pineapple BLE) was captured during the 12s window that just closed,
    # so this is a closer-to-the-fact position than the one taken at the
    # top of the tick, before BT Classic's own 7s ran.
    refresh_gps_tag
    if [ "$WANT_FLOCK" = "1" ] && [ -s /tmp/hci_scan.txt ]; then
        while read -r full_line; do
            MAC=$(echo "$full_line" | awk '{print $1}')
            NAME=$(echo "$full_line" | cut -d' ' -f2-)
            [ -z "$MAC" ] && continue
            if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$MAC $NAME"; then continue; fi
            MATCH=$(flock_ble_match "$MAC" "$NAME")
            [ -z "$MATCH" ] && continue
            CURRENT_TIME=$(date '+%H:%M:%S')
            ENTRY="DECT: $CURRENT_TIME | $MAC | $NAME$GPS_TAG"
            # $MATCH (name tier vs bare OUI) used to choose a LOG colour
            # here; with nothing printing, the tier survives only in the
            # loot line's own name text, which carries it anyway.
            bump_counter flock "$MAC" "$MAC"
            echo "$ENTRY" >> "$LOG_FILE"
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
            if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$MAC WIFI_MESH\|$MAC MESH_BLE"; then continue; fi
            MATCH=$(mesh_ble_match "$MAC" "$NAME")
            [ -z "$MATCH" ] && continue
            CURRENT_TIME=$(date '+%H:%M:%S')
            VENDOR=$(mesh_vendor_label "${MATCH#*:}")
            if [ -n "$VENDOR" ]; then
                ENTRY="DECT: $CURRENT_TIME | $MAC | $VENDOR detected (BLE \"$NAME\", $MATCH)$GPS_TAG"
            else
                ENTRY="DECT: $CURRENT_TIME | $MAC | Mesh-Detect (BLE \"$NAME\", $MATCH)$GPS_TAG"
            fi
            bump_counter mesh "$MAC" "$MAC B"
            echo "$ENTRY" >> "$LOG_FILE"
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
            if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$MAC BLE_SKIMMER"; then continue; fi
            MATCH=$(ble_skimmer_match "$MAC" "$NAME")
            [ -z "$MATCH" ] && continue
            CURRENT_TIME=$(date '+%H:%M:%S')
            ENTRY="DECT: $CURRENT_TIME | $MAC | CC Skimmer? (BLE \"$NAME\", $MATCH)$GPS_TAG"
            bump_counter skimmer "$MAC" "$MAC"
            echo "$ENTRY" >> "$LOG_FILE"
            stealth_blink
            SEEN_STRONG="$SEEN_STRONG $MAC BLE_SKIMMER"
        done < <(sort -u /tmp/hci_scan.txt)
    fi

    # --- Rogue Pineapple BLE scan: reuse the same hcitool lescan dump ---
    # --- above, checked against pineapple_match() instead of Flock/Mesh/ ---
    # --- Skimmer names -----------------------------------------------------
    if [ "$WANT_PINEAPPLE" = "1" ] && [ -s /tmp/hci_scan.txt ]; then
        while read -r full_line; do
            MAC=$(echo "$full_line" | awk '{print $1}')
            NAME=$(echo "$full_line" | cut -d' ' -f2-)
            [ -z "$MAC" ] && continue
            if [ "$ALWAYS_ALERT" != "1" ] && echo "$SEEN_STRONG" | grep -q "$MAC BLE_PINEAPPLE"; then continue; fi
            MATCH=$(pineapple_match "$MAC" "$NAME")
            [ -z "$MATCH" ] && continue
            CURRENT_TIME=$(date '+%H:%M:%S')
            ENTRY="DECT: $CURRENT_TIME | $MAC | Rogue Pineapple? (BLE \"$NAME\", $MATCH)$GPS_TAG"
            bump_counter pineapple "$MAC" "$MAC"
            echo "$ENTRY" >> "$LOG_FILE"
            stealth_blink
            SEEN_STRONG="$SEEN_STRONG $MAC BLE_PINEAPPLE"
        done < <(sort -u /tmp/hci_scan.txt)
    fi
    fi   # closes the WANT_FLOCK/WANT_MESH/WANT_TRACKER/WANT_DRONE/WANT_SKIMMER/WANT_PINEAPPLE BLE-scan gate above

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

    # --- Flock addr1 (receiver-address) scan: drain whatever ---
    # --- flock_wifi_addr1_monitor.awk found -- see that file's header for ---
    # --- the UNVERIFIED technique this is. Output is the same "wifi_flock|
    # --- ...|conf=medium" shape flock_wifi_monitor.awk's own Beacon/Probe-
    # --- Response match uses, so it reuses handle_flock_wifi_line() as-is,
    # --- no new handler needed.
    if [ "$FLOCK_WIFI_OK" = "1" ] && [ -f "$SCRIPT_DIR/flock_wifi_addr1_monitor.awk" ]; then
        NEW_SIZE=$(wc -c < "$FLOCK_ADDR1_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$FLOCK_ADDR1_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_flock_wifi_line "$line"
            done < <(tail -c "+$((FLOCK_ADDR1_HITS_OFFSET + 1))" "$FLOCK_ADDR1_HITS")
            FLOCK_ADDR1_HITS_OFFSET=$NEW_SIZE
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
    # (also carries "ble_beacon|..." lines from that same file's generic
    # iBeacon/Eddystone branches -- routed to handle_beacon_line() instead,
    # see rogue_tracker_monitor.awk's header for why they're one process.)
    if [ "$TRACKER_BLE_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$TRACKER_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$TRACKER_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                case "$line" in
                    ble_beacon\|*) [ -n "$line" ] && handle_beacon_line "$line" ;;
                    *)             [ -n "$line" ] && handle_tracker_line "$line" ;;
                esac
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

    # Refresh the stats screen's source data every cycle. No heartbeat
    # paint any more, and nothing reaches the screen here at all -- LEFT
    # is what puts the panel up, whenever you want it.
    write_dash_state

    sleep 3
done
}

detection_loop &
DETECTION_PID=$!

# ---------------------------------------------------------------------------
# Menu -- the foreground, and the only thing that draws
# ---------------------------------------------------------------------------
# Modelled on bt-bluepine: print a screen, block on a picker, act, print,
# block again. The screen never changes while it is being read, because
# the only process that draws is the one waiting for you.

# Hold a screen until a button is pressed.
#
# Without this the menu loop raises the next LIST_PICKER the instant a screen
# finishes printing, and the picker draws straight over it -- reported from
# the device as "it goes to a dashboard then quickly gives the choice again".
# bt-bluepine does not have that problem because it never returns straight to
# its picker: it prints, says "Press OK...", and blocks on
# WAIT_FOR_BUTTON_PRESS first. This is that wait.
#
# WAIT_FOR_INPUT (any button) rather than WAIT_FOR_BUTTON_PRESS A (BluePine's
# choice): any press dismissing the screen is kinder than hunting for one
# specific key, and WAIT_FOR_INPUT is the call already confirmed working on
# this device.
pause_screen() {
    LOG green "Press any button to return to the menu"
    WAIT_FOR_INPUT >/dev/null 2>&1
}

screen_live_stats()   { show_dash_screen; }

# Last hits across every loot file this session, newest first. Read from
# the files rather than from memory: the counters live in detection_loop's
# process and are not visible here.
screen_recent() {
    local n=0 f line
    LOG magenta "$(dash_rule 'Recent Detections')"
    for f in "$LOG_FILE" "$TRACKER_LOG_FILE" "$DRONE_LOG_FILE" "$DEAUTH_LOG_FILE"; do
        [ -s "$f" ] || continue
        while IFS= read -r line; do
            case "$line" in ""|*"log started"*|*"started at"*) continue ;; esac
            LOG "${line:0:48}"
            n=$((n + 1))
            [ "$n" -ge 8 ] && break
        done < <(tail -n 8 "$f")
        [ "$n" -ge 8 ] && break
    done
    [ "$n" = "0" ] && LOG green "Nothing logged yet this session"
    LOG magenta "$(dash_rule 'Recent Detections')"
}


screen_session() {
    LOG magenta "$(dash_rule 'Session Files')"
    LOG cyan "Loot: $LOOT_DIR"
    LOG "Session: $TIMESTAMP"
    LOG "Version: v$SCRIPT_VERSION"
    LOG magenta "$(dash_rule 'Session Files')"
}

# Falls back to running headless if LIST_PICKER is missing, rather than
# spinning on a picker that never returns -- same defensive stance the
# startup toggle menu already takes.
if ! command -v LIST_PICKER >/dev/null 2>&1; then
    LOG red "LIST_PICKER unavailable -- detectors running, no menu."
    wait "$DETECTION_PID"
    exit 0
fi

LOG " "
LOG green "Detectors running in the background. Use the menu."

# Cross-process-safe status line for the menu banner below: pulled from
# $DASH_STATE_FILE rather than GPS_FIX/STEALTH_MODE/DETECTIONS directly.
# Those only exist inside detection_loop's process (backgrounded with
# "detection_loop &", a separate shell) -- see write_dash_state()'s own
# header for why the state file is the only channel between the two. Line
# 2 of that file is always write_dash_state()'s "Uptime: .. | GPS: .. |
# Alerts: .." cyan fact line; cut drops just the leading "cyan|" colour
# field and rejoins the rest on the same delimiter, which is safe here
# because that line's own " | " separators use spaces around the pipe and
# never collide with cut's bare "|" field split.
menu_status_line() {
    [ -s "$DASH_STATE_FILE" ] && sed -n '2p' "$DASH_STATE_FILE" | cut -d'|' -f2-
}

# Persistent header + numbered list, painted before every LIST_PICKER
# raise -- context only, NOT gated behind its own WAIT_FOR_INPUT. An
# earlier version of this function added that second gate, modeled on
# bt-bluepine's main_menu() (which does block on a press before its own
# picker) -- confirmed live on THIS device to cause exactly the "flashing
# between two screens" symptom pause_screen() exists to prevent: reported
# from the field as the banner and the picker alternating rapidly.
#
# The mechanism isn't WAIT_FOR_INPUT itself -- pause_screen() below uses
# the identical call and has been solid the whole time this function
# existed. What's different here is calling it a SECOND time back-to-back:
# every path into this function arrives immediately after pause_screen()'s
# own WAIT_FOR_INPUT just returned (leaf screen) or after a
# CONFIRMATION_DIALOG just closed (declined Stop Scanning), with no
# rendering happening in between the two waits the way pause_screen()
# always has (a leaf screen's own LOG output, including this file's
# dash-style sleep 0.2 pauses between sections, running before ITS
# WAIT_FOR_INPUT is reached). Two WAIT_FOR_INPUT calls with nothing
# rendered between them is the one thing that changed; removing this
# function's own call, while still painting the banner for context, is
# the targeted revert -- pause_screen() already covers the transition that
# actually caused the original documented bug (leaf screen -> menu).
show_menu_banner() {
    local status
    status=$(menu_status_line)
    LOG magenta "$(dash_rule 'Main Menu')"
    [ -n "$status" ] && LOG cyan "$status"
    LOG "1: Live Stats"
    LOG "2: Recent Detections"
    LOG "3: Bookmark This Moment"
    LOG "4: Session Files"
    LOG "5: GPS Status"
    LOG "0: Stop Scanning"
}

while true; do
    show_menu_banner
    _sel=$(LIST_PICKER "Counter-Surveillance v$SCRIPT_VERSION" \
        "1: Live Stats" \
        "2: Recent Detections" \
        "3: Bookmark This Moment" \
        "4: Session Files" \
        "5: GPS Status" \
        "0: Stop Scanning" \
        "1: Live Stats")
    case "$_sel" in
        "1: Live Stats")           screen_live_stats; pause_screen ;;
        "2: Recent Detections")    screen_recent;  pause_screen ;;
        "3: Bookmark This Moment") do_bookmark;    pause_screen ;;
        "4: Session Files")        screen_session; pause_screen ;;
        "5: GPS Status")           screen_gps;     pause_screen ;;
        "0: Stop Scanning")
            # Confirmation dialog, bt-bluepine style (its own main_menu()
            # exit does the same before killing anything). Guarded the
            # same way LIST_PICKER itself is guarded above: if
            # CONFIRMATION_DIALOG isn't available, fall through to the old
            # immediate-stop behavior rather than hang waiting on a verb
            # that doesn't exist here.
            if command -v CONFIRMATION_DIALOG >/dev/null 2>&1; then
                _resp=$(CONFIRMATION_DIALOG "Stop scanning and exit?")
                [ "$_resp" = "$DUCKYSCRIPT_USER_CONFIRMED" ] && break
                continue
            fi
            break
            ;;
        *)                         break ;;
    esac
done

LOG magenta "$(dash_rule 'Stopping')"
kill "$DETECTION_PID" 2>/dev/null
wait "$DETECTION_PID" 2>/dev/null
LOG green "Detectors stopped. Loot in $LOOT_DIR"
exit 0
