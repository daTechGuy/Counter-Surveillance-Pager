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
#              baked-in list to port) -- combined with an Open Drone ID
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
#   Flock WiFi scan    : + awk, iw, tcpdump, a second radio (phy0/wlan0mon)
#                        -- shares its capture radio/channel-hop with Drone
#                        WiFi scan
#   Mesh-Detect BLE scan: none beyond Flock BLE scan above -- reuses its
#                        hcitool lescan output, only runs once
#                        mesh_detect_targets.conf has an oui:/mac:/name: entry
#   Mesh-Detect WiFi scan: + awk, iw, tcpdump, a second radio (phy0/wlan0mon)
#                        -- same shared radio/channel-hop, only runs once
#                        mesh_detect_targets.conf has an oui:/mac: entry
#   Rogue tracker BLE scan: + awk, hcidump (own reader, alongside Drone BLE
#                        scan's) -- no config needed to be active, but see
#                        tracker_allowlist.conf re: your own trackers
#   Drone BLE scan    : + awk, hcidump
#   Drone WiFi scan   : + awk, iw, tcpdump, a second radio (phy0/wlan0mon)
# ============================================================================
#
# WIFI RADIO: phy0/wlan0mon, NOT phy1/wlan1mon -- confirmed live on hardware
# that phy1/wlan1mon is the Pager's own default-configured primary recon
# interface (/etc/config/pineapd: `bands '2,5'`, `hop '1'`, `hopspeed
# 'fast'`, auto-started at boot by pineapd --recon=true), which actively
# fights this payload's own channel-hop loop for control of that interface
# -- observed as wifi_hop.log filling with continuous "Resource busy (-16)"
# and wlan1mon's actual channel drifting onto 5GHz (44, 144) that this
# payload's own hop set never sets, meaning none of the WiFi detectors were
# reliably on the 2.4GHz channels they need to be on. phy0/wlan0mon was
# confirmed idle (no pineapd hop activity, wlan0 not currently acting as an
# AP) at the time of this fix, and is also the more capable radio (2.4/5/
# 6GHz ac/ax vs wlan1mon's 2.4GHz-only) -- though WIFI_CHANNELS below is
# deliberately still 2.4GHz-only (11/6/1), matching flock-you's own hop set,
# since the devices this payload targets are overwhelmingly 2.4GHz; wider
# per-cycle coverage would mean less dwell time on the channels that
# actually matter. KNOWN RISK: if the Pager's native AP/hotspot features
# ever get used on phy0 while this payload is running, THAT would collide
# with wlan0mon the same way pineapd's recon collided with wlan1mon -- this
# wasn't the case when this fix was made and verified, but isn't guaranteed
# to never happen.
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
#    handle_tracker_line() below) has no GPS and can't tell "this tracker
#    has followed me across locations" from "this tracker has sat 15+
#    minutes near wherever the Pager itself is sitting" -- it's the same
#    class of heuristic Apple/Android's own on-device detection uses, just
#    without their location-diversity refinement. A tracker in a stationary
#    neighboring apartment/vehicle you're not near could false-positive if
#    you happen to stay put nearby for the persistence window; a tracker
#    that boards a fast-moving vehicle you're not in but that happens to sit
#    near the Pager only briefly could false-negative.
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
#    rid_wifi_monitor.awk -- but the detection logic itself has NOT yet been
#    confirmed against a real Flock Safety camera's actual RF, only against
#    flock-you's published fingerprint constant. If a real camera's IE
#    signature has drifted from that constant (as it apparently already has
#    at least once upstream), this will silently miss it the same way the
#    unmodified BLE path can. Treat this as "ported and unit-tested," not
#    "field-confirmed."
#  - mesh_wifi_monitor.awk's matching logic (OUI/MAC lookup, config-file
#    parsing) is likewise only unit-tested against synthetic packets and a
#    synthetic config file, not run on-device yet -- same "ported and
#    unit-tested, not field-confirmed" caveat applies.
#  - rogue_tracker_monitor.awk has been checked against synthetic packets
#    for all four protocols (positive match per protocol, two negative
#    cases, and the packet-count emit-throttle) with gawk -- not yet against
#    a real AirTag/Tile/SmartTag/FMDN accessory or on-device. Same "unit-
#    tested, not field-confirmed" caveat as the WiFi detectors above.
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
touch "$BLE_HITS" "$WIFI_HITS" "$FLOCK_WIFI_HITS" "$MESH_WIFI_HITS" "$TRACKER_HITS"
BLE_FIFO="$WORK_DIR/ble_raw.fifo"
WIFI_FIFO="$WORK_DIR/wifi_raw.fifo"
FLOCK_WIFI_FIFO="$WORK_DIR/flock_wifi_raw.fifo"
MESH_WIFI_FIFO="$WORK_DIR/mesh_wifi_raw.fifo"
TRACKER_FIFO="$WORK_DIR/tracker_raw.fifo"
rm -f "$BLE_FIFO" "$WIFI_FIFO" "$FLOCK_WIFI_FIFO" "$MESH_WIFI_FIFO" "$TRACKER_FIFO"

MESH_CONFIG_FILE="$SCRIPT_DIR/mesh_detect_targets.conf"
TRACKER_ALLOWLIST_FILE="$SCRIPT_DIR/tracker_allowlist.conf"
TRACKER_LOG_FILE="${LOOT_DIR}/rogue_trackers_${TIMESTAMP}.txt"
echo "Rogue BLE tracker log started at $(date)" > "$TRACKER_LOG_FILE"
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

WIFI_IFACE="wlan0mon"
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
WIFI_HOP_PID=""
WIFI_IFACE_CREATED=0

cleanup() {
    for p in "$HCIDUMP_PID" "$BLE_MON_PID" "$TCPDUMP_PID" "$WIFI_MON_PID" \
             "$FLOCK_TCPDUMP_PID" "$FLOCK_WIFI_MON_PID" \
             "$MESH_TCPDUMP_PID" "$MESH_WIFI_MON_PID" \
             "$TRACKER_HCIDUMP_PID" "$TRACKER_MON_PID" "$WIFI_HOP_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    rm -f "$BLE_FIFO" "$WIFI_FIFO" "$FLOCK_WIFI_FIFO" "$MESH_WIFI_FIFO" "$TRACKER_FIFO"
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
if [ "$MESH_BLE_OK" = "1" ]; then
    LOG green "Mesh-Detect BLE detection: enabled (${#MESH_OUI_TARGETS[@]} oui, ${#MESH_MAC_TARGETS[@]} mac, ${#MESH_NAME_TARGETS[@]} name target(s))"
else
    LOG yellow "Mesh-Detect BLE detection: no-op (mesh_detect_targets.conf has no oui:/mac:/name: entries yet)"
fi

if [ "$AWK_FILES_OK" = "1" ] && [ -n "$AWK" ] && [ -n "$HCIDUMP" ]; then
    BLE_RID_OK=1
    LOG green "Drone BLE detection: enabled (hcidump found)"
elif [ "$AWK_FILES_OK" = "1" ]; then
    LOG red "Drone BLE detection: disabled (missing$( [ -z "$AWK" ] && echo " awk")$( [ -z "$HCIDUMP" ] && echo " hcidump"))"
fi

# Own file-existence gate (like FLOCK_AWK_FILE_OK / MESH_AWK_FILE_OK above) --
# a missing rogue_tracker_monitor.awk shouldn't take down drone BLE detection.
if [ -n "$AWK" ] && [ -n "$HCIDUMP" ] && [ -f "$SCRIPT_DIR/rogue_tracker_monitor.awk" ]; then
    TRACKER_BLE_OK=1
    LOG green "Rogue tracker BLE detection: enabled (hcidump found)"
elif [ ! -f "$SCRIPT_DIR/rogue_tracker_monitor.awk" ]; then
    LOG red "Rogue tracker BLE detection: disabled (rogue_tracker_monitor.awk not found -- looked in $SCRIPT_DIR)"
else
    LOG red "Rogue tracker BLE detection: disabled (missing$( [ -z "$AWK" ] && echo " awk")$( [ -z "$HCIDUMP" ] && echo " hcidump"))"
fi

if [ "$AWK_FILES_OK" = "1" ] && [ -n "$AWK" ] && [ -n "$IW" ] && [ -n "$TCPDUMP" ] && iw phy phy0 info >/dev/null 2>&1; then
    if ! iw dev "$WIFI_IFACE" info >/dev/null 2>&1; then
        if iw phy phy0 interface add "$WIFI_IFACE" type monitor 2>>"$LOG_FILE"; then
            WIFI_IFACE_CREATED=1
        fi
    fi
    if iw dev "$WIFI_IFACE" info >/dev/null 2>&1; then
        ip link set "$WIFI_IFACE" up 2>>"$LOG_FILE"
        iw dev "$WIFI_IFACE" set channel "${WIFI_CHANNELS%% *}" 2>>"$LOG_FILE"
        WIFI_RID_OK=1
        LOG green "Drone WiFi detection: enabled ($WIFI_IFACE on phy0, hopping ch $WIFI_CHANNELS)"
        wifi_channel_hop &
        WIFI_HOP_PID=$!
        if [ "$FLOCK_AWK_FILE_OK" = "1" ]; then
            FLOCK_WIFI_OK=1
            LOG green "Flock WiFi detection: enabled ($WIFI_IFACE on phy0, hopping ch $WIFI_CHANNELS)"
        fi
        if [ "$MESH_AWK_FILE_OK" = "1" ] && [ "$MESH_WIFI_TARGETS_PRESENT" = "1" ]; then
            MESH_WIFI_OK=1
            LOG green "Mesh-Detect WiFi detection: enabled ($WIFI_IFACE on phy0, hopping ch $WIFI_CHANNELS)"
        elif [ "$MESH_AWK_FILE_OK" = "1" ]; then
            LOG yellow "Mesh-Detect WiFi detection: no-op (mesh_detect_targets.conf has no oui:/mac: entries yet)"
        fi
    fi
fi
if [ "$WIFI_RID_OK" = "0" ] && [ "$AWK_FILES_OK" = "1" ]; then
    LOG red "Drone WiFi detection: disabled (need awk+iw+tcpdump and a usable phy0)"
fi
if [ "$FLOCK_WIFI_OK" = "0" ] && [ "$FLOCK_AWK_FILE_OK" = "1" ] && [ "$WIFI_RID_OK" = "0" ]; then
    LOG red "Flock WiFi detection: disabled (need awk+iw+tcpdump and a usable phy0)"
fi
if [ "$MESH_WIFI_OK" = "0" ] && [ "$MESH_AWK_FILE_OK" = "1" ] && [ "$MESH_WIFI_TARGETS_PRESENT" = "1" ] && [ "$WIFI_RID_OK" = "0" ]; then
    LOG red "Mesh-Detect WiFi detection: disabled (need awk+iw+tcpdump and a usable phy0)"
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

LOG "Color key:"
LOG yellow   "  FS Ext Battery"
LOG green    "  Penguin"
LOG magenta  "  Pigvision"
LOG cyan     "  Other Flock (BLE name match or WiFi wildcard-probe/IE match)"
LOG          "  Mesh-Detect (your OUI/MAC/name watchlist -- uncolored, see mesh_detect_targets.conf)"
LOG red      "  Drone Remote ID / Rogue BLE Tracker (both same color -- distinguished by alert text)"
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

# Per (mac|protocol) tracker state -- see handle_tracker_line(). Keyed on
# the exact string rogue_tracker_monitor.awk emits as its 3rd field
# (applefindmy/tile/smarttag/fmdn_normal/fmdn_unwanted), so Apple/Samsung/
# Google's MAC rotation naturally starts a fresh persistence count under a
# new key once the MAC changes -- there's no way around that without the
# key-derivation access described in tracker_allowlist.conf's header.
declare -A TRACKER_FIRST_SEEN
declare -A TRACKER_SIGHTINGS
declare -A TRACKER_LAST_ALERT

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

# Parse one "wifi_flock|MAC|wildcard_probe_ie_sig|oui=xx:xx:xx" line from
# flock_wifi_monitor.awk and LOG/loot/vibrate it -- same session-lifetime
# dedup (SEEN_STRONG) and physical alert as the BLE Flock hits below, so a
# camera caught by both radios doesn't double up every cycle.
handle_flock_wifi_line() {
    local line="$1"
    local src mac msgtype kv
    IFS='|' read -r src mac msgtype kv <<< "$line"
    [ -z "$mac" ] && return
    if echo "$SEEN_STRONG" | grep -q "$mac WIFI_FLOCK"; then return; fi

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    ENTRY="DECT: $CURRENT_TIME | $mac | Flock (WiFi $msgtype, $kv)"
    LOG cyan "$ENTRY"
    echo "$ENTRY" >> "$LOG_FILE"
    DETECTIONS=$((DETECTIONS + 1))
    COUNTER=$((COUNTER + 1))
    if [ -f /sys/class/gpio/vibrator/value ]; then
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.15
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
    fi
    if ls /sys/class/leds/* >/dev/null 2>&1; then
        LED=$(ls /sys/class/leds/* | head -1)
        echo 1 > "${LED}/brightness" 2>/dev/null
        sleep 0.3
        echo 0 > "${LED}/brightness" 2>/dev/null
    fi
    SEEN_STRONG="$SEEN_STRONG $mac WIFI_FLOCK"
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

    local vendor
    vendor=$(mesh_vendor_label "${matchkind#*:}")

    local CURRENT_TIME ENTRY
    CURRENT_TIME=$(date '+%H:%M:%S')
    if [ -n "$vendor" ]; then
        ENTRY="DECT: $CURRENT_TIME | $mac | $vendor detected (WiFi, $matchkind)"
    else
        ENTRY="DECT: $CURRENT_TIME | $mac | Mesh-Detect (WiFi, $matchkind)"
    fi
    LOG "$ENTRY"
    echo "$ENTRY" >> "$LOG_FILE"
    DETECTIONS=$((DETECTIONS + 1))
    COUNTER=$((COUNTER + 1))
    if [ -f /sys/class/gpio/vibrator/value ]; then
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.15
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
    fi
    if ls /sys/class/leds/* >/dev/null 2>&1; then
        LED=$(ls /sys/class/leds/* | head -1)
        echo 1 > "${LED}/brightness" 2>/dev/null
        sleep 0.3
        echo 0 > "${LED}/brightness" 2>/dev/null
    fi
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

    local key="${mac}|${protocol}"
    local now
    now=$(date +%s)
    [ -z "${TRACKER_FIRST_SEEN[$key]:-}" ] && TRACKER_FIRST_SEEN[$key]=$now
    TRACKER_SIGHTINGS[$key]=$(( ${TRACKER_SIGHTINGS[$key]:-0} + 1 ))

    local label
    label=$(tracker_protocol_label "$protocol")
    echo "$(date '+%H:%M:%S') | $mac | $label | sighting=${TRACKER_SIGHTINGS[$key]} | $detail" >> "$TRACKER_LOG_FILE"

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
    LED RED
    RINGTONE warning
    ALERT_RINGTONE "ROGUE TRACKER" "$label\n$mac\nseen ${TRACKER_SIGHTINGS[$key]}x over ${minutes}min"
    LED OFF
    DETECTIONS=$((DETECTIONS + 1))
}

# Parse one "SRC|MAC|MSG_TYPE|k=v;k=v;..." line and LOG/alert/loot it.
handle_rid_line() {
    local line="$1"
    local src mac msgtype kv
    IFS='|' read -r src mac msgtype kv <<< "$line"
    [ -z "$mac" ] && return

    echo "$(date '+%H:%M:%S') | $src | $mac | $msgtype | $kv" >> "$DRONE_LOG_FILE"

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
        LED RED
        RINGTONE warning
        ALERT_RINGTONE "DRONE REMOTE ID" "$label\n$summary\nvia $src"
        LED OFF
    fi
}

while true; do
    # --- Flock Safety BLE scan cycle (unmodified from Flock-You / Flock_Detect) ---
    hciconfig hci0 down 2>>"$LOG_FILE"
    hciconfig hci0 reset 2>>"$LOG_FILE"
    hciconfig hci0 up 2>>"$LOG_FILE"
    timeout 18 hcitool lescan --duplicates > /tmp/hci_scan.txt 2>>"$LOG_FILE" &
    PID=$!
    sleep 12
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    if [ -s /tmp/hci_scan.txt ]; then
        grep -i "fs ext battery\|penguin\|flock\|pigvision" /tmp/hci_scan.txt | sort -u | while read -r full_line; do
            MAC=$(echo "$full_line" | awk '{print $1}')
            NAME=$(echo "$full_line" | cut -d' ' -f2-)
            if echo "$SEEN_STRONG" | grep -q "$MAC $NAME"; then continue; fi
            CURRENT_TIME=$(date '+%H:%M:%S')
            ENTRY="DECT: $CURRENT_TIME | $MAC | $NAME"
            if echo "$NAME" | grep -qi "fs ext battery"; then
                LOG yellow "$ENTRY"
            elif echo "$NAME" | grep -qi "penguin"; then
                LOG green "$ENTRY"
            elif echo "$NAME" | grep -qi "pigvision"; then
                LOG magenta "$ENTRY"
            elif echo "$NAME" | grep -qi "flock"; then
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
            if [ -f /sys/class/gpio/vibrator/value ]; then
                echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
                sleep 0.15
                echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
            fi
            if ls /sys/class/leds/* >/dev/null 2>&1; then
                LED=$(ls /sys/class/leds/* | head -1)
                echo 1 > "${LED}/brightness" 2>/dev/null
                sleep 0.3
                echo 0 > "${LED}/brightness" 2>/dev/null
            fi
            SEEN_STRONG="$SEEN_STRONG $MAC $NAME"
        done
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
                ENTRY="DECT: $CURRENT_TIME | $MAC | $VENDOR detected (BLE \"$NAME\", $MATCH)"
            else
                ENTRY="DECT: $CURRENT_TIME | $MAC | Mesh-Detect (BLE \"$NAME\", $MATCH)"
            fi
            LOG "$ENTRY"
            echo "$ENTRY" >> "$LOG_FILE"
            DETECTIONS=$((DETECTIONS + 1))
            COUNTER=$((COUNTER + 1))
            if [ -f /sys/class/gpio/vibrator/value ]; then
                echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
                sleep 0.15
                echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
            fi
            if ls /sys/class/leds/* >/dev/null 2>&1; then
                LED=$(ls /sys/class/leds/* | head -1)
                echo 1 > "${LED}/brightness" 2>/dev/null
                sleep 0.3
                echo 0 > "${LED}/brightness" 2>/dev/null
            fi
            SEEN_STRONG="$SEEN_STRONG $MAC MESH_BLE"
        done < <(sort -u /tmp/hci_scan.txt)
    fi

    # --- Flock Safety WiFi scan: drain whatever flock_wifi_monitor.awk found ---
    # Uses process substitution (not a `cmd | while` pipe) so the SEEN_STRONG
    # update inside handle_flock_wifi_line persists in *this* shell -- see the
    # comment on the drone RID drains below for why a plain pipe would lose it.
    if [ "$FLOCK_WIFI_OK" = "1" ]; then
        NEW_SIZE=$(wc -c < "$FLOCK_WIFI_HITS" 2>/dev/null); [ -z "$NEW_SIZE" ] && NEW_SIZE=0
        if [ "$NEW_SIZE" -gt "$FLOCK_WIFI_HITS_OFFSET" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && handle_flock_wifi_line "$line"
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
