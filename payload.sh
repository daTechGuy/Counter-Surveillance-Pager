#!/bin/bash
# Title: Flock-Sky-Spy - Combined Flock Safety + Drone Remote ID Detector
# Description: Flock Safety surveillance device detector -- BLE device-name
#              scanning (unmodified logic from Flock-You / Flock_Detect) PLUS
#              a port of flock-you's current WiFi method (OUI-gated
#              wildcard-SSID Probe Request + IE fingerprint, with the same
#              11/6/1 channel hop flock-you uses), since flock-you's main
#              branch moved to WiFi as its primary detection path and the
#              BLE name scan alone was found to miss cameras -- combined with
#              an Open Drone ID (ASTM F3411) detector covering all three
#              broadcast transports: BLE legacy advertising, WiFi Beacon, and
#              WiFi NAN -- ported from the Sky-Spy ESP32 firmware's detection
#              approach onto the Pager's Linux BLE/WiFi stack, since no
#              Linux/bash build of Sky-Spy exists upstream.
# Credit: All three detection concepts this payload combines originate with
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
#   All credit for the underlying detection concepts and the original
#   Flock-You code belongs to Colonel Panic; this payload is a derivative work.
# Original Flock-You Contributors: colonelpanichacks, Claude (Anthropic), Grok (xAI), Brandon Starkweather
# Remote ID spec/byte-offset sources (see rid_common.awk header for citations):
#   opendroneid/opendroneid-core-c, opendroneid/transmitter-linux
# Category: Reconnaissance
#
# The Remote ID decoders and the WiFi Flock detector are plain POSIX-ish awk
# (rid_common.awk + rid_ble_monitor.awk + rid_wifi_monitor.awk +
# flock_wifi_monitor.awk), not python3: this device (mipsel_24kc / ramips,
# 30M flash) has no python3 in its opkg feeds at all, confirmed live against
# the actual hardware -- awk was confirmed present with the specific
# functions needed (index/substr/toupper/sprintf/fflush).
# The Remote ID awk parsers were verified against this exact device's real
# hcidump 5.72 / tcpdump 4.99.5 text-output formats, including hand-decoding
# a real capture byte-by-byte to confirm the framing, before being wired in
# here. flock_wifi_monitor.awk reuses that same verified tcpdump -xx framing;
# its detection logic itself (OUI list, wildcard/IE-signature check) was
# validated against synthetic packets built to match flock-you's own
# FLOCK_PROBE_IE_SIG_PRIMARY constant, not yet against a real camera capture
# -- see KNOWN LIMITATIONS.
#
# ============================================================================
# REQUIRES, PER DETECTOR (each is independently optional -- missing tools
# just disable that one piece and are reported at startup, everything else
# still runs):
#   Flock BLE scan    : hciconfig, hcitool               (stock on Flock-You)
#   Flock WiFi scan    : + awk, iw, tcpdump, a second radio (phy1) -- shares
#                        its capture radio/channel-hop with Drone WiFi scan
#   Drone BLE scan    : + awk, hcidump
#   Drone WiFi scan   : + awk, iw, tcpdump, a second radio (phy1)
# ============================================================================
#
# KNOWN LIMITATIONS -- read before relying on this in the field:
#  - Drone BLE detection only sees advertisements during Flock-You's own
#    ~12-of-15s hcitool lescan windows (it piggybacks on that scan rather
#    than running a separate one) -- NOT continuous like the ESP32 Sky-Spy.
#  - Both WiFi detectors (Flock probe + drone Remote ID) now share one
#    hopped radio (channels 11/6/1, 250ms dwell, matching flock-you's own
#    CUSTOM hop set) instead of drone detection's old fixed channel 6. A
#    drone beaconing Remote ID only on 5GHz, or on a 2.4GHz channel outside
#    11/6/1, will still be missed.
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
#  - BLE Extended/Long-Range advertising (Bluetooth 5) Remote ID is not
#    decoded, only Legacy advertising -- covers the common case.
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
for _candidate in "." "/root/payloads/user/reconnaissance/Flock_Sky_Spy" "$(dirname "$0" 2>/dev/null)"; do
    if [ -n "$_candidate" ] && [ -f "$_candidate/rid_common.awk" ]; then
        SCRIPT_DIR="$_candidate"
        break
    fi
done
LOOT_DIR="/root/loot/flock_sky_spy"
WORK_DIR="/tmp/flock_sky_spy"
mkdir -p "$LOOT_DIR" "$WORK_DIR"
rm -f "$WORK_DIR"/*.log "$WORK_DIR"/*.fifo 2>/dev/null

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOOT_DIR}/flock_you_${TIMESTAMP}.txt"
DRONE_LOG_FILE="${LOOT_DIR}/drone_rid_${TIMESTAMP}.txt"
# Created (truncating) here, before any of the capability-detection commands
# below start appending (2>>) diagnostic output to LOG_FILE -- writing this
# with `>` again later would silently wipe out those first-run diagnostics
# right when they're most useful (e.g. did `iw ... type monitor` fail?).
echo "Flock-Sky-Spy started at $(date)" > "$LOG_FILE"
echo "Drone Remote ID log started at $(date)" > "$DRONE_LOG_FILE"

BLE_HITS="$WORK_DIR/ble_rid_hits.log"
WIFI_HITS="$WORK_DIR/wifi_rid_hits.log"
FLOCK_WIFI_HITS="$WORK_DIR/flock_wifi_hits.log"
touch "$BLE_HITS" "$WIFI_HITS" "$FLOCK_WIFI_HITS"
BLE_FIFO="$WORK_DIR/ble_raw.fifo"
WIFI_FIFO="$WORK_DIR/wifi_raw.fifo"
FLOCK_WIFI_FIFO="$WORK_DIR/flock_wifi_raw.fifo"
rm -f "$BLE_FIFO" "$WIFI_FIFO" "$FLOCK_WIFI_FIFO"

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
WIFI_HOP_PID=""
WIFI_IFACE_CREATED=0

cleanup() {
    for p in "$HCIDUMP_PID" "$BLE_MON_PID" "$TCPDUMP_PID" "$WIFI_MON_PID" \
             "$FLOCK_TCPDUMP_PID" "$FLOCK_WIFI_MON_PID" "$WIFI_HOP_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    rm -f "$BLE_FIFO" "$WIFI_FIFO" "$FLOCK_WIFI_FIFO"
    if [ "$WIFI_IFACE_CREATED" = "1" ]; then
        iw dev "$WIFI_IFACE" del 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

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

LOG yellow "Flock-Sky-Spy started at $(date)"

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

if [ "$AWK_FILES_OK" = "1" ] && [ -n "$AWK" ] && [ -n "$HCIDUMP" ]; then
    BLE_RID_OK=1
    LOG green "Drone BLE detection: enabled (hcidump found)"
elif [ "$AWK_FILES_OK" = "1" ]; then
    LOG red "Drone BLE detection: disabled (missing$( [ -z "$AWK" ] && echo " awk")$( [ -z "$HCIDUMP" ] && echo " hcidump"))"
fi

if [ "$AWK_FILES_OK" = "1" ] && [ -n "$AWK" ] && [ -n "$IW" ] && [ -n "$TCPDUMP" ] && iw phy phy1 info >/dev/null 2>&1; then
    if ! iw dev "$WIFI_IFACE" info >/dev/null 2>&1; then
        if iw phy phy1 interface add "$WIFI_IFACE" type monitor 2>>"$LOG_FILE"; then
            WIFI_IFACE_CREATED=1
        fi
    fi
    if iw dev "$WIFI_IFACE" info >/dev/null 2>&1; then
        ip link set "$WIFI_IFACE" up 2>>"$LOG_FILE"
        iw dev "$WIFI_IFACE" set channel "$(echo $WIFI_CHANNELS | cut -d' ' -f1)" 2>>"$LOG_FILE"
        WIFI_RID_OK=1
        LOG green "Drone WiFi detection: enabled ($WIFI_IFACE on phy1, hopping ch $WIFI_CHANNELS)"
        wifi_channel_hop &
        WIFI_HOP_PID=$!
        if [ "$FLOCK_AWK_FILE_OK" = "1" ]; then
            FLOCK_WIFI_OK=1
            LOG green "Flock WiFi detection: enabled ($WIFI_IFACE on phy1, hopping ch $WIFI_CHANNELS)"
        fi
    fi
fi
if [ "$WIFI_RID_OK" = "0" ] && [ "$AWK_FILES_OK" = "1" ]; then
    LOG red "Drone WiFi detection: disabled (need awk+iw+tcpdump and a usable phy1)"
fi
if [ "$FLOCK_WIFI_OK" = "0" ] && [ "$FLOCK_AWK_FILE_OK" = "1" ] && [ "$WIFI_RID_OK" = "0" ]; then
    LOG red "Flock WiFi detection: disabled (need awk+iw+tcpdump and a usable phy1)"
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

LOG "Color key:"
LOG yellow   "  FS Ext Battery"
LOG green    "  Penguin"
LOG magenta  "  Pigvision"
LOG cyan     "  Other Flock (BLE name match or WiFi wildcard-probe/IE match)"
LOG red      "  Drone Remote ID"
LOG "----------------------------------"

DETECTIONS=0
SEEN_STRONG=""
COUNTER=0

declare -A DRONE_LAST_ALERT
declare -A DRONE_KNOWN
BLE_HITS_OFFSET=0
WIFI_HITS_OFFSET=0
FLOCK_WIFI_HITS_OFFSET=0

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
