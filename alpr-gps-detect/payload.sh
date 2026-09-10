#!/bin/bash
# Title: ALPR-GPS-Detect - known ALPR cameras by position, no radio
# Description: Cross-references the Pager's live GPS position against a local
#              database of known ALPR (automatic licence plate reader) camera
#              locations, and alerts when you come within range of one.
#              Split out of Counter-Surveillance-Pager, where it ran as one
#              detector among eight.
# Author: daTechGuy
# Version: see the VERSION file beside this script
# Category: reconnaissance
#
# ============================================================================
# WHY THIS IS ITS OWN PAYLOAD
# ============================================================================
# Every other detector in Counter-Surveillance-Pager is a radio listener: it
# hears something and decides what it is. This one hears nothing. It is pure
# geography -- where am I, and is there a camera near here on a map somebody
# else already drew. That difference runs deeper than it sounds:
#
#   - It needs NO radio at all. No BLE adapter, no monitor-mode WiFi, no
#     channel hopping, none of the pineapd contention the WiFi detectors have
#     to be configured around. Only GPS_GET and sqlite3.
#   - It therefore CANNOT be starved by the shared-radio duty cycle that
#     every other detector competes inside, and equally it never takes radio
#     time from them.
#   - It alerts on ground truth rather than an RF heuristic. A database match
#     is a mapped camera, not a signature that might be something else, which
#     is why its alert is a hard one.
#   - It carries a 3.8MB dataset that nothing else in that payload reads.
#
# Running it separately also means it can run when the other payload cannot,
# or should not: no radios means nothing transmits, nothing is put into
# monitor mode, and battery cost is a GPS fix and one indexed query every few
# seconds.
#
# DATA: alpr_camera_db.csv is DeFlock's own aggregated OpenStreetMap dataset
# (deflock.org), fetched by fetch_alpr_db.sh. The .sqlite this actually reads
# is built from that CSV and is a gitignored build artefact -- see
# fetch_alpr_db.sh's header, and README.md for how to build it on the device.
# ============================================================================

# ---------------------------------------------------------------------------
# Where we are running from
# ---------------------------------------------------------------------------
# The Pager copies a payload to /tmp/payload-<n>.sh before running it, so
# "$(dirname "$0")" points at /tmp, not at the payload's own directory. The
# working directory IS that directory when launched from the payload menu,
# which is why "." is tried first and is what actually resolves in practice.
SCRIPT_DIR=""
for _candidate in "." "/root/payloads/user/reconnaissance/ALPR-GPS-Detect" "$(dirname "$0" 2>/dev/null)"; do
    if [ -n "$_candidate" ] && [ -f "$_candidate/gps_alpr_proximity.awk" ]; then
        SCRIPT_DIR="$_candidate"
        break
    fi
done
if [ -z "$SCRIPT_DIR" ]; then
    LOG red "Cannot find gps_alpr_proximity.awk next to this payload -- aborting."
    exit 1
fi

SCRIPT_VERSION="unknown"
[ -f "$SCRIPT_DIR/VERSION" ] && SCRIPT_VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null)
[ -z "$SCRIPT_VERSION" ] && SCRIPT_VERSION="unknown"

LOOT_DIR="/root/loot/alpr_gps_detect"
mkdir -p "$LOOT_DIR"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="${LOOT_DIR}/alpr_gps_${TIMESTAMP}.txt"
TRACK_FILE="${LOOT_DIR}/track_${TIMESTAMP}.txt"
echo "ALPR-GPS-Detect v$SCRIPT_VERSION started at $(date)" > "$LOG_FILE"
echo "GPS track log started at $(date)" > "$TRACK_FILE"

# The indexed database this reads. A plain CSV scan is not fast enough to run
# every cycle at this dataset's size -- a full linear scan measured 3m42s over
# a 100k-row test set, against well under a second for the indexed query.
ALPR_DB_FILE="$SCRIPT_DIR/alpr_camera_db.sqlite"

# Alert radius. 0.0947mi is ~152m, about a city block: close enough that the
# camera is plausibly seeing you, far enough to be told before you are past it.
ALPR_RADIUS_MI=0.0947

# Bounding-box pre-filter margin in degrees, a coarse first pass only -- the
# precise haversine check in gps_alpr_proximity.awk is what actually enforces
# ALPR_RADIUS_MI. Generous on purpose: this only has to avoid excluding a
# camera that the precise check would have accepted.
ALPR_BBOX_MARGIN_DEG=0.15

# How often to take a fix and query. Faster than this mostly burns battery:
# at 30mph you cover ~130m in 3s, which is inside the alert radius anyway.
POLL_SECONDS=3

# STEALTH_MODE: 0 off, 1 no LED/sound but vibrate stays, 2 fully silent.
STEALTH_MODE=0

# Re-alert on a camera already seen this session. Off by default so driving
# a loop past the same camera does not buzz every lap; on for when you
# specifically want every pass marked.
ALWAYS_ALERT=0

# Log every GPS fix to TRACK_FILE, not just camera hits, so a session can be
# exported as a track afterwards. Off by default: it writes a line every
# POLL_SECONDS for the whole run.
TRACK_GPS=0

DETECTIONS=0
declare -A ALPR_GPS_SEEN
DETECTION_PID=""

cleanup() {
    [ -n "$DETECTION_PID" ] && kill "$DETECTION_PID" 2>/dev/null
}
# Same reasoning as the parent payload: a bare `trap cleanup EXIT` does not
# fire on SIGTERM/SIGINT in bash unless the handler exits itself, and the
# Pager stops a payload with SIGTERM.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# ---------------------------------------------------------------------------
# Device helpers -- same implementations as the parent payload
# ---------------------------------------------------------------------------
# GPS_GET returns "lat lon alt speed", or "0 0 0 0" when there is no fix.
# The timeout matters: without a fix it can sit there.
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

# A database match is ground truth, not a guess, so this is the hard alert:
# LED, ringtone and a dialog. STEALTH_MODE 1 and 2 both suppress it and fall
# back to the vibrate pulse below.
stealth_alert() {
    local title="$1" body="$2"
    if [ "$STEALTH_MODE" = "0" ]; then
        LED RED
        RINGTONE warning
        ALERT_RINGTONE "$title" "$body"
        LED OFF
    fi
}

# Vibrate is its own tier rather than folded into "everything off": unlike a
# blink or a ringtone, a pulse is not visible or audible to anyone else, so
# it stays available as a silent channel in STEALTH_MODE 1.
stealth_blink() {
    if [ "$STEALTH_MODE" != "2" ] && [ -f /sys/class/gpio/vibrator/value ]; then
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.15
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Screens -- styled after hak5's bt-bluepine
# ---------------------------------------------------------------------------
DASH_RULE_W=48
dash_rule() {
    local tail=" $1 ====" n eq
    n=$(( DASH_RULE_W - ${#tail} ))
    [ "$n" -lt 4 ] && n=4
    eq=$(printf "%${n}s" "" | tr ' ' '=')
    echo "$eq$tail"
}

STATE_FILE="/tmp/alpr_gps_state"

# Written by the detection loop, read by the menu. They are separate
# processes -- the loop is backgrounded so the menu can own the screen --
# so a file is the only way the menu sees live numbers.
write_state() {
    {
        echo "fixes=$FIX_COUNT"
        echo "hits=$DETECTIONS"
        echo "lastfix=$LAST_FIX"
        echo "lastfixtime=$LAST_FIX_TIME"
        echo "lasthit=$LAST_HIT"
    } > "$STATE_FILE.tmp" 2>/dev/null
    mv -f "$STATE_FILE.tmp" "$STATE_FILE" 2>/dev/null
}

read_state() {
    FIX_COUNT=0; DETECTIONS=0; LAST_FIX=""; LAST_FIX_TIME=""; LAST_HIT=""
    [ -s "$STATE_FILE" ] || return
    local k v
    while IFS='=' read -r k v; do
        case "$k" in
            fixes)       FIX_COUNT="$v" ;;
            hits)        DETECTIONS="$v" ;;
            lastfix)     LAST_FIX="$v" ;;
            lastfixtime) LAST_FIX_TIME="$v" ;;
            lasthit)     LAST_HIT="$v" ;;
        esac
    done < "$STATE_FILE"
}

screen_status() {
    read_state
    local up_s up_h up_m
    up_s=$(( $(date +%s) - SESSION_START ))
    up_h=$(printf '%02d' $(( up_s / 3600 )))
    up_m=$(printf '%02d' $(( (up_s % 3600) / 60 )))

    LOG magenta "$(dash_rule 'ALPR GPS Status')"
    LOG cyan "Uptime: $up_h:$up_m | Fixes: $FIX_COUNT | Radius: ${ALPR_RADIUS_MI}mi"
    if [ -n "$LAST_FIX" ]; then
        LOG "Position: $LAST_FIX"
        LOG "Fix at: $LAST_FIX_TIME"
    else
        LOG red "No GPS fix yet"
    fi
    if [ "$DETECTIONS" = "0" ]; then
        LOG green "Cameras in range: 0"
    else
        LOG red "Cameras in range: $DETECTIONS"
        [ -n "$LAST_HIT" ] && LOG "Last: $LAST_HIT"
    fi
    LOG magenta "$(dash_rule 'End')"
}

screen_cameras() {
    local n=0 line
    LOG magenta "$(dash_rule 'Cameras Found')"
    while IFS= read -r line; do
        case "$line" in ""|*"started at"*) continue ;; esac
        LOG "${line:0:48}"
        n=$((n + 1))
        [ "$n" -ge 8 ] && break
    done < <(tail -n 8 "$LOG_FILE")
    [ "$n" = "0" ] && LOG green "None yet this session"
    LOG magenta "$(dash_rule 'Cameras Found')"
}

screen_database() {
    LOG magenta "$(dash_rule 'Database')"
    if [ ! -f "$ALPR_DB_FILE" ]; then
        LOG red "NOT BUILT: $(basename "$ALPR_DB_FILE")"
        LOG "Build it from the CSV -- see README.md"
    elif ! command -v sqlite3 >/dev/null 2>&1; then
        LOG red "sqlite3 not found -- cannot query"
    else
        LOG green "Ready: $(basename "$ALPR_DB_FILE")"
        LOG cyan "Cameras: $(sqlite3 "$ALPR_DB_FILE" 'SELECT COUNT(*) FROM cameras;' 2>/dev/null)"
        LOG "Size: $(( $(wc -c < "$ALPR_DB_FILE" 2>/dev/null) / 1024 )) KB"
    fi
    LOG magenta "$(dash_rule 'Database')"
}

screen_session() {
    LOG magenta "$(dash_rule 'Session')"
    LOG cyan "Loot: $LOOT_DIR"
    LOG "Hits: $(basename "$LOG_FILE")"
    [ "$TRACK_GPS" = "1" ] && LOG "Track: $(basename "$TRACK_FILE")"
    LOG "Version: v$SCRIPT_VERSION"
    LOG magenta "$(dash_rule 'End')"
}

# ---------------------------------------------------------------------------
# Startup checks
# ---------------------------------------------------------------------------
LOG " "
LOG cyan "== ALPR-GPS-DETECT == v$SCRIPT_VERSION"
LOG "Known ALPR cameras by position. No radio used."
LOG " "

if ! command -v GPS_GET >/dev/null 2>&1; then
    LOG red "GPS_GET not found -- this payload cannot work without it."
    exit 1
fi
if ! command -v sqlite3 >/dev/null 2>&1; then
    LOG red "sqlite3 not found -- cannot query the camera database."
    exit 1
fi
if [ ! -f "$ALPR_DB_FILE" ]; then
    LOG red "Database not built: $(basename "$ALPR_DB_FILE")"
    LOG yellow "Build it from alpr_camera_db.csv -- see README.md"
    exit 1
fi
LOG green "Database: $(sqlite3 "$ALPR_DB_FILE" 'SELECT COUNT(*) FROM cameras;' 2>/dev/null) cameras"
LOG green "Radius: ${ALPR_RADIUS_MI}mi | Poll: every ${POLL_SECONDS}s"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
stealth_menu_item() {
    case "$STEALTH_MODE" in
        0) echo "[ ] Stealth Mode (off)" ;;
        1) echo "[X] Stealth Mode (no LED/sound, vibrate stays)" ;;
        2) echo "[X] Stealth Mode (fully silent)" ;;
    esac
}
toggle_item() {
    if [ "$1" = "1" ]; then echo "[X] $2"; else echo "[ ] $2"; fi
}

if command -v LIST_PICKER >/dev/null 2>&1; then
    while true; do
        _resp=$(LIST_PICKER "Options (select to toggle)" \
            "$(stealth_menu_item)" \
            "$(toggle_item "$ALWAYS_ALERT" 'Always Alert (re-alert on every pass)')" \
            "$(toggle_item "$TRACK_GPS" 'Log GPS track (every fix, not just hits)')" \
            "Start scanning" \
            "Start scanning")
        case "$_resp" in
            *"Stealth Mode"*)  STEALTH_MODE=$(( (STEALTH_MODE + 1) % 3 )) ;;
            *"Always Alert"*)  ALWAYS_ALERT=$((1 - ALWAYS_ALERT)) ;;
            *"Log GPS track"*) TRACK_GPS=$((1 - TRACK_GPS)) ;;
            "Start scanning")  break ;;
            *)                 break ;;
        esac
    done
fi

SESSION_START=$(date +%s)
FIX_COUNT=0
LAST_FIX=""
LAST_FIX_TIME=""
LAST_HIT=""

# ---------------------------------------------------------------------------
# Detection loop -- backgrounded, silent
# ---------------------------------------------------------------------------
# Prints nothing at all. Hits go to LOG_FILE, alerts go to the LED/ringtone
# and vibrator, and the numbers the menu shows go to STATE_FILE. That silence
# is what lets a menu screen stay put once drawn.
detection_loop() {
    local GPS_FIX GPS_TAG lat lon id clat2 clon2 dist
    local box_lat1 box_lat2 box_lon1 box_lon2 CURRENT_TIME ENTRY
    while true; do
        GPS_FIX=$(get_gps_fix)
        if [ -n "$GPS_FIX" ]; then
            FIX_COUNT=$((FIX_COUNT + 1))
            LAST_FIX="$GPS_FIX"
            LAST_FIX_TIME=$(date '+%H:%M:%S')
            [ "$TRACK_GPS" = "1" ] && echo "$LAST_FIX_TIME | $GPS_FIX" >> "$TRACK_FILE"

            GPS_TAG=" | gps=$GPS_FIX"
            lat="${GPS_FIX%%,*}"
            lon="${GPS_FIX##*,}"

            read -r box_lat1 box_lat2 box_lon1 box_lon2 < <(awk \
                -v clat="$lat" -v clon="$lon" -v m="$ALPR_BBOX_MARGIN_DEG" \
                'BEGIN { print clat-m, clat+m, clon-m, clon+m }')

            # Stage 1 (sqlite3): indexed bounding-box pre-filter, which is
            # the whole reason this is a database and not a CSV. Stage 2
            # (awk, fed by stdin): precise haversine on just that candidate
            # set, which is what actually enforces the radius.
            while IFS=',' read -r id clat2 clon2 dist; do
                [ -z "$id" ] && continue
                if [ "$ALWAYS_ALERT" != "1" ] && [ -n "${ALPR_GPS_SEEN[$id]:-}" ]; then continue; fi
                CURRENT_TIME=$(date '+%H:%M:%S')
                ENTRY="DECT: $CURRENT_TIME | osm:$id | Known ALPR Camera (GPS, ${dist}mi away)$GPS_TAG"
                echo "$ENTRY" >> "$LOG_FILE"
                DETECTIONS=$((DETECTIONS + 1))
                LAST_HIT="$CURRENT_TIME osm:$id ${dist}mi"
                ALPR_GPS_SEEN[$id]=1
                stealth_alert "KNOWN ALPR CAMERA" "osm node $id\n${dist} miles away"
                stealth_blink
            done < <(sqlite3 -csv "$ALPR_DB_FILE" \
                "SELECT id,lat,lon FROM cameras WHERE lat BETWEEN $box_lat1 AND $box_lat2 AND lon BETWEEN $box_lon1 AND $box_lon2;" 2>/dev/null \
                | awk -v clat="$lat" -v clon="$lon" -v radius_mi="$ALPR_RADIUS_MI" -f "$SCRIPT_DIR/gps_alpr_proximity.awk")
        fi
        write_state
        sleep "$POLL_SECONDS"
    done
}

write_state
detection_loop &
DETECTION_PID=$!

# ---------------------------------------------------------------------------
# Menu -- the foreground, and the only thing that draws
# ---------------------------------------------------------------------------
if ! command -v LIST_PICKER >/dev/null 2>&1; then
    LOG red "LIST_PICKER unavailable -- scanning, no menu."
    wait "$DETECTION_PID"
    exit 0
fi

LOG " "
LOG green "Scanning in the background. Use the menu."

while true; do
    _sel=$(LIST_PICKER "ALPR-GPS-Detect v$SCRIPT_VERSION" \
        "1: Status" \
        "2: Cameras Found" \
        "3: Database" \
        "4: Session Files" \
        "0: Stop Scanning" \
        "1: Status")
    case "$_sel" in
        "1: Status")         screen_status ;;
        "2: Cameras Found")  screen_cameras ;;
        "3: Database")       screen_database ;;
        "4: Session Files")  screen_session ;;
        "0: Stop Scanning")  break ;;
        *)                   break ;;
    esac
done

LOG magenta "$(dash_rule 'Stopping')"
kill "$DETECTION_PID" 2>/dev/null
wait "$DETECTION_PID" 2>/dev/null
read_state
LOG green "Stopped. $DETECTIONS camera(s) found, $FIX_COUNT fix(es)."
LOG "Loot in $LOOT_DIR"
exit 0
