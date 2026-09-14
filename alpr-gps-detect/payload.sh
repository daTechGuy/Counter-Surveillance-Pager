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
stealth_alert() {
    if [ "$STEALTH_MODE" = "0" ]; then
        LED RED
        RINGTONE warning
        LED OFF
    fi
    # Felt, not seen, and kept in STEALTH_MODE 1: a pulse is not visible or
    # audible to anyone else, unlike the LED and the ringtone.
    if [ "$STEALTH_MODE" != "2" ] && [ -f /sys/class/gpio/vibrator/value ]; then
        echo 1 > /sys/class/gpio/vibrator/value 2>/dev/null
        sleep 0.25
        echo 0 > /sys/class/gpio/vibrator/value 2>/dev/null
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
# GPS health
# ---------------------------------------------------------------------------
# This payload's ONLY input is position, so "no fix" and "GPS is broken" have
# to look different. Silence means the same thing in both cases -- no cameras
# reported -- and without this you cannot tell a clear drive past nothing from
# a receiver that was never plugged in.
#
# Three things have to line up, and each fails differently:
#
#   gpsd running      -- GPS_GET returns "0 0 0 0" when it is not, which is
#                        indistinguishable from a cold receiver with no lock.
#   device path valid -- gpsd.core.device is a /dev/serial/by-path entry, and
#                        that path encodes the USB PORT. Moving the receiver
#                        to a different port, or adding a hub, changes it and
#                        gpsd then cannot open it. Seen on this device: the
#                        config said 1.1_1-1.1:1.0 while the hardware was on
#                        1.3_1-1.3:1.x.
#   a fix             -- a cold first fix can take 15-30 minutes with clear
#                        sky, per Hak5's own GPS documentation, and indoors
#                        it will never arrive.
#
# Setting any of it is deliberately NOT this payload's job: GPS is device
# configuration, done in Settings > GPS in the Pager UI (path, baud, then
# "Restart GPSd"). Reporting it accurately IS this payload's job.
gpsd_running() {
    # NOT `pgrep -x gpsd`. That was the first attempt and it is wrong on this
    # device: pgrep here is BusyBox, whose -x matches the whole command line
    # rather than the process name, so it returned no match while gpsd was
    # demonstrably running and serving. Verified live -- ps showed
    # "/usr/sbin/gpsd -N -n -S 2947 ...", `pgrep -x gpsd` said NO MATCH,
    # `pgrep -f /usr/sbin/gpsd` said MATCH, and port 2947 was listening.
    #
    # Matching the full path keeps the precision -x was reached for (a shell
    # whose arguments merely contain "gpsd" will not match) without relying
    # on GNU pgrep semantics this platform does not have.
    pgrep -f "/usr/sbin/gpsd" >/dev/null 2>&1
}

gps_device_path() { uci get gpsd.core.device 2>/dev/null; }
gps_device_speed() { uci get gpsd.core.speed 2>/dev/null; }

# Find the receiver by listening for it, rather than trusting configuration.
#
# Only safe to call when gpsd is NOT running: gpsd holds the port open, and
# reading it underneath the daemon would fight it for bytes.
#
# A GPS receiver streams NMEA continuously whether or not it has a lock, so
# "does this port emit sentences starting with $GP/$GN/$GL/$GA" is a
# definitive test -- unlike matching USB vendor IDs, which would need a list
# of every adapter anyone might use. The OEM module attached here is a
# Quectel LC86LIC behind a CH340 (1a86:7523) appearing as /dev/ttyUSB0, but
# nothing below depends on that.
#
# 9600 first because it is both this module's rate and the platform default;
# the others are the rates Hak5's own GPS documentation lists.
gps_detect_port() {
    local d baud
    for d in /dev/ttyUSB0 /dev/ttyUSB1 /dev/ttyACM0 /dev/ttyACM1; do
        [ -e "$d" ] || continue
        for baud in 9600 4800 38400 115200; do
            stty -F "$d" "$baud" raw -echo 2>/dev/null || continue
            if timeout 3 head -c 300 "$d" 2>/dev/null | grep -qE '\$G[PNLA][A-Z]{3},'; then
                echo "$d"
                return 0
            fi
        done
    done
    return 1
}

# Start gpsd if it is not already up, and say plainly what happened.
#
# This payload used to refuse to touch any of it, on the grounds that GPS is
# device configuration. That was the wrong line to draw: starting a daemon
# that is meant to be running is not reconfiguring anything, and leaving it
# stopped meant the payload reported a fault the user then had to go and fix
# by hand for no reason.
#
# Where it still will not act alone is the device PATH. gpsd.core.device is a
# /dev/serial/by-path entry encoding the USB port, so it goes stale whenever
# the receiver moves ports or a hub is added -- which is exactly what was
# wrong on this device for days. Rewriting it silently would be changing
# system configuration behind the user's back, so it asks first, on screen.
# This runs during startup, before the detection loop is backgrounded, so a
# modal here is safe (see stealth_alert for why it would not be later).
ensure_gpsd() {
    local dev detected
    if gpsd_running; then
        LOG green "GPS: gpsd already running"
        return 0
    fi

    dev=$(gps_device_path)
    if [ -n "$dev" ] && [ -e "$dev" ]; then
        LOG yellow "GPS: gpsd not running -- starting it"
        /etc/init.d/gpsd start >/dev/null 2>&1
        sleep 4
        if gpsd_running; then
            LOG green "GPS: gpsd started on $(basename "$dev")"
            return 0
        fi
        LOG red "GPS: gpsd would not start on the configured port"
    else
        LOG yellow "GPS: configured port is missing ($(basename "${dev:-none}"))"
    fi

    LOG yellow "GPS: listening for the receiver on each serial port..."
    detected=$(gps_detect_port)
    if [ -z "$detected" ]; then
        LOG red "GPS: no NMEA on any serial port."
        LOG yellow "Receiver not plugged in, or not powered."
        return 1
    fi

    LOG green "GPS: receiver found on $(basename "$detected")"

    # Prefer the by-path name over the raw /dev/ttyUSB0: the raw name is
    # assigned in enumeration order and can move between boots, while the
    # by-path name is stable for as long as the receiver stays in that port.
    local bypath="" link
    for link in /dev/serial/by-path/*; do
        [ -e "$link" ] || continue
        if [ "$(readlink -f "$link")" = "$(readlink -f "$detected")" ]; then
            bypath="$link"
            break
        fi
    done
    [ -z "$bypath" ] && bypath="$detected"

    if command -v CONFIRMATION_DIALOG >/dev/null 2>&1; then
        local ans
        ans=$(CONFIRMATION_DIALOG "GPS found on $(basename "$bypath") but config points elsewhere. Update it?" 2>/dev/null)
        case "$ans" in
            [Yy]*|"true"|"1"|"OK"|"Yes")
                uci set gpsd.core.device="$bypath" 2>/dev/null
                uci commit gpsd 2>/dev/null
                LOG green "GPS: config updated to $(basename "$bypath")"
                /etc/init.d/gpsd restart >/dev/null 2>&1
                sleep 4
                gpsd_running && { LOG green "GPS: gpsd running"; return 0; }
                LOG red "GPS: gpsd still would not start"
                return 1
                ;;
        esac
    fi

    LOG yellow "Left unchanged. To fix it yourself:"
    LOG yellow "  Settings > GPS > device: $(basename "$bypath")"
    LOG yellow "  then Restart GPSd"
    return 1
}

# "" when everything checks out, otherwise a short reason.
gps_fault() {
    local d
    gpsd_running || { echo "gpsd not running"; return; }
    d=$(gps_device_path)
    [ -z "$d" ] && { echo "no device configured"; return; }
    [ -e "$d" ] || { echo "device path missing"; return; }
    echo ""
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
        echo "lastfixepoch=$LAST_FIX_EPOCH"
        echo "lasthit=$LAST_HIT"
    } > "$STATE_FILE.tmp" 2>/dev/null
    mv -f "$STATE_FILE.tmp" "$STATE_FILE" 2>/dev/null
}

read_state() {
    FIX_COUNT=0; DETECTIONS=0; LAST_FIX=""; LAST_FIX_TIME=""; LAST_HIT=""
    LAST_FIX_EPOCH=0
    [ -s "$STATE_FILE" ] || return
    local k v
    while IFS='=' read -r k v; do
        case "$k" in
            fixes)       FIX_COUNT="$v" ;;
            hits)        DETECTIONS="$v" ;;
            lastfix)     LAST_FIX="$v" ;;
            lastfixtime) LAST_FIX_TIME="$v" ;;
            lastfixepoch) LAST_FIX_EPOCH="$v" ;;
            lasthit)     LAST_HIT="$v" ;;
        esac
    done < "$STATE_FILE"
}

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

screen_status() {
    read_state
    local up_s up_h up_m
    up_s=$(( $(date +%s) - SESSION_START ))
    up_h=$(printf '%02d' $(( up_s / 3600 )))
    up_m=$(printf '%02d' $(( (up_s % 3600) / 60 )))

    LOG magenta "$(dash_rule 'ALPR GPS Status')"
    LOG cyan "Uptime: $up_h:$up_m | Fixes: $FIX_COUNT | Radius: ${ALPR_RADIUS_MI}mi"
    # Fix AGE, not just the timestamp. A position from 20 minutes ago looks
    # identical to a current one on screen, and for a detector that only
    # matters while you are moving, a stale fix is the same as no fix.
    local age fault
    if [ -n "$LAST_FIX" ]; then
        age=$(( $(date +%s) - LAST_FIX_EPOCH ))
        LOG "Position: $LAST_FIX"
        if [ "$age" -le 10 ]; then
            LOG green "Fix: ${age}s ago ($LAST_FIX_TIME)"
        elif [ "$age" -lt 120 ]; then
            LOG yellow "Fix: ${age}s ago ($LAST_FIX_TIME) -- stale"
        else
            LOG red "Fix: $((age / 60))m ago ($LAST_FIX_TIME) -- LOST"
        fi
    else
        LOG red "No GPS fix yet"
    fi
    fault=$(gps_fault)
    [ -n "$fault" ] && LOG red "GPS: $fault -- see GPS Health"
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

screen_gps() {
    local fault d
    LOG magenta "$(dash_rule 'GPS Health')"
    if gpsd_running; then LOG green "gpsd: running"; else LOG red "gpsd: NOT RUNNING"; fi
    d=$(gps_device_path)
    if [ -z "$d" ]; then
        LOG red "Device: not configured"
    elif [ -e "$d" ]; then
        LOG green "Device: OK ($(basename "$d"))"
    else
        LOG red "Device: MISSING ($(basename "$d"))"
    fi
    LOG cyan "Baud: $(gps_device_speed)"
    read_state
    if [ -n "$LAST_FIX" ]; then
        LOG green "Last fix: $LAST_FIX_TIME"
    else
        LOG yellow "No fix yet (cold start can take 15-30m)"
    fi
    fault=$(gps_fault)
    if [ -n "$fault" ]; then
        LOG red "Fix in Settings > GPS, then Restart GPSd"
    fi
    LOG magenta "$(dash_rule 'End')"
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

# Try to bring GPS up rather than merely complaining about it. Still not
# fatal either way: the receiver can be plugged in mid-session and the loop
# picks up a fix the moment one exists.
ensure_gpsd
_gps_fault=$(gps_fault)
if [ -n "$_gps_fault" ]; then
    LOG red "GPS PROBLEM: $_gps_fault"
    LOG yellow "Nothing will be detected until this is fixed."
else
    LOG green "GPS: gpsd running, device present"
    if [ "$(timeout 3 GPS_GET 2>/dev/null)" = "0 0 0 0" ]; then
        LOG yellow "No fix yet -- a cold start can take 15-30m with clear sky."
    else
        LOG green "GPS: fix available"
    fi
fi

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
LAST_FIX_EPOCH=0
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
            LAST_FIX_EPOCH=$(date +%s)
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
        "3: GPS Health" \
        "4: Database" \
        "5: Session Files" \
        "0: Stop Scanning" \
        "1: Status")
    case "$_sel" in
        "1: Status")         screen_status;   pause_screen ;;
        "2: Cameras Found")  screen_cameras;  pause_screen ;;
        "3: GPS Health")     screen_gps;      pause_screen ;;
        "4: Database")       screen_database; pause_screen ;;
        "5: Session Files")  screen_session;  pause_screen ;;
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
