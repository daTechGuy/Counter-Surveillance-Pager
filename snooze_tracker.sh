#!/bin/bash
# snooze_tracker.sh -- temporarily ignore a specific rogue-tracker MAC for a
# selectable duration, without editing tracker_allowlist.conf (which is
# meant to be permanent -- "this is my own tag"). Use this instead when you
# know a tracker is nearby for an innocuous reason right now (a neighbor's
# AirTag through a wall, a coworker's Tile in the next office) and don't
# want alerts on it for the next few hours, but DO still want to hear about
# it again after that if it's still around days later.
#
# The live payload.sh session re-reads the snooze file once per main-loop
# tick (same cadence as its GPS refresh, see load_tracker_snooze()) -- no
# restart needed for a snooze added while it's already running. Run this
# directly from the Pager's own terminal payload (or over SSH) while
# Counter-Surveillance-Pager is running.
#
# SAME MAC-ROTATION CAVEAT AS tracker_allowlist.conf: Apple/Samsung/Google's
# rotating protocols (everything except Tile) can rotate to a new MAC
# during your snooze window, in which case the new MAC isn't snoozed and
# you'll get an alert anyway -- see that file's header for why there's no
# way around this at this layer. A multi-hour snooze isn't a guarantee, but
# is a reasonable bet in practice -- this project's own field testing has
# observed a real AirTag hold the identical MAC for 2+ hours straight.
#
# Storage: WORK_DIR (session-scoped /tmp), not SCRIPT_DIR -- a snooze is a
# reactive, temporary decision, not a saved config file. If the payload
# session restarts, WORK_DIR is not guaranteed to survive (depends on the
# device's own /tmp handling across a full payload stop/start) -- if your
# snooze seems to have reset after a restart, just re-run this.
#
# Usage:
#   ./snooze_tracker.sh add <MAC> <duration>
#       e.g. ./snooze_tracker.sh add CB:C7:07:6C:14:B4 4h
#       duration: <N>m minutes, <N>h hours, <N>d days, or a bare number of
#       seconds
#   ./snooze_tracker.sh list
#   ./snooze_tracker.sh remove <MAC>

set -u
WORK_DIR="/tmp/counter_surveillance_pager"
SNOOZE_FILE="$WORK_DIR/tracker_snooze.txt"
mkdir -p "$WORK_DIR"
touch "$SNOOZE_FILE"

usage() {
    echo "Usage:" >&2
    echo "  $0 add <MAC> <duration>   e.g. $0 add CB:C7:07:6C:14:B4 4h" >&2
    echo "      duration: <N>m minutes, <N>h hours, <N>d days, or bare seconds" >&2
    echo "  $0 list" >&2
    echo "  $0 remove <MAC>" >&2
    exit 1
}

# Prints a positive integer of seconds on success, prints nothing and
# returns 1 on anything unparseable (caller checks both).
parse_duration() {
    local d="$1" num unit
    case "$d" in
        *m) num="${d%m}"; unit=60 ;;
        *h) num="${d%h}"; unit=3600 ;;
        *d) num="${d%d}"; unit=86400 ;;
        *)  num="$d"; unit=1 ;;
    esac
    case "$num" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$num" -le 0 ] && return 1
    echo $((num * unit))
}

is_mac() {
    case "$1" in
        [0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F])
            return 0 ;;
        *) return 1 ;;
    esac
}

cmd="${1:-}"
case "$cmd" in
    add)
        mac="${2:-}"
        dur="${3:-}"
        [ -z "$mac" ] && usage
        [ -z "$dur" ] && usage
        if ! is_mac "$mac"; then
            echo "Not a MAC address (expected XX:XX:XX:XX:XX:XX): $mac" >&2
            exit 1
        fi
        secs=$(parse_duration "$dur")
        if [ -z "$secs" ]; then
            echo "Not a valid duration: $dur" >&2
            usage
        fi
        mac_lc="$(echo "$mac" | tr 'A-Z' 'a-z')"
        now=$(date +%s)
        expiry=$((now + secs))
        # Replace any existing entry for this MAC rather than stacking dupes.
        grep -v "^${mac_lc}|" "$SNOOZE_FILE" > "$SNOOZE_FILE.tmp" 2>/dev/null || true
        mv "$SNOOZE_FILE.tmp" "$SNOOZE_FILE"
        echo "${mac_lc}|${expiry}|added $(date '+%Y-%m-%d %H:%M:%S'), snoozed for ${dur}" >> "$SNOOZE_FILE"
        echo "Snoozing $mac_lc for ${dur} (~$((secs / 60)) minutes from now)."
        echo "Takes effect within the live session's next tick -- no restart needed."
        ;;
    list)
        now=$(date +%s)
        found=0
        while IFS='|' read -r mac_lc expiry note; do
            [ -z "$mac_lc" ] && continue
            found=1
            remaining=$((expiry - now))
            if [ "$remaining" -gt 0 ]; then
                echo "$mac_lc  active, ${remaining}s (~$((remaining / 60))m) remaining  -- $note"
            else
                echo "$mac_lc  EXPIRED $((-remaining))s ago  -- $note"
            fi
        done < "$SNOOZE_FILE"
        [ "$found" = "0" ] && echo "No snoozed trackers."
        ;;
    remove)
        mac="${2:-}"
        [ -z "$mac" ] && usage
        mac_lc="$(echo "$mac" | tr 'A-Z' 'a-z')"
        grep -v "^${mac_lc}|" "$SNOOZE_FILE" > "$SNOOZE_FILE.tmp" 2>/dev/null || true
        mv "$SNOOZE_FILE.tmp" "$SNOOZE_FILE"
        echo "Removed any snooze for $mac_lc"
        ;;
    *)
        usage
        ;;
esac
