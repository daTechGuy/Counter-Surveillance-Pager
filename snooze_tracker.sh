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
# THREE DURATION MODES:
#   <N>m / <N>h / <N>d / bare seconds  -- time-bounded, expires on its own.
#   reboot                              -- ignored until the device actually
#     reboots. Survives a mere payload restart (the snooze file lives on
#     /tmp, which is tmpfs -- confirmed live on this device -- so it only
#     clears on a real power cycle, not on stopping/restarting the payload
#     script). Takes effect immediately, same as a timed snooze.
#   forever                             -- permanent: writes a mac: entry
#     to tracker_allowlist.conf (survives reboots, since that file lives
#     alongside the payload's own scripts, not on tmpfs) AND ALSO adds an
#     immediate same-session snooze, so you're not left waiting for a
#     restart to see the effect -- the permanent allowlist entry is what
#     takes over on your next restart onward.
#
# SAME MAC-ROTATION CAVEAT AS tracker_allowlist.conf: Apple/Samsung/Google's
# rotating protocols (everything except Tile) can rotate to a new MAC
# during your snooze window, in which case the new MAC isn't snoozed and
# you'll get an alert anyway -- see that file's header for why there's no
# way around this at this layer. A multi-hour snooze isn't a guarantee, but
# is a reasonable bet in practice -- this project's own field testing has
# observed a real AirTag hold the identical MAC for 2+ hours straight.
#
# Usage:
#   ./snooze_tracker.sh add <MAC> <duration>
#       e.g. ./snooze_tracker.sh add CB:C7:07:6C:14:B4 4h
#       e.g. ./snooze_tracker.sh add CB:C7:07:6C:14:B4 reboot
#       e.g. ./snooze_tracker.sh add CB:C7:07:6C:14:B4 forever
#   ./snooze_tracker.sh list
#   ./snooze_tracker.sh remove <MAC>

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="/tmp/counter_surveillance_pager"
SNOOZE_FILE="$WORK_DIR/tracker_snooze.txt"
ALLOWLIST_FILE="$SCRIPT_DIR/tracker_allowlist.conf"
# Not a real future date -- just "far enough" that $now < $expiry stays
# true for as long as the entry exists, so payload.sh's existing
# handle_tracker_line() check needs no special-casing for "not time-
# bound" vs "really will expire". The entry disappearing (tmpfs cleared
# by a reboot) is what actually ends a "reboot" snooze, not this number.
FAR_FUTURE_EPOCH=9999999999
mkdir -p "$WORK_DIR"
touch "$SNOOZE_FILE"

usage() {
    echo "Usage:" >&2
    echo "  $0 add <MAC> <duration>" >&2
    echo "      duration: <N>m minutes, <N>h hours, <N>d days, bare seconds," >&2
    echo "                'reboot' (until the device reboots), or 'forever'" >&2
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

# Replaces any existing snooze entry for $1 (mac_lc) with a fresh one --
# expiry ($2) and a free-text note ($3) for `list` to display.
write_snooze_entry() {
    local mac_lc="$1" expiry="$2" note="$3"
    grep -v "^${mac_lc}|" "$SNOOZE_FILE" > "$SNOOZE_FILE.tmp" 2>/dev/null || true
    mv "$SNOOZE_FILE.tmp" "$SNOOZE_FILE"
    echo "${mac_lc}|${expiry}|${note}" >> "$SNOOZE_FILE"
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
        mac_lc="$(echo "$mac" | tr 'A-Z' 'a-z')"
        now=$(date +%s)

        case "$dur" in
            forever)
                if [ ! -f "$ALLOWLIST_FILE" ]; then
                    echo "tracker_allowlist.conf not found at $ALLOWLIST_FILE -- can't add permanently" >&2
                    exit 1
                fi
                if grep -qi "^mac:${mac_lc}" "$ALLOWLIST_FILE" 2>/dev/null; then
                    echo "$mac_lc is already in tracker_allowlist.conf -- nothing to add there."
                else
                    echo "mac:${mac_lc}   # added by snooze_tracker.sh $(date '+%Y-%m-%d %H:%M:%S')" >> "$ALLOWLIST_FILE"
                    echo "Added $mac_lc to tracker_allowlist.conf (permanent, survives reboots)."
                fi
                write_snooze_entry "$mac_lc" "$FAR_FUTURE_EPOCH" "forever, added $(date '+%Y-%m-%d %H:%M:%S') -- see tracker_allowlist.conf"
                echo "Also snoozed for the current session immediately (no restart needed)."
                echo "The permanent allowlist entry takes over on its own from your next restart on."
                ;;
            reboot|untilreboot)
                write_snooze_entry "$mac_lc" "$FAR_FUTURE_EPOCH" "added $(date '+%Y-%m-%d %H:%M:%S'), snoozed until reboot"
                echo "Snoozing $mac_lc until the device actually reboots."
                echo "Survives a payload restart (stored on tmpfs /tmp, only a real reboot clears it)."
                echo "Takes effect within the live session's next tick -- no restart needed."
                ;;
            *)
                secs=$(parse_duration "$dur")
                if [ -z "$secs" ]; then
                    echo "Not a valid duration: $dur" >&2
                    usage
                fi
                expiry=$((now + secs))
                write_snooze_entry "$mac_lc" "$expiry" "added $(date '+%Y-%m-%d %H:%M:%S'), snoozed for ${dur}"
                echo "Snoozing $mac_lc for ${dur} (~$((secs / 60)) minutes from now)."
                echo "Takes effect within the live session's next tick -- no restart needed."
                ;;
        esac
        ;;
    list)
        now=$(date +%s)
        found=0
        while IFS='|' read -r mac_lc expiry note; do
            [ -z "$mac_lc" ] && continue
            found=1
            remaining=$((expiry - now))
            if [ "$remaining" -gt 315360000 ]; then   # >10 years -- reboot/forever, not really time-bound
                echo "$mac_lc  active until reboot (or permanently, if 'forever')  -- $note"
            elif [ "$remaining" -gt 0 ]; then
                echo "$mac_lc  active, ${remaining}s (~$((remaining / 60))m) remaining  -- $note"
            else
                echo "$mac_lc  EXPIRED $((-remaining))s ago  -- $note"
            fi
        done < "$SNOOZE_FILE"
        [ "$found" = "0" ] && echo "No snoozed trackers."
        if [ -f "$ALLOWLIST_FILE" ]; then
            echo ""
            echo "Permanent entries in tracker_allowlist.conf:"
            grep -i '^mac:' "$ALLOWLIST_FILE" 2>/dev/null || echo "  (none)"
        fi
        ;;
    remove)
        mac="${2:-}"
        [ -z "$mac" ] && usage
        mac_lc="$(echo "$mac" | tr 'A-Z' 'a-z')"
        grep -v "^${mac_lc}|" "$SNOOZE_FILE" > "$SNOOZE_FILE.tmp" 2>/dev/null || true
        mv "$SNOOZE_FILE.tmp" "$SNOOZE_FILE"
        echo "Removed any timed/reboot snooze for $mac_lc."
        if [ -f "$ALLOWLIST_FILE" ] && grep -qi "^mac:${mac_lc}" "$ALLOWLIST_FILE" 2>/dev/null; then
            echo "NOTE: $mac_lc is also in tracker_allowlist.conf (permanent) -- this command"
            echo "      doesn't touch that file. Edit it directly if you want to remove it there too."
        fi
        ;;
    *)
        usage
        ;;
esac
