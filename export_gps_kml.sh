#!/bin/bash
# export_gps_kml.sh -- wrapper around export_gps_kml.awk: picks a session
# (most recent by default, or one you name) and hands its four loot files
# (whichever exist) to the awk exporter, writing the result back into
# $LOOT_DIR as a KML you can pull off the device (USB Mount Loot Transfer,
# scp, etc.) and open in Google Earth/Google My Maps.
#
# Usage:
#   ./export_gps_kml.sh                  # most recent session
#   ./export_gps_kml.sh 20260818_125137  # a specific session timestamp
#     (the "TIMESTAMP" suffix on that session's own surveillance_*.txt /
#     rogue_trackers_*.txt / deauth_eviltwin_*.txt / drone_rid_*.txt)
#
# Not run automatically by payload.sh -- GPS tagging only fires once GPS
# hardware/mobile2gps is actually attached (see payload.sh's GPS_GET
# comment), so this is a manual "I just got back, show me the map" step,
# not something that needs to run during a live session.
#
# ARCHIVE-AWARE: this Pager's own web UI has an "Archive Loot" feature
# (moves /root/loot's current contents into /root/loot/archive/archive-
# <timestamp>/) that does NOT stop a running payload or its file handles --
# confirmed live: using it mid-session splits that session's log files,
# since bash re-opens each loot file by path on every `>>` append. Old
# content ends up frozen in the archive; new hits from that point on
# accumulate in a fresh file back at the live path, same filename. See
# resolve_loot_file() below for how both halves get found and stitched
# back together transparently.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOOT_DIR="/root/loot/counter_surveillance_pager"
ARCHIVE_GLOB="/root/loot/archive/archive-*/counter_surveillance_pager"
SCRATCH_DIR="/tmp/counter_surveillance_pager"

# Finds one loot file (e.g. "surveillance_20260818_173841.txt") wherever it
# actually is -- live LOOT_DIR, an archived copy, or (if a mid-session
# archive split it) both -- and prints the path to use. When both a live
# and an archived copy exist for the same filename, concatenates archive-
# then-live (chronological order) into a scratch file so neither half is
# silently dropped. Prints nothing if the file isn't found anywhere.
resolve_loot_file() {
    # Split across separate `local` statements deliberately: `local
    # fname="$1" live="$LOOT_DIR/$fname"` on one line tripped `set -u`'s
    # unbound-variable check on THIS device's bash -- $fname isn't
    # reliably available yet for a later assignment on the same `local`
    # line as its own declaration. Confirmed live, not theoretical.
    local fname="$1"
    local live="$LOOT_DIR/$fname"
    local archived="" d candidate
    for d in $(ls -td $ARCHIVE_GLOB/ 2>/dev/null); do
        candidate="${d}${fname}"
        if [ -s "$candidate" ]; then archived="$candidate"; break; fi
    done
    local live_has=0 archived_has=0
    [ -s "$live" ] && live_has=1
    [ -n "$archived" ] && archived_has=1
    if [ "$live_has" = "1" ] && [ "$archived_has" = "1" ]; then
        mkdir -p "$SCRATCH_DIR"
        local combined="$SCRATCH_DIR/.resolved_${fname}"
        cat "$archived" "$live" > "$combined"
        echo "$combined"
    elif [ "$live_has" = "1" ]; then
        echo "$live"
    elif [ "$archived_has" = "1" ]; then
        echo "$archived"
    fi
}

TS="${1:-}"
if [ -z "$TS" ]; then
    # Most recent surveillance_*.txt across BOTH live and archived
    # locations, not just live -- a fully-archived session (payload not
    # currently running) should still be found by default.
    LATEST=$(ls -t "$LOOT_DIR"/surveillance_*.txt $ARCHIVE_GLOB/surveillance_*.txt 2>/dev/null | head -1)
    if [ -z "$LATEST" ]; then
        echo "No surveillance_*.txt session logs found in $LOOT_DIR or $ARCHIVE_GLOB" >&2
        exit 1
    fi
    # surveillance_20260818_125137.txt -> 20260818_125137
    TS="$(basename "$LATEST")"
    TS="${TS#surveillance_}"
    TS="${TS%.txt}"
fi

FILES=()
for prefix in surveillance rogue_trackers deauth_eviltwin drone_rid bookmarks; do
    f="$(resolve_loot_file "${prefix}_${TS}.txt")"
    [ -n "$f" ] && FILES+=("$f")
done

if [ ${#FILES[@]} -eq 0 ]; then
    echo "No loot files found for session timestamp '$TS' in $LOOT_DIR or $ARCHIVE_GLOB" >&2
    exit 1
fi

OUT="$LOOT_DIR/kml_export_${TS}.kml"
if ! command -v awk >/dev/null 2>&1; then
    echo "awk not found -- can't run the exporter" >&2
    exit 1
fi

awk -f "$SCRIPT_DIR/export_gps_kml.awk" "${FILES[@]}" > "$OUT"
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
    echo "Export failed (awk exit $STATUS)" >&2
    rm -f "$OUT"
    exit 1
fi

echo "Session: $TS"
echo "Source files: ${FILES[*]}"
echo "Wrote: $OUT"
