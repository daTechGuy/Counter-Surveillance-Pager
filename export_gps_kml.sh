#!/bin/bash
# export_gps_kml.sh -- wrapper around export_gps_kml.awk: picks a session
# (most recent by default, or one you name) out of $LOOT_DIR, hands its
# four loot files (whichever exist) to the awk exporter, and writes the
# result back into $LOOT_DIR as a KML you can pull off the device (USB
# Mount Loot Transfer, scp, etc.) and open in Google Earth/Google My Maps.
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

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOOT_DIR="/root/loot/counter_surveillance_pager"

if [ ! -d "$LOOT_DIR" ]; then
    echo "No loot directory found at $LOOT_DIR -- has this payload ever run?" >&2
    exit 1
fi

TS="${1:-}"
if [ -z "$TS" ]; then
    LATEST=$(ls -t "$LOOT_DIR"/surveillance_*.txt 2>/dev/null | head -1)
    if [ -z "$LATEST" ]; then
        echo "No surveillance_*.txt session logs found in $LOOT_DIR" >&2
        exit 1
    fi
    # surveillance_20260818_125137.txt -> 20260818_125137
    TS="$(basename "$LATEST")"
    TS="${TS#surveillance_}"
    TS="${TS%.txt}"
fi

FILES=()
for prefix in surveillance rogue_trackers deauth_eviltwin drone_rid; do
    f="$LOOT_DIR/${prefix}_${TS}.txt"
    [ -f "$f" ] && FILES+=("$f")
done

if [ ${#FILES[@]} -eq 0 ]; then
    echo "No loot files found for session timestamp '$TS' in $LOOT_DIR" >&2
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
