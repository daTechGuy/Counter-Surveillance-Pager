#!/bin/bash
# summarize_session.sh -- quick post-session report: hit counts, unique MAC
# counts, and GPS-fix coverage per detector, without reading four separate
# loot files by hand. Companion to export_gps_kml.sh -- same session-
# timestamp argument convention (most recent session by default, or name
# one explicitly).
#
# Usage:
#   ./summarize_session.sh                  # most recent session
#   ./summarize_session.sh 20260818_125137  # a specific session timestamp
#
# Read-only: greps/counts against the loot files, doesn't touch anything
# live. Safe to run alongside an active payload session or after one ends.
#
# ARCHIVE-AWARE: see export_gps_kml.sh's header for the full explanation --
# this Pager's "Archive Loot" web UI feature doesn't stop a running payload,
# so using it mid-session splits that session's log files between the live
# path and /root/loot/archive/archive-<timestamp>/. resolve_loot_file()
# below finds both halves (if both exist) and stitches them back together.

set -u
LOOT_DIR="/root/loot/counter_surveillance_pager"
ARCHIVE_GLOB="/root/loot/archive/archive-*/counter_surveillance_pager"
SCRATCH_DIR="/tmp/counter_surveillance_pager"

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
    LATEST=$(ls -t "$LOOT_DIR"/surveillance_*.txt $ARCHIVE_GLOB/surveillance_*.txt 2>/dev/null | head -1)
    if [ -z "$LATEST" ]; then
        echo "No surveillance_*.txt session logs found in $LOOT_DIR or $ARCHIVE_GLOB" >&2
        exit 1
    fi
    TS="$(basename "$LATEST")"
    TS="${TS#surveillance_}"
    TS="${TS%.txt}"
fi

SURV="$(resolve_loot_file "surveillance_${TS}.txt")"
TRACK="$(resolve_loot_file "rogue_trackers_${TS}.txt")"
DEAUTH="$(resolve_loot_file "deauth_eviltwin_${TS}.txt")"
DRONE="$(resolve_loot_file "drone_rid_${TS}.txt")"

# Count matches of a pattern in a file, always printing a clean integer
# (grep -c prints 0 on no match already, but exits nonzero for it under
# `set -u`-adjacent strict callers -- guard defensively either way).
count_of() {
    local pat="$1" file="$2" n
    n=$(grep -cE "$pat" "$file" 2>/dev/null)
    echo "${n:-0}"
}

echo "Session: $TS"
echo "======================================"
echo ""

if [ -f "$SURV" ]; then
    total=$(count_of '^DECT:' "$SURV")
    flock_high=$(count_of 'conf=high' "$SURV")
    flock_low=$(count_of 'conf=low' "$SURV")
    flock_ble_uuid=$(count_of 'unverified signature' "$SURV")
    flock_name=$(count_of '\| (fs ext battery|[Pp]enguin|[Pp]igvision)' "$SURV")
    mesh=$(count_of 'Mesh-Detect|detected \(' "$SURV")
    gps_hits=$(count_of ' \| gps=' "$SURV")
    rssi_hits=$(count_of '\|rssi=' "$SURV")
    unique_macs=$(grep '^DECT:' "$SURV" 2>/dev/null | awk -F' \\| ' '{print $2}' | sort -u | wc -l)
    echo "Flock / Mesh-Detect (surveillance.txt):"
    echo "  Total hit lines            : $total"
    echo "  Unique MACs                : $unique_macs"
    echo "  Flock, conf=high           : $flock_high"
    echo "  Flock, conf=low            : $flock_low"
    echo "  Flock BLE UUID (unverified): $flock_ble_uuid"
    echo "  Flock BLE name-match       : $flock_name"
    echo "  Mesh-Detect watchlist      : $mesh"
    echo "  GPS-tagged                 : $gps_hits"
    echo "  RSSI-tagged                : $rssi_hits"
else
    echo "Flock / Mesh-Detect: no surveillance_${TS}.txt found"
fi
echo ""

if [ -f "$TRACK" ]; then
    total=$(count_of '^[0-9][0-9]:[0-9][0-9]:[0-9][0-9] \|' "$TRACK")
    applefindmy=$(count_of 'Apple Find My' "$TRACK")
    tile=$(count_of '\| Tile \|' "$TRACK")
    smarttag=$(count_of 'Samsung SmartTag' "$TRACK")
    fmdn_unwanted=$(count_of 'flagged unwanted tracking' "$TRACK")
    fmdn_total=$(count_of 'Google Find My Device Network' "$TRACK")
    fmdn_normal=$((fmdn_total - fmdn_unwanted))
    gps_hits=$(count_of ' \| gps=' "$TRACK")
    unique_macs=$(grep -E '^[0-9][0-9]:[0-9][0-9]:[0-9][0-9] \|' "$TRACK" 2>/dev/null | awk -F' \\| ' '{print $2}' | sort -u | wc -l)
    echo "Rogue BLE trackers:"
    echo "  Total sighting lines       : $total"
    echo "  Unique MACs                : $unique_macs"
    echo "  Apple Find My              : $applefindmy"
    echo "  Tile                       : $tile"
    echo "  Samsung SmartTag           : $smarttag"
    echo "  Google FMDN (normal)       : $fmdn_normal"
    echo "  Google FMDN (self-flagged unwanted): $fmdn_unwanted"
    echo "  GPS-tagged                 : $gps_hits"
    if [ "$fmdn_unwanted" -gt 0 ] || [ "$applefindmy" -gt 0 ] || [ "$tile" -gt 0 ] || [ "$smarttag" -gt 0 ]; then
        echo "  NOTE: a sighting here is NOT proof of being followed -- only a"
        echo "        sighting=N count of 3+ spread over 15+ minutes (or any"
        echo "        FMDN-unwanted sighting) would have crossed this session's"
        echo "        persistence threshold and triggered a loud alert. Check"
        echo "        the sighting= counts above per-MAC in this session's"
        echo "        rogue_trackers_${TS}.txt (live and/or archived copy)."
    fi
else
    echo "Rogue BLE trackers: no rogue_trackers_${TS}.txt found"
fi
echo ""

if [ -f "$DEAUTH" ]; then
    # Field-based, not substring grep: the 2nd field ("kind") is literally
    # "deauth" for BOTH the Deauthentication and Disassociation subtypes
    # (see deauth_eviltwin_monitor.awk's process_deauth_packet -- only the
    # 4th field, subtype, actually distinguishes them), so a naive
    # '| deauth |' substring match would count disassoc lines too.
    deauth_n=$(awk -F' \\| ' '$2=="deauth" && $4=="deauth" {c++} END{print c+0}' "$DEAUTH")
    disassoc_n=$(awk -F' \\| ' '$2=="deauth" && $4=="disassoc" {c++} END{print c+0}' "$DEAUTH")
    eviltwin_n=$(awk -F' \\| ' '$2=="eviltwin" {c++} END{print c+0}' "$DEAUTH")
    gps_hits=$(count_of ' \| gps=' "$DEAUTH")
    unique_srcs=$(awk -F' \\| ' '$2=="deauth" {split($3,a," "); print a[1]}' "$DEAUTH" 2>/dev/null | sort -u | wc -l)
    echo "Deauth / Evil-Twin AP:"
    echo "  Deauth frame lines   : $deauth_n"
    echo "  Disassoc frame lines : $disassoc_n"
    echo "  Evil-twin AP lines   : $eviltwin_n"
    echo "  Unique deauth sources: $unique_srcs"
    echo "  GPS-tagged           : $gps_hits"
else
    echo "Deauth / Evil-Twin AP: no deauth_eviltwin_${TS}.txt found"
fi
echo ""

if [ -f "$DRONE" ]; then
    total=$(count_of '^[0-9][0-9]:[0-9][0-9]:[0-9][0-9] \|' "$DRONE")
    ble_n=$(count_of '\| ble \|' "$DRONE")
    wifi_beacon_n=$(count_of '\| wifi_beacon \|' "$DRONE")
    wifi_nan_n=$(count_of '\| wifi_nan \|' "$DRONE")
    gps_hits=$(count_of ' \| gps=' "$DRONE")
    unique_macs=$(grep -E '^[0-9][0-9]:[0-9][0-9]:[0-9][0-9] \|' "$DRONE" 2>/dev/null | awk -F' \\| ' '{print $3}' | sort -u | wc -l)
    echo "Drone Remote ID:"
    echo "  Total message lines : $total"
    echo "  Unique MACs         : $unique_macs"
    echo "  Via BLE             : $ble_n"
    echo "  Via WiFi Beacon     : $wifi_beacon_n"
    echo "  Via WiFi NAN        : $wifi_nan_n"
    echo "  Pager's own GPS tag : $gps_hits (drone/operator's own self-reported"
    echo "                         position, if any, is separate -- see the"
    echo "                         raw lines for lat=/lon=/operator_lat=/lon=)"
else
    echo "Drone Remote ID: no drone_rid_${TS}.txt found"
fi
