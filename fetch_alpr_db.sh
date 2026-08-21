#!/bin/bash
# fetch_alpr_db.sh -- pulls the full OpenStreetMap ALPR camera dataset (the
# same data DeFlock's map at https://deflock.org renders) via the public
# Overpass API, and writes it to alpr_camera_db.csv for gps_proximity_check()
# in payload.sh to use.
#
# WHY OVERPASS DIRECTLY, NOT DEFLOCK'S OWN SITE: DeFlock (FoggedLens/deflock
# on GitHub) is itself built on OpenStreetMap data -- its own README lists
# "OpenStreetMap - Overpass API" under Services, and deflock.org returned
# HTTP 403 to a direct fetch anyway (no public export endpoint found). The
# underlying data is the standardized OSM tagging scheme documented on the
# OSM wiki: `man_made=surveillance` + `surveillance:type=ALPR` on a node --
# querying that directly is both the actual data source and doesn't depend
# on DeFlock's own infrastructure staying up or exposing an API.
#
# WHY GRIDDED, NOT ONE NATIONWIDE QUERY: confirmed live against the public
# overpass-api.de instance -- a single query bounded to the whole continental
# US timed out at 55s with zero results, twice (once via an admin-boundary
# area lookup, once via a direct bbox). A single small test bbox (roughly
# the Austin/San Antonio, TX area, ~1.0 x 1.4 degrees) returned 918 nodes in
# a few seconds with no issue, confirming the query itself is correct and
# that density alone (not query correctness) is what breaks a nationwide
# single request. Grid cells here are sized similarly to that confirmed-
# working test cell.
#
# WHY SEQUENTIAL WITH A DELAY, NOT PARALLEL: overpass-api.de is a shared,
# free public resource with a documented fair-use expectation of not
# hammering it with concurrent/rapid requests. ~975 cells at roughly 3-5s
# each plus a respectful pause between requests means this realistically
# takes on the order of an hour for full continental-US coverage -- run it
# in the background, it's a one-time (or occasional refresh) pull, not
# something that needs to be fast.
set -u

OUT_CSV="${1:-alpr_camera_db.csv}"
# Multiple public mirrors, tried in order per cell -- confirmed live this
# matters: the primary instance alone hit a >55% failure rate (HTTP 429
# rate-limits and outright connection failures) partway into a first
# attempt at this pull, even at a 2s delay between requests. Rotating to a
# different mirror on failure, rather than just retrying the same
# overloaded one, is what actually recovers a cell instead of burning
# retries against a server that's already refusing requests.
OVERPASS_MIRRORS=(
    "https://overpass-api.de/api/interpreter"
    "https://overpass.kumi.systems/api/interpreter"
    "https://overpass.private.coffee/api/interpreter"
)
CELL_LAT=1.0
CELL_LON=1.5
DELAY_SECONDS=4
MAX_RETRIES_PER_CELL=3

# Continental US bounding rectangle. Deliberately not Alaska/Hawaii/PR --
# easy to extend with more bbox ranges later if needed, kept out for now to
# bound the initial pull's runtime.
LAT_MIN=24.5
LAT_MAX=49.5
LON_MIN=-125.0
LON_MAX=-66.9

# Tries each mirror in turn, MAX_RETRIES_PER_CELL times each, with a short
# growing backoff between attempts (2s, 4s, 6s...) before moving to the
# next mirror -- a burst of retries against the SAME already-overloaded
# server just adds to its load without improving the odds; rotating targets
# is what actually helps. Writes to $TMP_JSON, returns 0 on a 200 with a
# non-empty body, 1 if every mirror/attempt failed.
fetch_cell() {
    local bbox_lat1="$1" bbox_lon1="$2" bbox_lat2="$3" bbox_lon2="$4"
    local query="[out:json][timeout:25];node[\"man_made\"=\"surveillance\"][\"surveillance:type\"=\"ALPR\"](${bbox_lat1},${bbox_lon1},${bbox_lat2},${bbox_lon2});out;"
    local mirror attempt http_code
    for mirror in "${OVERPASS_MIRRORS[@]}"; do
        for attempt in $(seq 1 "$MAX_RETRIES_PER_CELL"); do
            http_code=$(curl -s --max-time 30 -o "$TMP_JSON" -w "%{http_code}" \
                -X POST "$mirror" --data-urlencode "data=${query}" 2>/dev/null)
            if [ "$http_code" = "200" ] && [ -s "$TMP_JSON" ]; then
                return 0
            fi
            echo "  retry: mirror=$mirror attempt=$attempt http=$http_code" >&2
            sleep $((attempt * 2))
        done
    done
    return 1
}

echo "id,lat,lon" > "$OUT_CSV"
TMP_JSON=$(mktemp)
total_cells=0
total_nodes=0
failed_cells=0

lat=$LAT_MIN
while awk -v a="$lat" -v b="$LAT_MAX" 'BEGIN{exit !(a<b)}'; do
    lat_next=$(awk -v a="$lat" -v c="$CELL_LAT" 'BEGIN{print a+c}')
    lon=$LON_MIN
    while awk -v a="$lon" -v b="$LON_MAX" 'BEGIN{exit !(a<b)}'; do
        lon_next=$(awk -v a="$lon" -v c="$CELL_LON" 'BEGIN{print a+c}')
        total_cells=$((total_cells + 1))

        if fetch_cell "$lat" "$lon" "$lat_next" "$lon_next"; then
            awk '
                /"type": "node"/ { in_node=1 }
                in_node && /"id":/ { gsub(/[^0-9]/,"",$0); id=$0 }
                in_node && /"lat":/ { gsub(/[^0-9.\-]/,"",$0); lat=$0 }
                in_node && /"lon":/ {
                    gsub(/[^0-9.\-]/,"",$0); lon=$0
                    print id","lat","lon
                    in_node=0
                    count++
                }
                END { print count+0 > "/tmp/fetch_alpr_count.tmp" }
            ' "$TMP_JSON" >> "$OUT_CSV"
            n=$(cat /tmp/fetch_alpr_count.tmp 2>/dev/null); n=${n:-0}
            total_nodes=$((total_nodes + n))
        else
            failed_cells=$((failed_cells + 1))
            echo "WARN: cell (${lat},${lon})-(${lat_next},${lon_next}) failed after all mirrors/retries -- see retry lines above" >&2
        fi

        echo "cell $total_cells: (${lat},${lon}) running total=${total_nodes} failed=${failed_cells}"
        sleep "$DELAY_SECONDS"
        lon=$lon_next
    done
    lat=$lat_next
done

rm -f "$TMP_JSON" /tmp/fetch_alpr_count.tmp
echo "DONE: $total_cells cells, $total_nodes nodes written to $OUT_CSV, $failed_cells cells failed"

# Also build the indexed .sqlite database payload.sh actually reads --
# see ALPR_DB_FILE's comment in payload.sh for why: a real on-device timing
# test (100k synthetic rows, this exact device) showed a full awk scan of
# the CSV takes 3m42s, an indexed sqlite3 range query takes well under a
# second to a few seconds depending on box size. The CSV stays the
# canonical, human-inspectable output of the fetch itself; this is a
# derived build artifact from it, rebuilt fresh each run rather than
# updated in place.
if command -v sqlite3 >/dev/null 2>&1; then
    DB_FILE="${OUT_CSV%.csv}.sqlite"
    rm -f "$DB_FILE"
    sqlite3 "$DB_FILE" <<SQL
CREATE TABLE cameras (id INTEGER, lat REAL, lon REAL);
.mode csv
.import --skip 1 $OUT_CSV cameras
CREATE INDEX idx_lat ON cameras(lat);
SQL
    echo "DB: $DB_FILE built ($(sqlite3 "$DB_FILE" 'SELECT COUNT(*) FROM cameras;') rows indexed)"
else
    echo "WARN: sqlite3 not found on this machine -- $OUT_CSV was written, but the .sqlite payload.sh actually reads was NOT built. Install sqlite3 and re-run, or build it manually (see this script's own sqlite3 invocation above)." >&2
fi
