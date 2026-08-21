#!/bin/bash
# fetch_alpr_db.sh -- pulls ALPR camera locations (the same data DeFlock's
# own map at https://deflock.org / maps.deflock.org renders) and writes a
# region-filtered id,lat,lon CSV, then builds the indexed .sqlite database
# payload.sh actually reads.
#
# DATA SOURCE, 2nd revision: a single static GeoJSON download --
# https://data.dontgetflocked.com/cameras.geojson.gz -- found by reading
# deflockhopper_maps (FoggedLens/deflockhopper_maps, the DeFlock map
# frontend's own repo, split out from the main deflock repo -- see its
# CLAUDE.md's "Data Sources" section) rather than guessing. This is
# DeFlock's own pre-aggregated, deduplicated dataset (132k+ US+Canada
# cameras as of a live pull on 2026-08-20, more current than the ~114k
# figure in that repo's own docs), served from Cloudflare -- confirmed
# live: full file downloads in ~1.5s, vs. the gridded-Overpass-query
# approach this script used to take (see git history), which depended on
# ~975 sequential queries against shared, unreliable public Overpass
# mirrors. A live check the same night found ALL of overpass-api.de,
# overpass.kumi.systems, overpass.private.coffee, and 4 more public
# instances either down or serving stale/incomplete data (one returned
# HTTP 200 with valid-looking JSON but 0 nodes for a query independently
# confirmed to have 918 real matches elsewhere) -- crowdsourced community
# Overpass mirrors are not a reliable foundation for something meant to
# run reliably. DeFlock's own CDN-backed static file doesn't have that
# problem, and it's the same underlying OSM data either way (both this
# file's earlier Overpass-based approach and DeFlock's own pipeline trace
# back to the same `man_made=surveillance` / `surveillance:type=ALPR` OSM
# tagging scheme -- this isn't a different, less-authoritative source).
#
# GeoJSON, not the compressed .gz extension the URL implies: confirmed
# live the server/CDN already serves it decompressed (or curl's automatic
# content-encoding handling did) -- `file` on the downloaded content
# reports plain ASCII text, and it parses directly as JSON with no
# decompression step needed.
#
# Coordinate order is [lon, lat] (GeoJSON's own convention), NOT [lat,
# lon] -- easy to get backwards, double-checked against real entries
# before trusting it (e.g. a Georgia camera at lon=-83.15, lat=34.28 --
# a lon of +34 would place it in the Mediterranean, not Georgia).
set -u

OUT_CSV="${1:-alpr_camera_db.csv}"
SOURCE_URL="https://data.dontgetflocked.com/cameras.geojson.gz"

# Same override convention as before: defaults to the continental US, set
# LAT_MIN/LAT_MAX/LON_MIN/LON_MAX to scope a single state/region instead.
LAT_MIN="${LAT_MIN:-24.5}"
LAT_MAX="${LAT_MAX:-49.5}"
LON_MIN="${LON_MIN:--125.0}"
LON_MAX="${LON_MAX:--66.9}"

RAW_JSON=$(mktemp)
echo "Downloading $SOURCE_URL ..."
http_code=$(curl -s --max-time 120 -o "$RAW_JSON" -w "%{http_code}" "$SOURCE_URL")
if [ "$http_code" != "200" ] || [ ! -s "$RAW_JSON" ]; then
    echo "FATAL: download failed (http=$http_code)" >&2
    rm -f "$RAW_JSON"
    exit 1
fi
raw_size=$(wc -c < "$RAW_JSON")
echo "Downloaded $raw_size bytes."

# RS trick: each awk "record" after the first is one GeoJSON Feature's
# raw text (the whole file is a handful of very long lines, not one
# Feature per line, so a normal per-line parser doesn't apply here the
# way it did for tcpdump/hcidump/Overpass's own multi-line JSON output).
awk -v RS='{"type":"Feature"' -v latmin="$LAT_MIN" -v latmax="$LAT_MAX" -v lonmin="$LON_MIN" -v lonmax="$LON_MAX" '
    BEGIN { print "id,lat,lon" }
    NR > 1 {
        if (!match($0, /"coordinates":\[(-?[0-9.]+),(-?[0-9.]+)\]/, m)) next
        lon = m[1] + 0; lat = m[2] + 0
        if (!match($0, /"osmId":([0-9]+)/, m2)) next
        id = m2[1]
        if (lat >= latmin && lat <= latmax && lon >= lonmin && lon <= lonmax) {
            print id "," lat "," lon
            count++
        }
    }
    END { print "matched: " count+0 > "/dev/stderr" }
' "$RAW_JSON" > "$OUT_CSV"

rm -f "$RAW_JSON"
node_count=$(($(wc -l < "$OUT_CSV") - 1))
echo "DONE: $node_count nodes in region written to $OUT_CSV"

# Same final step as before: build the indexed .sqlite database
# payload.sh actually reads -- see ALPR_DB_FILE's comment in payload.sh
# for why a plain CSV scan isn't fast enough for a live per-GPS-cycle
# check at any real dataset size.
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
