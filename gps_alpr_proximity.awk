# gps_alpr_proximity.awk -- checks the current GPS position against a local
# CSV of known ALPR camera locations (id,lat,lon -- see fetch_alpr_db.sh),
# run as:
#   awk -v clat=LAT -v clon=LON -v radius_mi=25 -f gps_alpr_proximity.awk alpr_camera_db.csv
#
# Purely geographic, no RF involved at all -- this is meant to catch a
# camera regardless of whether it emits anything any of this project's other
# detectors could see. Complements them rather than replacing them: a known-
# but-silent camera (see README's "never once caught by BLE" finding) still
# shows up here as long as it's in the database and you have a GPS fix,
# while a real but unmapped camera only ever shows up via RF.
#
# TWO-STAGE FILTER, not a straight per-row haversine call: the source
# database can realistically be tens of thousands of rows nationwide (a
# single ~1x1.5 degree test cell over one Texas metro area alone returned
# 918 real ALPR nodes -- see fetch_alpr_db.sh's header). Computing sin/cos/
# atan2 for every row on every GPS cycle would be wasteful when the
# overwhelming majority of rows are nowhere near the current position. Each
# row is first checked with cheap plain-arithmetic lat/lon deltas (no trig)
# against a bounding box sized to the requested radius (with a small margin,
# and a longitude delta that accounts for the current latitude -- a degree
# of longitude covers much less ground near the poles than at the equator,
# so a fixed-degree box would either be too tight at low latitudes or
# wastefully large at high ones). Only rows that pass that cheap filter get
# the real haversine distance computed.
#
# Confirmed live on this device before relying on it: BusyBox awk's sin(),
# cos(), atan2(), and sqrt() all return correct values (checked against
# known results: sin(1)=0.841471, cos(1)=0.540302, atan2(1,1)=0.785398,
# sqrt(2)=1.41421).

BEGIN {
    FS = ","
    PI = 3.14159265358979
    if (radius_mi == "") radius_mi = 25
    clat_rad = clat * PI / 180
    # Small safety margin (+0.05 degrees, ~3.5mi) so the cheap bbox filter
    # never rejects a row the precise haversine check below would have
    # accepted -- it only needs to be a superset of the real radius, not
    # exact; the haversine check is what actually enforces radius_mi.
    lat_delta = radius_mi / 69.0 + 0.05
    coslat = cos(clat_rad)
    if (coslat < 0.01) coslat = 0.01   # guards a divide-by-near-zero at the poles; never hit for any real US latitude
    lon_delta = radius_mi / (69.0 * coslat) + 0.05
}

NR == 1 && $1 == "id" { next }   # header row from fetch_alpr_db.sh

NF >= 3 {
    id = $1; lat = $2 + 0; lon = $3 + 0

    dlat = lat - clat; if (dlat < 0) dlat = -dlat
    dlon = lon - clon; if (dlon < 0) dlon = -dlon
    if (dlat > lat_delta || dlon > lon_delta) next

    rlat2 = lat * PI / 180
    dLat = (lat - clat) * PI / 180
    dLon = (lon - clon) * PI / 180
    sa = sin(dLat / 2)
    sb = sin(dLon / 2)
    a = sa * sa + coslat * cos(rlat2) * sb * sb
    if (a > 1) a = 1   # clamp for float rounding right at antipodal/identical points
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    dist_mi = 3958.8 * c

    if (dist_mi <= radius_mi) {
        printf "%s,%.6f,%.6f,%.2f\n", id, lat, lon, dist_mi
    }
}
