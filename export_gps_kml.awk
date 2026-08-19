# export_gps_kml.awk -- turns this payload's GPS-tagged loot lines into a
# KML file for Google Earth/Maps, so a session's drive can be seen on a map
# instead of read as scrolling text. Run as:
#   awk -f export_gps_kml.awk surveillance_TS.txt rogue_trackers_TS.txt \
#       deauth_eviltwin_TS.txt drone_rid_TS.txt bookmarks_TS.txt > session.kml
# (any of the five loot files can be omitted from the argument list -- awk
# just processes whichever ones exist; export_gps_kml.sh builds this list
# for you from a session timestamp).
#
# Depends on exactly one thing, not each file's own per-detector field
# layout: every GPS-tagged loot line in this project ends in its own
# " | gps=LAT,LON" field, appended only when GPS_GET had a fix at log time
# (see payload.sh's GPS_TAG). That trailing field is stripped for the
# coordinates; everything before it becomes the placemark's label as-is --
# no attempt to re-decode each detector's own field format, so this stays
# correct even if a detector's log line format changes later.
#
# Lines with no gps= field (no GPS fix at the time, or GPS hardware never
# attached) are silently skipped -- they have no coordinates to plot, not
# an error.

BEGIN {
    print "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    print "<kml xmlns=\"http://www.opengis.net/kml/2.2\">"
    print "<Document>"
    print "  <name>Counter-Surveillance-Pager Export</name>"
    # One Style per category so Google Earth/Maps color-codes the pins.
    # KML color format is aabbggrr (alpha, blue, green, red), not rrggbb.
    print style_def("flock",    "ff0000ff")   # red
    print style_def("mesh",     "ff00a5ff")   # orange
    print style_def("tracker",  "ffff00ff")   # magenta
    print style_def("deauth",   "ff0000ff")   # red
    print style_def("eviltwin", "ff0080ff")   # deep orange-red
    print style_def("drone",    "ff00ffff")   # yellow
    print style_def("bookmark", "ff00ff00")   # green -- deliberately not used
                                               # by any detector category, so a
                                               # manually-flagged moment always
                                               # stands out from real hits
    print style_def("other",    "ffffffff")   # white
    total = 0
}

function style_def(id, color) {
    return "  <Style id=\"" id "\"><IconStyle><color>" color "</color><scale>1.1</scale></IconStyle></Style>"
}

# Minimal XML escaping for placemark text -- loot lines can contain BLE
# device names or SSIDs from untrusted RF broadcasts (already sanitized to
# printable ASCII by rid_common.awk's sanitize() for the fields that go
# through it, but not every field here does), so this isn't optional.
function xmlesc(s) {
    gsub(/&/, "\\&amp;", s)
    gsub(/</, "\\&lt;", s)
    gsub(/>/, "\\&gt;", s)
    return s
}

function category_for(fname, text,    lt) {
    lt = tolower(text)
    if (fname ~ /bookmarks/) return "bookmark"
    if (fname ~ /rogue_trackers/) return "tracker"
    if (fname ~ /deauth_eviltwin/) {
        if (lt ~ / \| eviltwin \|/) return "eviltwin"
        return "deauth"
    }
    if (fname ~ /drone_rid/) return "drone"
    # Flock BLE name-scan hits ("fs ext battery"/"penguin"/"pigvision"/
    # "flock") and Flock WiFi/BLE-UUID hits ("Flock (..." / "Flock? (..." /
    # "Flock?? (...") all land here.
    if (lt ~ /flock|penguin|pigvision|battery/) return "flock"
    # Mesh-Detect: either the generic "Mesh-Detect (..." label, or a
    # vendor-specific one from mesh_vendor_label(), e.g. "Axon Cam detected
    # (...)" -- neither contains the word "Mesh-Detect" in the vendor case,
    # so "detected (" is the shared marker instead.
    if (lt ~ /mesh-detect|detected \(/) return "mesh"
    return "other"
}

{
    # Matched directly against the end of the line, not via split-on-" | "
    # -- a field with nothing in it before gps= (e.g. rogue_tracker_
    # monitor.awk's tile/smarttag/fmdn hits, whose 4th field is always
    # empty) produces a "| | gps=..." double-pipe run that a last-field
    # split would silently treat as not matching /^gps=/ and drop.
    # Matching the suffix pattern directly sidesteps that regardless of
    # what odd-but-valid punctuation precedes it.
    if (!match($0, / \| gps=[-0-9.]+,[-0-9.]+$/)) next
    coords = substr($0, RSTART, RLENGTH)
    sub(/^ \| gps=/, "", coords)
    split(coords, ll, ",")
    lat = ll[1]; lon = ll[2]
    if (lat == "" || lon == "") next

    desc = substr($0, 1, RSTART - 1)

    cat = category_for(FILENAME, desc)
    total++
    print "  <Placemark>"
    print "    <name>" xmlesc(desc) "</name>"
    print "    <styleUrl>#" cat "</styleUrl>"
    print "    <Point><coordinates>" lon "," lat ",0</coordinates></Point>"
    print "  </Placemark>"
}

END {
    print "</Document>"
    print "</kml>"
    print "Wrote " total " placemark(s)" > "/dev/stderr"
}
