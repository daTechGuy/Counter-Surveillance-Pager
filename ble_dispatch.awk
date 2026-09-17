# ble_dispatch.awk -- shared packet-reassembly driver for every BLE
# detector that reads hcidump's raw hex format (Drone Remote ID, Rogue
# Trackers, Flock BLE UUID, Smart Glasses). Run as:
#   hcidump -i hci0 --raw | awk \
#     -f rid_common.awk \
#     -f rid_ble_monitor.awk -f rogue_tracker_monitor.awk \
#     -f flock_ble_monitor.awk -f glasses_ble_monitor.awk \
#     -f ble_dispatch.awk \
#     -v WANT_RID_BLE=1 -v WANT_TRACKER=1 -v WANT_FLOCK_BLE=1 -v WANT_GLASSES=1 \
#     -v RID_HITS_FILE=... -v TRACKER_HITS_FILE=... \
#     -v FLOCK_BLE_HITS_FILE=... -v GLASSES_HITS_FILE=...
#
# Same change, same reasoning, as wifi_mgt_dispatch.awk on the WiFi side --
# see that file's own header for the full story (confirmed live this
# session: redundant per-detector capture+decode of the identical stream
# drove system load high enough on this embedded MIPS hardware to glitch
# the foreground menu). This is the BLE-side equivalent: rid_ble_monitor.awk
# / rogue_tracker_monitor.awk / flock_ble_monitor.awk / glasses_ble_monitor.awk
# each used to run their own `hcidump -i hci0 --raw` and independently
# reparse the identical HCI event stream. One shared hcidump, one shared
# reassembly pass here, calling each detector's own process_*_packet()
# function -- same non-merge as the WiFi side: each detector keeps its own
# function, own byte array (pkt[]/tpkt[]/fbpkt[]/gbpkt[]), own packet count
# (npkt/tnpkt/fbnpkt/gbnpkt), already uniquely named per file before this
# change.
#
# hcidump's own text format differs from tcpdump's -xx format this
# dispatches for on the WiFi side (see rid_ble_monitor.awk's header for the
# citation against bluez-hcidump's own parser.c/hcidump.c source): "> " or
# "< " marks a NEW packet's first line, and continuation lines carry no
# marker at all -- just more hex bytes, indistinguishable from any other
# line except by position (they follow a "> "/"< " line and precede the
# next one). That's why the reassembly here is two rules, not three like
# the WiFi side's summary-line/hex-line/catch-all: the catch-all here IS
# the hex-line rule, gated on dispatch_started instead of matched by its
# own pattern, because there is no separate marker to match against for a
# continuation line.
#
# Gating: each detector's WANT_* flag (set from payload.sh's own
# BLE_RID_OK/TRACKER_BLE_OK/FLOCK_BLE_UUID_OK/GLASSES_BLE_OK) controls both
# whether its array gets populated at all and whether its process function
# gets called -- same reasoning as wifi_mgt_dispatch.awk's own gating.

BEGIN {
    dispatch_npkt = 0
    dispatch_started = 0
}

/^[><] / {
    if (dispatch_started && dispatch_npkt > 0) dispatch_process()
    dispatch_started = 1
    dispatch_npkt = 0
    n = split($0, toks, " ")
    for (k = 2; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {
            dispatch_npkt++
            tok = toks[k]
            if (WANT_RID_BLE)    { npkt = dispatch_npkt;  pkt[dispatch_npkt]  = tok }
            if (WANT_TRACKER)    { tnpkt = dispatch_npkt; tpkt[dispatch_npkt] = tok }
            if (WANT_FLOCK_BLE)  { fbnpkt = dispatch_npkt; fbpkt[dispatch_npkt] = tok }
            if (WANT_GLASSES)    { gbnpkt = dispatch_npkt; gbpkt[dispatch_npkt] = tok }
        }
    }
    next
}

{
    if (!dispatch_started) next   # ignore hcidump's own startup banner lines
    n = split($0, toks, " ")
    for (k = 1; k <= n; k++) {
        if (toks[k] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {
            dispatch_npkt++
            tok = toks[k]
            if (WANT_RID_BLE)    { npkt = dispatch_npkt;  pkt[dispatch_npkt]  = tok }
            if (WANT_TRACKER)    { tnpkt = dispatch_npkt; tpkt[dispatch_npkt] = tok }
            if (WANT_FLOCK_BLE)  { fbnpkt = dispatch_npkt; fbpkt[dispatch_npkt] = tok }
            if (WANT_GLASSES)    { gbnpkt = dispatch_npkt; gbpkt[dispatch_npkt] = tok }
        }
    }
}

END {
    if (dispatch_started && dispatch_npkt > 0) dispatch_process()
}

function dispatch_process() {
    if (WANT_RID_BLE)   process_ble_packet()
    if (WANT_TRACKER)   process_tracker_packet()
    if (WANT_FLOCK_BLE) process_flock_ble_packet()
    if (WANT_GLASSES)   process_glasses_packet()
}
