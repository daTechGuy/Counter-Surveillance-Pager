# wifi_mgt_dispatch.awk -- shared packet-reassembly driver for every "type
# mgt" WiFi detector (Drone Remote ID, Flock, Mesh-Detect, Deauth/Evil-Twin).
# Run as:
#   tcpdump -i wlan1mon -n -l -xx type mgt | awk \
#     -f rid_common.awk \
#     -f rid_wifi_monitor.awk -f flock_wifi_monitor.awk \
#     -f mesh_wifi_monitor.awk -f deauth_eviltwin_monitor.awk \
#     -f wifi_mgt_dispatch.awk \
#     -v WANT_WIFI_RID=1 -v WANT_FLOCK_WIFI=1 -v WANT_MESH_WIFI=1 -v WANT_DEAUTH=1 \
#     -v RID_HITS_FILE=... -v FLOCK_HITS_FILE=... -v MESH_HITS_FILE=... -v DEAUTH_HITS_FILE=... \
#     -v MESH_CONFIG_FILE=... -v DEAUTH_CONFIG_FILE=...
#
# WHY THIS EXISTS: each of the four detector files above used to carry its
# OWN independent copy of this same reassembly driver (BEGIN state, the
# summary-line/hex-line pattern rules, a catch-all, an END flush), and
# payload.sh ran each as its own tcpdump+awk process -- four full
# independent captures and re-parses of the identical management-frame
# stream, up to 4x the CPU work for one radio's traffic. Confirmed live
# this session: with several of these enabled together, system load on
# this embedded MIPS hardware climbed into the teens, and the foreground
# menu's WAIT_FOR_INPUT/LIST_PICKER started flashing/glitching under that
# contention -- isolated by testing every detector alone (all clean) and by
# combination (flashing scaled with detector COUNT, not any specific one).
# An earlier pass already consolidated the tcpdump CAPTURE side (one
# process instead of four, `tee`'d out to per-detector FIFOs); this
# consolidates the awk DECODE side on top of that -- one reassembly pass
# instead of four, feeding all four detector functions directly in-process
# instead of through FIFOs at all.
#
# NOT a further merge into fewer functions: rid_wifi_monitor.awk /
# flock_wifi_monitor.awk / mesh_wifi_monitor.awk / deauth_eviltwin_monitor.awk
# each keep their own process_*_packet() function, own byte array (pkt[] /
# fpkt[] / mpkt[] / dpkt[]), own packet count (npkt / fnpkt / mnpkt /
# dnpkt) -- already uniquely named per file before this change, so there
# was nothing to rename there. This file's own driver populates all four
# in ONE pass over each hex line (one string-split/regex pass instead of
# four), then calls whichever process_*_packet() functions are actually
# wanted for this session.
#
# Gating: each detector's WANT_* flag (set from payload.sh's own
# WIFI_RID_OK/FLOCK_WIFI_OK/MESH_WIFI_OK/DEAUTH_OK) controls both whether
# its array gets populated at all (skips the redundant byte-copy for a
# detector that isn't running) and whether its process function gets
# called. mesh_have_targets is ALSO checked before calling
# process_mesh_packet(), same short-circuit mesh_wifi_monitor.awk's own
# removed driver already did -- calling it with an empty target list can
# never match anything, so there's nothing worth spending the call on.
#
# Hex-byte case: rid_wifi_monitor.awk's ORIGINAL driver stored tokens as
# tcpdump printed them (uppercase); flock/mesh/deauth's ORIGINAL drivers
# each lowercased via tolower(b). Preserved exactly per detector below
# (pkt[] uppercase, fpkt[]/mpkt[]/dpkt[] lowercased) rather than picked one
# and changed the others -- every downstream comparison in all four files
# already normalizes case itself where it matters (hex2dec() uppercases
# internally, mac_str_dot11() explicit toupper()s), so this was never
# functionally significant, and matching each file's own prior behavior
# exactly removes any need to re-verify that claim against real hardware.

BEGIN {
    dispatch_npkt = 0
    dispatch_started = 0
}

/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\./ {
    if (dispatch_started && dispatch_npkt > 0) dispatch_process()
    dispatch_started = 1
    dispatch_npkt = 0
    next   # summary line carries no packet bytes
}

/^[ \t]*0x[0-9A-Fa-f]+:/ {
    if (!dispatch_started) next
    line = $0
    sub(/^[ \t]*0x[0-9A-Fa-f]+:[ \t]*/, "", line)
    n = split(line, toks, " ")
    for (k = 1; k <= n; k++) {
        tok = toks[k]
        if (tok ~ /^[0-9A-Fa-f]+$/) {
            tl = length(tok)
            for (p = 1; p <= tl; p += 2) {
                b = substr(tok, p, 2)
                if (length(b) == 2) {
                    dispatch_npkt++
                    if (WANT_WIFI_RID)   { npkt = dispatch_npkt;  pkt[dispatch_npkt]  = b }
                    if (WANT_FLOCK_WIFI) { bl = tolower(b); fnpkt = dispatch_npkt; fpkt[dispatch_npkt] = bl }
                    if (WANT_MESH_WIFI)  { bl = tolower(b); mnpkt = dispatch_npkt; mpkt[dispatch_npkt] = bl }
                    if (WANT_DEAUTH)     { bl = tolower(b); dnpkt = dispatch_npkt; dpkt[dispatch_npkt] = bl }
                }
            }
        }
    }
    next
}

{ next }   # ignore tcpdump's startup banner / trailing capture-stats lines

END {
    if (dispatch_started && dispatch_npkt > 0) dispatch_process()
}

function dispatch_process() {
    if (WANT_WIFI_RID)   process_wifi_packet()
    if (WANT_FLOCK_WIFI) process_flock_packet()
    if (WANT_MESH_WIFI && mesh_have_targets) process_mesh_packet()
    if (WANT_DEAUTH)     process_deauth_packet()
}
