# ALPR-GPS-Alert

Alerts when the Pager comes within range of a **mapped ALPR camera** (automatic
licence plate reader), by position alone. No radio is used at any point.

**Scope:** this covers every mapped plate reader, not only Flock Safety. The
dataset is tagged `surveillance:type=ALPR`, which includes Motorola/Vigilant,
Genetec and the rest. A hit means *a mapped plate reader is near you*, not
*that camera is a Flock*. The detector that genuinely identifies Flock Safety
hardware over RF lives in the [parent payload](../README.md).

Split out of [Counter-Surveillance-Pager](../README.md), where it ran as one
detector among eight.

## Why it is separate

Every other detector in that payload is a radio listener: it hears something
and decides what it is. This one hears nothing. It is pure geography — where
am I, and is there a camera near here on a map somebody else already drew.
That difference runs deeper than it sounds:

- **It needs no radio at all.** No BLE adapter, no monitor-mode WiFi, no
  channel hopping, and none of the `pineapd` interface contention the WiFi
  detectors have to be configured around. Only `GPS_GET` and `sqlite3`.
- **It cannot be starved by the shared-radio duty cycle** every other detector
  competes inside, and it never takes radio time from them.
- **It alerts on ground truth, not an RF heuristic.** A database match is a
  mapped camera, not a signature that might turn out to be something else,
  which is why its alert is a hard one.
- **It carries a 3.8MB dataset** that nothing else in that payload reads.

Running it separately also means it can run where the other payload should
not: nothing transmits, nothing is put into monitor mode, and the battery cost
is a GPS fix and one indexed query every few seconds.

## Requirements

| Needs | Why |
| --- | --- |
| `GPS_GET` | the Pager's own GPS command, and a live fix |
| `sqlite3` | confirmed present on this device |
| `alpr_camera_db.sqlite` | built from the shipped CSV, see below |

Without a GPS fix it simply finds nothing — a fix can come and go mid-session
(tunnel, parking garage), which is handled: it polls again next cycle.

## Building the database

`alpr_camera_db.csv` is committed (132,766 cameras, US + Canada). The `.sqlite`
this actually reads is a **gitignored build artefact** — a binary not worth
diffing in git, regenerable from the CSV in one command.

On the device, in this payload's directory:

```sh
sqlite3 alpr_camera_db.sqlite <<'SQL'
CREATE TABLE cameras (id INTEGER, lat REAL, lon REAL);
.mode csv
.import --skip 1 alpr_camera_db.csv cameras
CREATE INDEX idx_lat ON cameras(lat);
SQL
```

That takes about 3.5 minutes on the Pager's mipsel CPU. The payload refuses to
start without it and says so.

To refresh the data on a machine with real internet, then copy both files
across:

```sh
bash fetch_alpr_db.sh alpr_camera_db.csv
```

Bound it to a region with `LAT_MIN`/`LAT_MAX`/`LON_MIN`/`LON_MAX` if you do not
want the full US + Canada set.

## Why a database and not the CSV

A full linear scan of the CSV measured **3m42s** on a 100k-row test set, which
is useless for a check that has to run every few seconds. The indexed query
measured **0.26–0.30s** on the real 132,766-row dataset on the device.

The lookup is two stages: `sqlite3` does an indexed bounding-box pre-filter,
then `gps_alpr_proximity.awk` runs a precise haversine distance over just that
small candidate set. The bounding box is deliberately generous — it only has to
avoid excluding a camera the precise check would have accepted.

## GPS has to be working first

This payload does **not** start or configure the GPS. It calls `GPS_GET` and
uses whatever fix `gpsd` already has, because GPS is device configuration, not
a payload's business. But it does *report* the state, since silence would
otherwise be ambiguous: "no cameras nearby" and "the receiver was never plugged
in" look identical.

Three things have to line up, and each fails differently:

| Check | Failure looks like |
| --- | --- |
| `gpsd` running | `GPS_GET` returns `0 0 0 0`, same as a cold receiver |
| Device path valid | `gpsd` cannot open it, so it will not start |
| A fix acquired | cold start takes 15-30 minutes with clear sky |

**The device path encodes the USB port.** `gpsd.core.device` is a
`/dev/serial/by-path/...` entry, so moving the receiver to a different port, or
adding a hub, changes it and breaks the config. Seen on this very device after
a reflash: the config said `1.1_1-1.1:1.0` while the hardware was on
`1.3_1-1.3:1.x`.

Set it in the Pager UI under `Settings` > `GPS` — device path and baud (4800,
9600 or 115200), then **Restart GPSd**. `cgps` over SSH shows live satellite
detail. Hak5's own [GPS documentation](https://documentation.hak5.org/wifi-pineapple-pager/gps)
covers supported receivers; U-Blox M8030-KT and Quectel are the recommended
chipsets.

The startup banner reports any of this that is wrong, and the **GPS Health**
screen shows it live. Neither is fatal: `gpsd` can be started and the receiver
replugged while this runs, and the loop picks up a fix the moment one exists.

## Using it

Options at startup: Stealth Mode (3-way), Always Alert, and GPS track logging.
Then it scans in the background and the menu owns the screen:

```
1: Status          uptime, fix count, position, FIX AGE, cameras found
2: Cameras Found   the session's hits
3: GPS Health      gpsd, device path, baud, and what to fix
4: Database        camera count, size, or why it is not usable
5: Session Files   where the loot went
0: Stop Scanning
```

The menu style follows hak5's
[`bt-bluepine`](https://github.com/hak5/wifipineapplepager-payloads/tree/master/library/user/reconnaissance/bt-bluepine):
print a screen, block on a picker, act, print, block again. Nothing prints
while a screen is being read, which is what keeps it still.

## Alerting

A database match is ground truth, so it gets the hard alert: LED, ringtone and
a dialog, plus a vibrate pulse. Stealth Mode 1 drops to vibrate only; Stealth
Mode 2 is fully silent and the loot file is the only record.

Each camera alerts **once per session** by OSM node id, so driving a loop past
the same one does not buzz every lap. Always Alert turns that off.

## Loot

Written to `/root/loot/alpr_gps_alert/`:

- `alpr_gps_<timestamp>.txt` — one line per camera found, with the position you
  were at when it triggered
- `track_<timestamp>.txt` — every GPS fix, only when track logging is on

Hit lines carry a trailing `| gps=LAT,LON`, the same format
[`export_gps_kml.sh`](../export_gps_kml.sh) in the parent payload reads, so a
session can be exported to KML for Google Earth or My Maps.

## Credit

The dataset is **DeFlock's** own aggregated OpenStreetMap data
([deflock.org](https://deflock.org)), traced back to the `man_made=surveillance`
/ `surveillance:type=ALPR` tagging scheme. See `fetch_alpr_db.sh`'s header for
how that source was chosen and why the earlier Overpass-based approach was
abandoned.
