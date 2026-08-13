# Flock-Sky-Spy

## Credit

Both detectors this payload combines originate with **[colonelpanichacks (Colonel Panic)](https://github.com/colonelpanichacks)**:

- **[Flock-You / flock-you](https://github.com/colonelpanichacks/flock-you)** ([Flock_Detect on the official Pager payload repo](https://github.com/hak5/wifipineapplepager-payloads/tree/master/library/user/reconnaissance/Flock_Detect)) -- the BLE scan loop and Flock Safety detection logic in this payload are taken from here **unmodified**.
- **[Sky-Spy](https://github.com/colonelpanichacks/Sky-Spy)** -- the drone Remote ID detection *approach* this payload ports comes from here. Sky-Spy itself is ESP32 firmware with no Linux build, so the port is a from-scratch reimplementation of that same detection concept against the ASTM F3411 spec, for the Pager's own Linux BLE/WiFi stack.

All credit for the underlying detection concepts and the original Flock-You code belongs to Colonel Panic. This repo is a derivative work combining both of his projects into one payload for a device (the Pager) that Sky-Spy doesn't natively run on.

## What this is

Combines two detectors into one Pager payload:

- **Flock Safety BLE detection** -- taken verbatim from Flock-You / Flock_Detect. Unmodified scan loop, unmodified alert logic.
- **Drone Remote ID detection** -- a from-scratch Linux port of what Sky-Spy does on ESP32, reimplementing its detection logic directly against the ASTM F3411 / Open Drone ID spec for the Pager's own BLE and WiFi radios, using `hcidump` and `iw`/`tcpdump` instead of ESP-IDF.

## Why this needed real engineering, not a copy-paste

Sky-Spy's own README describes what it detects (WiFi Beacon + WiFi NAN + BLE broadcasts of drone position/ID), but the actual bytes-on-the-wire format isn't in that repo -- it's implicit in the ESP-IDF/Arduino build. Getting it right required going to the reference implementation and spec:

- [`opendroneid-core-c`](https://github.com/opendroneid/opendroneid-core-c) -- `libopendroneid/opendroneid.h` (encoded message struct layouts), `opendroneid.c` (scale factors: `LATLON_MULT=1e7`, `ALT_DIV=0.5`/`ALT_ADDER=1000`, `SPEED_DIV`), `odid_wifi.h`/`.c` (vendor IE / NAN OUIs and frame structure)
- [`transmitter-linux`](https://github.com/opendroneid/transmitter-linux/blob/main/bluetooth.c) -- exact BLE legacy advertising byte layout (Service Data, UUID `0xFFFA`, AD App Code `0x0D`)

All of this is cited inline in `rid_common.awk`.

### Why awk, not python3

The first version of this was written in python3. It turned out this Pager (`mipsel_24kc` / `ramips` target, 24.10.1, `no-all busybox` build, ~30MB overlay flash) has **no python3 available at all** -- confirmed live against the actual device: `which python3` finds nothing, and `opkg list` shows no python3 package in the configured feeds for this target, not just "not installed." Chasing a hand-built static python3 for this exact old MIPS chip was judged not worth the uncertainty, so the decoders were rewritten from scratch in POSIX-ish awk, run via BusyBox's own `awk` (confirmed present, along with the specific functions needed: `index`, `substr`, `toupper`, `sprintf`, `fflush`).

### What was actually verified, and how

Every layer of this was checked against **real captures pulled from this specific device** during development, not just generic docs, because two format assumptions turned out to matter a lot:

1. **`hcidump --raw`'s exact text format** (direction marker, hex-byte wrapping) -- confirmed by fetching bluez-hcidump's own `parser.c`/`hcidump.c` source, then cross-checked against a real ~6-second BLE capture from this device. One of the real advertising reports in that capture was hand-decoded byte-by-byte (MAC, AD structures, RSSI) to confirm the LE Advertising Report event's "structure of arrays" layout (all event types, then all address types, then all addresses, then all lengths, then the concatenated data blocks, then all RSSIs -- not one struct per report).
2. **`tcpdump -xx`'s hex-dump layout** -- confirmed against a real 3-beacon capture from this device's `wlan1mon`. The radiotap `it_len` field read from the real bytes (56) landed exactly on `frame_control = 0x0080` (Beacon) when used to compute where the 802.11 frame starts, and offset `dot11_start + 10` landed exactly on the real source MAC -- both hand-verified against the actual hex, not assumed.
3. **The awk decoders themselves** -- round-trip tested locally (via `gawk`, functionally equivalent to the device's `awk` for everything used here) against: (a) the real, unmodified BLE and WiFi captures from this device, to confirm zero false positives and no crashes on ordinary ambient traffic; and (b) synthetic Basic ID / Location / System messages injected into correctly-framed copies of those same real captures (single BLE legacy advertisement, a 3-message WiFi Beacon pack, and a 3-message WiFi NAN Service Descriptor attribute), to confirm detection actually fires and every field decodes to the exact input value. The full FIFO-based pipeline wiring in `payload.sh` (capture tool -> named pipe -> awk) was also tested end-to-end locally to rule out any deadlock in the producer/consumer startup ordering.

None of this required guessing at busybox-awk-specific behavior blind -- every primitive it depends on was confirmed running on the real device first (see the conversation this was built in).

## Files

| File | Role |
|---|---|
| `payload.sh` | Main driver. Runs Flock-You's original BLE loop unchanged; starts the two Remote ID background monitors (each via a named FIFO, not a shell pipe, so their PIDs are directly killable on exit) if their dependencies are present; drains their hit logs each cycle for LOG/LED/RINGTONE alerts. |
| `rid_common.awk` | Shared decode functions: hex conversion, ASTM message decoders (Basic ID, Location, System, Self ID, Operator ID), field sanitization, hit-line formatting. No I/O, no BEGIN/END/main rules -- loaded via a second `-f` alongside one of the two monitor scripts below. |
| `rid_ble_monitor.awk` | Reads `hcidump --raw`'s text output, reassembles HCI Event packets from its line-wrapped hex format, extracts LE Advertising Report events, looks for the Remote ID Service Data AD structure. |
| `rid_wifi_monitor.awk` | Reads `tcpdump -xx`'s text output, reassembles per-packet hex bytes, strips the radiotap header, looks for the Remote ID vendor IE (Beacon method) or NAN Service Descriptor attribute (NAN method). |

## Requirements per detector (each degrades independently)

- **Flock BLE** (unchanged from Flock-You): `hciconfig`, `hcitool` -- if these were on your Pager before, nothing changes here.
- **Drone BLE**: + `awk`, `hcidump`. Both confirmed present on this device.
- **Drone WiFi**: + `awk`, `iw`, `tcpdump`, and a usable second radio (`phy1`). Confirmed on this device: `phy1` exists and accepts `iw phy phy1 interface add wlan1mon type monitor`, and a real capture was taken from it successfully.

## Known limitations (by design, not oversights)

- **Drone BLE detection is not continuous.** It piggybacks on Flock-You's own `hcitool lescan` windows (~12 of every ~15 seconds) rather than running a separate scan, so it inherits that duty cycle. Continuous BLE scanning independent of the Flock cycle would need its own `hcitool lescan`/`bluetoothctl` session, which risks fighting the Flock scan for the single BLE radio -- left as a follow-up if the merged duty cycle proves insufficient in practice.
- **Drone WiFi detection is fixed to channel 6 (2.4GHz)**, matching Sky-Spy's own default. A drone broadcasting Remote ID only on 5GHz, or on a 2.4GHz channel other than 6, will be missed. Channel hopping across a small set (1/6/11 at minimum) is a reasonable next step once channel 6 alone is confirmed working against a real drone.
- **BLE Extended/Long-Range advertising (Bluetooth 5) is not decoded** -- only Legacy advertising (the common case for consumer drones).
- **Auth messages are identified but not decoded** (their content isn't useful for a recon alert).
- UI alerts are cooldown-throttled per MAC (10s, `ALERT_COOLDOWN` in `payload.sh`) since WiFi Remote ID beacons repeat far faster than Flock's BLE cycle and would otherwise spam the console. The loot log (`drone_rid_*.txt`) is **never** throttled -- every decoded message is recorded.

## Confirmed live on hardware

Beyond the local decoder testing described above, on the actual Pager:

- Both background pipelines (`hcidump`/`awk` for BLE, `tcpdump`/`awk` for WiFi) start, stay running, and produce **zero stderr output** -- confirmed via `ps` and the pipelines' own log files while `payload.sh` was live.
- A synthetic hit line appended directly to the WiFi hits file while the payload was running was picked up on the very next drain cycle and produced a correct on-screen `DRONE REMOTE ID` alert (title, MAC, decoded UAS ID, and transport all correct) -- confirming the full chain end to end: capture -> awk decode -> bash hit parsing -> cooldown/dedup -> `LOG`/`LED`/`RINGTONE`/`ALERT_RINGTONE`.
- Flock Safety detection is the original, untouched Flock-You code path, so it carries the same confidence as upstream.

## The one thing that's genuinely still unverified

Real-world timing and coverage against an actual Remote-ID-broadcasting drone (or a real Flock Safety device) -- neither was available during development. Every stage up to "a real target is nearby and broadcasting" has been checked against real captures and confirmed live on this hardware; what's left is just letting it run somewhere a real target actually shows up.

Loot: `/root/loot/flock_sky_spy/flock_you_<ts>.txt` (Flock hits, same format as upstream) and `/root/loot/flock_sky_spy/drone_rid_<ts>.txt` (every decoded drone message: time, transport, MAC, message type, fields).
