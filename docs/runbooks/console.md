<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: the console (development build)

This runbook is for the operator. It covers building Mooring.app, running the daemon that polls the M7, reading the console, and stopping both.

The design is §5.1, §10.1, §15.1 and §15.6. This is the development build: it runs from the repository's target directory, signed ad hoc, and the app registers the daemon it carries as a login item (`SMAppService`, M7), so it runs at every login until it is stopped from the app.

Before a deployment exists the console shows the M7 router only, and every other screen says it needs a deployment. Once `mooringctl exit init` has created one, the daemon serves the exit from its next poll (within a minute), with no restart: it resolves the egress, checks for foreign networks, meters the SIM and, once the exit is enabled and its preflight passes, runs `mooring-exit` (design §10.1, §10.2). The swap-day runbook (`swap-day.md`) covers that part. Mooring.app then shows the deployment's status on every screen (section 3); `mooringctl status --json` prints the same document.

With a deployment, the daemon reads each applied node's WireGuard key from the keychain the first time it starts the engine, and again after each configuration change: macOS asks once per key, as it does for the M7's password (section 2, question 1); choose **Always Allow**.

## 0. Once

The M7's identity, the Mac's interface to it and its admin password are recorded as for `router status`. Run these from Terminal.app's own shell, in the workspace root (design §15.6 rules 3, 4 and 10):

```
cargo xtask mooringctl
./target/signed/mooringctl router pin --interface en9
./target/signed/mooringctl router set-password
```

`en9` is the Mac's interface to the M7, the USB Ethernet adapter. Check it with `ifconfig`: it is the one with the address `192.168.1.x`. The pin records it, and the daemon polls the M7 on it until a deployment exists. A pin made before 2026-10-23 records no interface: run `router pin --interface en9` once more, which records it without asking again (the address is the same).

XcodeGen must be installed: `brew install xcodegen`.

## 1. Build

```
cargo xtask app
```

It builds `target/app/Mooring.app` with `mooringctl` inside it and the daemon's plist in `Contents/Library/LaunchAgents`, after:
- MooringKit's tests;
- Xcode's own check that the build, made clean, has no error or warning;
- a check that every string on screen has a Simplified Chinese translation, and so does the local network alert's text;
- a check that the daemon's plist in the app is `apple/App/LaunchAgents`' own.

Both are signed ad hoc with the hardened runtime. If the daemon is running (section 2), the build restarts it on the new `mooringctl` (`launchctl kickstart -k`), and macOS asks again for the keychain (section 2, question 1).

The app's language follows macOS.

## 2. Start the daemon

```
open target/app/Mooring.app
```

The app's menu (the antenna in the menu bar), and the banner above the console while the daemon is not started, offer **Start the Daemon at Login**. The app registers the daemon its bundle carries with macOS (`SMAppService`): launchd starts `mooringctl daemon` from the app at once and at every login, and keeps it running, until **Stop the Daemon** in the menu. macOS notifies that a background item was added; System Settings › General › Login Items lists it under Mooring. If macOS asks for approval first, the banner says so, and **Open Login Items…** opens that page: turn Mooring on there.

The daemon polls the M7 every 60 s on the interface the pin records (section 0). Its log is `~/Library/Logs/Mooring/daemon.log`, one line when it starts and one each time the poll's outcome changes; at 5 MiB it is renamed `daemon.log.1` (replacing the one before) and a new file begun. The daemon's last error, when it stops, is the log's last line.

On the first poll, macOS asks two questions. Allow both:
1. **The keychain:** "mooringctl wants to use your confidential information stored in "com.bill.mooring.dev"". Choose **Always Allow**; it asks for the Mac's login password. This is the M7's admin password, which only `mooringctl` reads.
2. **Local network:** "Mooring would like to find and connect to devices on your local network". Choose **Allow**. Without it the daemon's connection to the M7 fails with "host unreachable": macOS applies local network privacy to a LaunchAgent (design §5.1).

Rebuilding `mooringctl` changes its signature (it is signed ad hoc), and macOS asks again for the keychain. Rebuilding the app may ask again for local network access.

**Open Mooring at Login** in the menu makes the console open at login too.

**From the development agent.** Before 2026-10-23, `cargo xtask agent-install en9` ran the daemon from `target/launchd/`, under the same label. On a Mac that ran it, stop it and remove its plist once, before **Start the Daemon at Login**:

```
launchctl bootout gui/$(id -u)/com.bill.mooring.daemon
rm target/launchd/com.bill.mooring.daemon.plist
```

## 3. Open the console

```
open target/app/Mooring.app
```

The app lives in the menu bar (an antenna symbol); its menu opens the console window.

**The banner** at the top says where the stream stands, with the time the daemon made the status on screen:
- **Live:** the status on screen is the latest.
- **Waiting:** the daemon has not finished its first poll. It may be waiting for one of the questions above.
- **Not live: mooringctl stopped:** with how it ended and its own message. The app starts it again after 5 s. "The daemon's latest status is from …, more than 240 s ago" means the daemon's poll has not finished since: look for a keychain or local network question.
- **Not live: the latest status cannot be shown:** the daemon sent a line this build cannot show (for example a document of a newer version, from a daemon built from newer sources than the app); the status on screen is older.

**The router screen** lists first the settings the exit needs off that the M7 reports on (the Wi-Fi radio, Wi-Fi or Ethernet offload, UPnP, NETGEAR Insight), as the daemon decides them. It shows:
- what the M7 reports: network, service types, band, LTE carriers, signal, temperature, power, its own traffic counters, Wi-Fi and the settings the exit needs off, and the unread SMS count;
- the time of the poll.

The colours on RSRP and SINR are rules of thumb for placing the antenna, not limits.

**Once a deployment exists** every screen fills in from the deployment's status (design §15.3):
- **Overview:** the exit's state and why, the open alerts (critical first), each node's gate and latest REALITY and Hysteria2 verdicts, the SIM gauge, and the router.
- **Exit:** the state since when, latched violations with their evidence, the egress interface and link, the carrier check, `mooring-exit` and `mooring-probe`, the Mac's power and any foreign network.
- **SIM:** the billing cycle, bytes received and sent, the meter's accuracy, the warning, the stop policy and the plan's line, and the forecast with each threshold's crossing.
- **Nodes:** per node, its role, stage and generation, the in-chain verdicts, and its agent's report (gate, holds, halt, handshake and watch ages, conditions, engines, host and this month's transfer), or why it could not be polled.
- **Users:** one row per opaque id and alias; select a row for its figures, quota and expiry. When the daemon has no usage report the figures say "unavailable" with its reason, never zeros.
- **Capacity:** the egress rates, the uplink's use against its baseline, the loaded latency and saturation.
- **Events:** not read by this build; the open alerts are on the overview.

The app only shows: every change (`exit enable`, `node apply`, `user …`, `sim …`) is a `mooringctl` command in Terminal.

The same status is available in Terminal:
- `target/app/Mooring.app/Contents/MacOS/mooringctl status` prints it once;
- `… status --follow --json` prints each new status as one JSON line, as the app reads it (the app adds `--until-parent-exits`, so its follower ends with it).

## 4. Stop

**Stop the Daemon** in the app's menu: launchd stops it and no longer starts it at login. Quitting the app does not stop the daemon.

`cargo xtask clean` is refused while the daemon is loaded: it runs from the target directory that `clean` removes.

## Troubleshooting

**`the Mooring daemon is not running`:** the daemon is not started, or it stopped.
- Start it from the app's menu (section 2).
- Run `launchctl print gui/$(id -u)/com.bill.mooring.daemon` to see its state and last exit, and read the last lines of `~/Library/Logs/Mooring/daemon.log`.

**"The router adapter is not set up":** the M7 is not pinned, its password is not stored, or the pin records no interface (one made before 2026-10-23). The daemon's log names which; run section 0's command for it.

**The router screen says "The Mac could not poll the M7":** the keychain or the kernel's tables failed. The daemon's log names which.

**"The M7 is unreachable":** check the adapter and `ifconfig en9`. If the M7 answers `ping 192.168.1.1` from Terminal but the daemon cannot reach it, local network access was refused. Allow it under System Settings › Privacy & Security › Local Network, then wait for the next poll.

**"The M7 refused the login":** store the password again with `router set-password`, as in section 0.
