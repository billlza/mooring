<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: the console (development build)

This runbook is for the operator. It covers building Mooring.app, running the daemon that polls the M7, reading the console, and stopping both.

The design is §5.1, §10.1, §15.1 and §15.6 (revision 9). This is the development build: it runs from the repository's target directory, signed ad hoc, and the daemon runs until logout. M7 replaces this with a signed app that registers the daemon itself (`SMAppService`).

Before a deployment exists the console shows the M7 router only, and every other screen says it needs a deployment. Once `mooringctl exit init` has created one, the daemon serves the exit from its next poll (within a minute), with no restart: it resolves the egress, checks for foreign networks, meters the SIM and, once the exit is enabled and its preflight passes, runs `mooring-exit` (design §10.1, §10.2). The swap-day runbook (`swap-day.md`) covers that part. Mooring.app does not show a deployment's status yet (M7); `mooringctl status --json` prints it.

With a deployment, the daemon reads each applied node's WireGuard key from the keychain the first time it starts the engine, and again after each configuration change: macOS asks once per key, as it does for the M7's password (section 2, question 1); choose **Always Allow**.

## 0. Once

The M7's identity and admin password are recorded as for `router status`. Run these from Terminal.app's own shell, in the workspace root (design §15.6 rules 3, 4 and 10):

```
cargo xtask mooringctl
./target/signed/mooringctl router pin --interface en9
./target/signed/mooringctl router set-password
```

`en9` is the Mac's interface to the M7, the USB Ethernet adapter. Check it with `ifconfig`: it is the one with the address `192.168.1.x`.

XcodeGen must be installed: `brew install xcodegen`.

## 1. Build

```
cargo xtask app
```

It builds `target/app/Mooring.app` with `mooringctl` inside it, after:
- MooringKit's tests;
- Xcode's own check that the build, made clean, has no error or warning;
- a check that every string on screen has a Simplified Chinese translation, and so does the local network alert's text.

Both are signed ad hoc with the hardened runtime. If the daemon is running (section 2), the build restarts it on the new `mooringctl`, and macOS asks again for the keychain (section 2, question 1).

The app's language follows macOS.

## 2. Start the daemon

```
cargo xtask agent-install en9
```

This runs `mooringctl daemon --router-interface en9` as a LaunchAgent until logout. It polls the M7 every 60 s. Its log is `~/Library/Logs/Mooring/daemon.log`, one line when it starts and one each time the poll's outcome changes.

If the agent is already loaded, the command stops it first and starts the new one once launchd no longer lists the old one. It waits up to 10 s for that, and otherwise stops and says so.

On the first poll, macOS asks two questions. Allow both:
1. **The keychain:** "mooringctl wants to use your confidential information stored in "com.bill.mooring.dev"". Choose **Always Allow**; it asks for the Mac's login password. This is the M7's admin password, which only `mooringctl` reads.
2. **Local network:** "Mooring would like to find and connect to devices on your local network". Choose **Allow**. Without it the daemon's connection to the M7 fails with "host unreachable": macOS applies local network privacy to a LaunchAgent (design §5.1).

Rebuilding `mooringctl` changes its signature (it is signed ad hoc), and macOS asks again for the keychain. Rebuilding the app may ask again for local network access.

## 3. Open the console

```
open target/app/Mooring.app
```

The app lives in the menu bar (an antenna symbol); its menu opens the console window.

**The banner** at the top says where the stream stands, with the time the daemon made the status on screen:
- **Live:** the status on screen is the latest.
- **Waiting:** the daemon has not finished its first poll. It may be waiting for one of the questions above.
- **Not live: mooringctl stopped:** with how it ended and its own message. The app starts it again after 5 s. "The daemon's latest status is from …, more than 240 s ago" means the daemon's poll has not finished since: look for a keychain or local network question.
- **Not live: the latest status cannot be shown:** the daemon sent a line this build cannot show (for example a deployment's status); the status on screen is older.

**The router screen** lists first the settings the exit needs off that the M7 reports on (the Wi-Fi radio, Wi-Fi or Ethernet offload, UPnP, NETGEAR Insight), as the daemon decides them. It shows:
- what the M7 reports: network, service types, band, LTE carriers, signal, temperature, power, its own traffic counters, Wi-Fi and the settings the exit needs off, and the unread SMS count;
- the time of the poll.

The colours on RSRP and SINR are rules of thumb for placing the antenna, not limits.

The same status is available in Terminal:
- `target/app/Mooring.app/Contents/MacOS/mooringctl status` prints it once;
- `… status --follow --json` prints each new status as one JSON line, as the app reads it (the app adds `--until-parent-exits`, so its follower ends with it).

## 4. Stop

```
cargo xtask agent-uninstall
```

Quit the app from its menu. Quitting the app does not stop the daemon; this command does.

`cargo xtask clean` is refused while the daemon is loaded: it runs from the target directory that `clean` removes.

## Troubleshooting

**`the Mooring daemon is not running`:** the agent is not loaded.
- Run `cargo xtask agent-install en9` again.
- Run `launchctl print gui/$(id -u)/com.bill.mooring.daemon` to see its state and last exit.

**The router screen says "The Mac could not poll the M7":** the keychain or the kernel's tables failed. The daemon's log names which.

**"The M7 is unreachable":** check the adapter and `ifconfig en9`. If the M7 answers `ping 192.168.1.1` from Terminal but the daemon cannot reach it, local network access was refused. Allow it under System Settings › Privacy & Security › Local Network, then wait for the next poll.

**"The M7 refused the login":** store the password again with `router set-password`, as in section 0.
