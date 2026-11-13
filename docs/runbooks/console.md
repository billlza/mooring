<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: the console (development build)

This runbook is for the operator. It covers building Mooring.app, running the daemon that polls the M7, reading the console, and stopping both.

The design is §5.1, §10.1, §15.1 and §15.6. This is the development build: it is built in the repository's target directory, signed ad hoc, and installed to `~/Applications/Mooring.app`, and the app registers the daemon it carries as a login item (`SMAppService`, M7), so it runs at every login until it is stopped from the app.

The installed app carries the `mooringctl` the daemon runs. Below, `mooringctl` is that one, `~/Applications/Mooring.app/Contents/MacOS/mooringctl`, run from Terminal.app's own shell (design §15.6 rules 3, 4 and 10): the command line and the daemon are then one build, and what it stores in the keychain is the daemon's to read.

Before a deployment exists the console shows the M7 router only, and every other screen says it needs a deployment. Once `mooringctl exit init` has created one, the daemon serves the exit from its next poll (within a minute), with no restart: it resolves the egress, checks for foreign networks, meters the SIM and, once the exit is enabled and its preflight passes, runs `mooring-exit` (design §10.1, §10.2). The swap-day runbook (`swap-day.md`) covers that part. Mooring.app then shows the deployment's status on every screen (section 3); `mooringctl status --json` prints the same document.

With a deployment, the daemon reads each applied node's WireGuard key from the keychain the first time it starts the engine, and again after each configuration change: macOS asks once per key, as it does for the M7's password (section 2, question 1); choose **Always Allow**.

## 0. Once

The M7's identity, the Mac's interface to it and its admin password are recorded as for `router status`. Build and install the app first (section 1), then run these from Terminal.app's own shell (design §15.6 rules 3, 4 and 10):

```
~/Applications/Mooring.app/Contents/MacOS/mooringctl router pin --interface en9
~/Applications/Mooring.app/Contents/MacOS/mooringctl router set-password
```

`en9` is the Mac's interface to the M7, the USB Ethernet adapter. Check it with `ifconfig`: it is the one with the address `192.168.1.x`. The pin records it, and the daemon polls the M7 on it until a deployment exists. A pin made before 2026-10-23 records no interface: run `router pin --interface en9` once more, which records it without asking again (the address is the same).

XcodeGen must be installed: `brew install xcodegen`.

## 1. Build and install

```
cargo xtask app
cargo xtask install
```

`app` builds `target/app/Mooring.app` with `mooringctl` inside it, the power helper `mooring-power` beside it, and the daemon's plist in `Contents/Library/LaunchAgents`, after:
- MooringKit's tests;
- Xcode's own check that the build, made clean, has no error or warning;
- a check that every string on screen has a Simplified Chinese translation, and so does the local network alert's text;
- a check that the daemon's plist in the app is `apple/App/LaunchAgents`' own.

The app, `mooringctl` and the helper are each signed ad hoc with the hardened runtime, and the build checks each one's identifier.

`install` moves that app to `~/Applications/Mooring.app`, which the daemon is started from, so the target directory holds nothing the daemon runs: it can be cleaned (`cargo xtask clean`, or a plain `cargo clean`), and the app built again, while the daemon serves. It checks the build's signatures, copies the app, checks the copy, puts it in place of the app installed before and removes the build's app.

**Open only the installed app.** macOS records the daemon, and **Open Mooring at Login**, for the path of the app they are chosen in (design §5.1). An app under `target/` (the build's, between `app` and `install`, or Xcode's own product under `target/apple/`) would record them for the target directory.

`install` is refused while the daemon is registered (section 2), and while Mooring.app is open or a `mooringctl` command started from it still runs (**Quit Mooring** in its menu). launchd starts only the `mooringctl` the daemon was registered with (an ad-hoc signature is pinned by its cdhash), so one installed over it would not start. To install a new build, run `cargo xtask app` first, while the daemon still serves; then choose **Stop the Daemon**, quit the app, run `cargo xtask install`, open the installed app and choose **Start the Daemon at Login**. If the daemon was registered from another build, macOS refuses that first start: it keeps the stopped daemon's record, with the earlier build's launch constraint, and kills the new `mooringctl`. The same holds for the apply job, at its own first start (section 7).

**An app built since 2026-11-13 carries the start through by itself** (design §5.1, "The app carries a start through"; not deployed when this was written; against launchd it has run only where it reads, and its starts by hand and its registering again only against a stand-in in the tests, so the first start of the first build that carries it is its test). The banner above the console says **Starting a new build of Mooring**, and the menu **Daemon: a new build; waiting for macOS, about a minute and a half**. The app waits for launchd's second start of the daemon, a minute after the first, starts the apply job by hand meanwhile, 5 s and 25 s after the click, then, 20 s after macOS has replaced the daemon's record, unregisters and registers both, and the banner goes once the daemon has run for 2 s: about a minute and a half in all. Leave it alone: **Stop the Daemon** ends the round where it is, and nothing is registered after it. Do not install a new build between 19:15 and 19:45 UTC: a job that macOS does not refuse runs when the app starts it, which inside that window is the night's run, made while the daemon is still refused (section 7). The round does not register again under a running job: it waits for the job to end, and gives up after 240 s in all. macOS asks again for the keychain (section 2, question 1) and may ask for local network access. Then check both:

```
launchctl print gui/$(id -u)/com.bill.mooring.daemon | grep -E '^\s(state|runs|last exit code|job state) ='
launchctl print gui/$(id -u)/com.bill.mooring.apply | grep -E '^\s(state|runs|last exit code|job state) ='
```

The daemon shows `state = running`. The job shows `runs = 0` and `last exit code = (never exited)` until its first minute 20, and `last exit code = 0` after it.

**If the banner says "The start of the daemon and the apply job was not completed"**, it gives the reason, and **Try Again** runs the round again from what launchd shows. The steps by hand, which every build before needed, still work: `launchctl print gui/$(id -u)/com.bill.mooring.daemon` shows `job state = spawn failed`, and about a minute after the start, once launchd has had the record replaced, `last exit code = 78: EX_CONFIG`. During that minute, start the apply job by hand twice, about 20 s apart: `launchctl kickstart gui/$(id -u)/com.bill.mooring.apply`. The command prints nothing; launchd refuses both starts, the second with exit code 78, and has the job's record replaced as well (measured on 2026-11-13 with a throwaway app, not yet with Mooring's own job: section 7). Without them the job stops running after a new build. Then, once `launchctl print` shows `last exit code = 78: EX_CONFIG` for the daemon and for the job, choose **Stop the Daemon** and **Start the Daemon at Login** again: the daemon starts.

**A daemon started from the build** runs from `target/app/Mooring.app`, where every daemon was started from until `cargo xtask install` existed (2026-11-10). While it does, `cargo xtask app` and `cargo xtask clean` are refused, as they were, and a plain `cargo clean` would delete the app under it. Move it over once:

1. In the app that is open, the build's: switch **Open Mooring at Login** off if it is on, choose **Stop the Daemon**, and quit the app.
2. Run `cargo xtask install`: the app in the target directory is the build that was running. To install a newer build, run `cargo xtask app` first; it is no longer refused once the daemon is stopped.
3. `open ~/Applications/Mooring.app` and choose **Start the Daemon at Login**. As after a change of build, an app built since 2026-11-13 carries the start through in about a minute and a half (above). With an earlier one, once `launchctl print` shows `last exit code = 78: EX_CONFIG` about a minute later, choose **Stop the Daemon** and **Start the Daemon at Login** once more. Then switch **Open Mooring at Login** on again if it was on.
4. Check where the daemon runs from. The second command must name `~/Applications/Mooring.app/Contents/MacOS/mooringctl`:

   ```
   launchctl print gui/$(id -u)/com.bill.mooring.daemon | grep -E '^\s(state|pid|last exit code) ='
   codesign -dv +<pid> 2>&1 | grep '^Executable='
   ```

This first start from another place than the build was made once, on 2026-11-13 (design §5.1), and went as a change of build does: the first **Start the Daemon at Login** was refused, `last exit code = 78: EX_CONFIG` showed a minute later, and the next **Stop the Daemon** and **Start the Daemon at Login** ran the daemon from the installed app. **Open Mooring at Login** had moved to the installed app by itself when that app was first opened. A **Stop the Daemon** before the 78 loses the round: nothing is registered after it, and nothing more happens until the next **Start the Daemon at Login**. If the daemon still has no process after the second **Start the Daemon at Login**, keep what `launchctl print` shows and the last lines for `com.bill.mooring.daemon` in `/var/log/com.apple.xpc.launchd/launchd.log`, and go back: **Stop the Daemon**, quit the app, run `cargo xtask app`, `open target/app/Mooring.app`, and start the daemon there, as before.

The app's language follows macOS.

## 2. Start the daemon

```
open ~/Applications/Mooring.app
```

The app's menu (the antenna in the menu bar), the **Daemon** menu in the console window's toolbar, and the banner above the console while the daemon is not started, offer **Start the Daemon at Login**. The two menus hold the same items, so a menu bar manager that hides the antenna hides nothing the console window lacks. The app registers the daemon its bundle carries with macOS (`SMAppService`): launchd starts `mooringctl daemon` from the app at once and at every login, and keeps it running, until **Stop the Daemon** in either menu. macOS notifies that a background item was added; System Settings › General › Login Items lists it under Mooring. If macOS asks for approval first, the banner says so, and **Open Login Items…** opens that page: turn Mooring on there. An app built since 2026-11-13 then reads launchd's records until the daemon has run for 2 s, and its banner says what it waits for; after a new build that takes about a minute and a half (section 1).

The daemon polls the M7 every 60 s on the interface the pin records (section 0). Its log is `~/Library/Logs/Mooring/daemon.log`, one line when it starts and one each time the poll's outcome changes; at 5 MiB it is renamed `daemon.log.1` (replacing the one before) and a new file begun. The daemon's last error, when it stops, is the log's last line.

On the first poll, macOS asks two questions. Allow both:
1. **The keychain:** "mooringctl wants to use your confidential information stored in "com.bill.mooring.dev"". Choose **Always Allow**; it asks for the Mac's login password. This is the M7's admin password, which only `mooringctl` reads.
2. **Local network:** "Mooring would like to find and connect to devices on your local network". Choose **Allow**. Without it the daemon's connection to the M7 fails with "host unreachable": macOS applies local network privacy to a LaunchAgent (design §5.1).

Rebuilding `mooringctl` changes its signature (it is signed ad hoc), so a new build is installed with the daemon stopped (section 1), and macOS asks again for the keychain. Installing a new build may ask again for local network access.

**Open Mooring at Login** in the menu makes the console open at login too. macOS records it for the app it is chosen in, so choose it in the installed app.

**Power, with a deployment.** The daemon starts the power helper from the app (`Contents/MacOS/mooring-power`) and does not start without it. While the exit is enabled and the Mac is on mains, the helper holds two assertions that keep the Mac awake; `pmset -g assertions` lists them as "Mooring exit". On battery it releases them and the exit is `Degraded` (`OnBattery`). Mooring never changes `pmset` settings.

If the Mac sleeps anyway (the lid closed, or Sleep chosen from the Apple menu), the daemon first stops `mooring-exit`, then asks each node to close its gate for the drain, within 4 s in all, and lets the sleep proceed. The exit is `Paused` until the Mac wakes, and then it probes and starts again. The Exit screen shows the last sleep, the drain's outcome and the last wake. A drain that timed out or failed is no fault in itself: each node notices the Mac's silence within about 30 s.

**From the development agent.** Before 2026-10-23, `cargo xtask agent-install en9` ran the daemon from `target/launchd/`, under the same label. On a Mac that ran it, stop it and remove its plist once, before **Start the Daemon at Login**:

```
launchctl bootout gui/$(id -u)/com.bill.mooring.daemon
rm target/launchd/com.bill.mooring.daemon.plist
```

## 3. Open the console

```
open ~/Applications/Mooring.app
```

The app lives in the menu bar (an antenna symbol); its menu opens the console window.

**The banner** at the top says where the stream stands, with the time the daemon made the status on screen:
- **Live:** the status on screen is the latest.
- **Waiting:** the daemon has not finished its first poll. It may be waiting for one of the questions above.
- **Not live: mooringctl stopped:** with how it ended and its own message. The app starts it again after 5 s. "The daemon's latest status is from …, more than 240 s ago" means the daemon's poll has not finished since: look for a keychain or local network question.
- **Not live: the latest status cannot be shown:** the daemon sent a line this build cannot show (for example a document of a newer version, from a daemon built from newer sources than the app); the status on screen is older.

**The router screen** lists first the settings the exit needs off that the M7 reports on (the Wi-Fi radio, Wi-Fi or Ethernet offload, UPnP, NETGEAR Insight), as the daemon decides them. It shows:
- what the M7 reports: network, service types, band, LTE carriers, signal, temperature, power, its own traffic counters, Wi-Fi and the settings the exit needs off, and the unread SMS count;
- the time of the poll;
- **Signal history:** RSRP and SINR over the last 24 hours (LTE and NR; a gap in the readings breaks the line), the changes between polls (a failed poll and its recovery, a reboot, no service and its return, a service, band or network change, a session restart), and a note when today's file ends in a line the daemon is still writing. It comes from the samples the daemon records at every poll (`~/Library/Application Support/Mooring/radio/<UTC day>.jsonl`, the newest 90 days kept); **Reload** runs `mooringctl router history --json` again.

The colours on RSRP and SINR are rules of thumb for placing the antenna, not limits.

**Once a deployment exists** every screen fills in from the deployment's status (design §15.3):
- **Overview:** the exit's state and why, the open alerts (critical first), each node's gate and latest REALITY and Hysteria2 verdicts, the SIM gauge with the billing cycle it covers, above it the notice when the M7 reports another SIM or network than the one on record, and the router.
- **Exit:** the state since when, latched violations with their evidence, the egress interface and link, the carrier check (with that notice above it), `mooring-exit` and `mooring-probe`, the Mac's power and any foreign network.
- **SIM:** the SIM and network on record against what the M7 reports now (with that notice when they differ), the billing cycle, bytes received and sent, the meter's accuracy, the warning, the stop policy and the plan's line, and the forecast with each threshold's crossing.
- **Nodes:** per node, its role, stage and generation, the in-chain verdicts, and its agent's report (gate, holds, halt, handshake and watch ages, conditions, engines, host and this month's transfer), or why it could not be polled.
- **Users:** one row per opaque id and alias; select a row for its figures, quota and expiry. A daemon built since 2026-11-05 reads the nodes' usage. When it has no usage report, the screen says "Usage unavailable" with its reason, never zeros. A daemon built before reads none, so the screen says so and the figures say "not read". Status, activity and last seen are live either way.
- **Capacity:** the egress rates, the uplink's use against its baseline, the loaded latency and saturation.
- **Events:** not read by this build; the open alerts are on the overview.

**A latched violation** (design §10.2). When an egress check fails, the exit stops itself, has every node close its gate and stays down until the latch is cleared. It is a finding about the line, not about what you did. The overview and the Exit screen say:
- what the check found, for example that the egress address is outside the carrier prefixes recorded for this line;
- what to do about it, by what was found: for an address outside the prefixes, record the new prefixes if the SIM or the carrier's pool changed, or turn the M7's offload off, then `mooringctl exit retry` (`swap-day.md`, section 3). The overview has it under the exit's state, the Exit screen under each latch;
- when it was found, which is the latch's own time: "Found …" on the overview, "Violation found" on the Exit screen. The state's "Since" can be later: the state starts anew when the daemon restarts, and when another reason held the exit down in front of the latch (a foreign network, the M7 unplugged). Until 2026-11-12 the overview showed only that later time, and a latch two days old read as a new event.

While a latch is set the daemon runs no direct probe, so the address shown is the one it latched: after a SIM swap it is still the old SIM's.

**A latch behind another reason.** The daemon looks at a latch only after it has found the exit enabled, the SIM's plan recorded and its use under the stop, the egress interface there, no foreign network and a carrier check recorded (design §10.2), and a sleeping Mac's exit is paused whatever is latched. While one of those holds the exit down, the state names that reason and not the latch. The overview then says in a second line, in orange, that a violation found at the latch's time is latched as well and will keep the exit down once the reason above is gone; the Exit screen lists it under "Latched violations" with what to do. `mooringctl exit retry` clears a latch whatever the state shows, so the cause can be dealt with before the other reason is gone. Until 2026-11-12 the overview named only the reason in front: from 2026-11-10 22:45 UTC it showed a foreign network for a day and a half, over a latch written a minute before.

**The SIM gauge**, on the overview and on the SIM screen, names the first day of the cycle its figure covers and of the next one (UTC). The meter counts this Mac's traffic through the M7, whichever SIM is in it. After a SIM change the figure therefore still holds what the old SIM carried, until `mooringctl sim set-anchor` moves the cycle to the day the new plan started (`swap-day.md`, section 2, step 5).

**The SIM and network on record** (design §10.2). The carrier check and the billing cycle are records about one SIM, and nothing in the deployment ties them to it. So the daemon keeps its own record of what the M7 reported, the SIM's name (or that it has none) and the network's codes, at the first poll that found it attached after either was last recorded, and compares every later poll with it. The SIM screen shows it under "SIM and network": what is on record, when the M7 first reported it (or, after `mooringctl sim accept-network`, when it was taken), and what it reports now.

While the M7 reports something else, the overview's SIM card, the SIM screen and the Exit screen's carrier check show one notice in orange:
- "The M7 reports another SIM than the one on record" when the SIM's name differs (a name where there was none counts), or "another network" when the name is the same, or absent both times, and only the network's codes differ. The second also happens when a carrier moves one SIM to another of its networks, and the text says so;
- what the M7 reports and since when, and what the check and the cycle on record go with;
- what to do if the SIM was changed: both records are the old SIM's, so record them for the new one (`swap-day.md`, section 2, steps 3 to 6: `exit disable`, `exit observe`, `exit record-carrier --replace`, `sim set-anchor`, `node apply` for each node, `exit enable`);
- the command for when both records are right for the SIM now in the M7 (`mooringctl sim accept-network`, below), and what ends the notice.

The notice changes nothing by itself: the exit is not stopped or degraded for it. It ends when the carrier check or the cycle is recorded with other values (the daemon then takes what the M7 reports at its next attached poll as the one on record), or when the M7 reports the one on record again. Recording the same prefixes and pairing again, or an anchor on which a cycle already starts, does not end it; the command below does.

**Taking the network the M7 reports as the one on record** (2026-11-12). If the SIM was changed and neither record needs other values (two brands on one network's address pool, with the same bill day), or a carrier renamed the SIM or moved it to another network for good, both records are right as they are. Say so in Terminal:
```
mooringctl sim accept-network
```
It prints what the daemon holds and asks, for example:
```
on record: a SIM without a name (234-20), first reported 2026-10-30 09:12:00 UTC
the M7 reports: 1p (234-30), at the daemon's poll of 2026-11-12 19:31:00 UTC
another network than the one on record since 2026-11-11 18:40:00 UTC
Take 1p (234-30) as the SIM's network on record? The carrier check and the billing cycle stay as they are. [y/N]
```
Check the second line against the SIM that is in the M7, then answer `y` (`--yes` skips the question). The daemon takes that network and no other: if the M7 reports something else by then, or the daemon's latest poll did not find it attached, it refuses and says which. Its answer starts `taken: 1p (234-30) is the SIM's network on record now`; the notice ends with the daemon's next status, within about 10 s, and the SIM screen then shows the time under "Taken on record" and says that the check and the cycle were not recorded again for it.

The command changes the daemon's record of the SIM's network and nothing else: not the carrier check, the billing cycle, a latch or the exit's state, and the exit serves through it. It is not the step to take when the SIM was changed and either record is the old SIM's: record them then (`swap-day.md`, section 2). When it takes nothing it says why and exits 1:
- `no network was taken: there is no network other than the one on record`: the M7 reports the one on record, or no poll has found it attached since the record began. There is no notice to end;
- `no network was taken: the latest poll of the M7 did not find it attached`: wait until the M7 has a data service again (`mooringctl router status`), then run it again;
- `the daemon refused the request: the M7 no longer reports the network that was to be taken`: its report changed between the lines above and your answer. Run it again and read the lines anew;
- `the daemon refused the request: its loop did not come to the request in time; nothing was changed, try again`: the daemon's loop was held up, as it is while it polls a node or waits at a keychain prompt;
- `there is no deployment yet …`, or `the Mooring daemon is not running`: there is no record to change, or no daemon to change it.

The first two are the command's own reading of the status it printed. When the daemon finds the same after your answer, the sentence starts `the daemon refused the request:` and ends in the same words.

Before this command the only way was to stop the daemon and remove `~/Library/Application Support/Mooring/run/sim-network.json`, which stopped the exit for that long; it is no longer needed.

What it cannot see:
- two SIMs of one carrier report the same name and codes, and raise nothing. The daemon never reads the card's number (ICCID) or the subscriber's (IMSI);
- a SIM changed before the record began. The SIM screen says under "SIM and network" where the record began: at the first attached poll after the check or the cycle was last recorded; or at your word, with `sim accept-network`; or after the daemon started without a record, which is the first run of a build that keeps one (2026-11-12); or after a record it could not read, which it says in its log and begins again. In the last two, what is on record is the SIM that was in the M7 then, whichever SIM the check and the cycle were recorded for. The swap of 2026-11-11 is such a case: the build that first keeps the record takes the new SIM as the one on record and shows no notice, though the check and the cycle were still the old SIM's;
- a SIM without a data session: the M7 names no network then, and nothing is compared until it attaches.

The daemon's log (`~/Library/Logs/Mooring/daemon.log`) has a line starting `sim network:` for each change: the record begun, the network taken as the one on record (at a poll, or at the operator's word with `sim accept-network`, which names the network it replaced), another network reported, the one on record reported again, a record that could not be read or written.

The app only shows: every change (`exit enable`, `node apply`, `user …`, `sim …`) is a `mooringctl` command in Terminal.

The same status is available in Terminal:
- `mooringctl status` prints it once (the installed app's `mooringctl`, as everywhere in this runbook);
- `… status --follow --json` prints each new status as one JSON line, as the app reads it (the app adds `--until-parent-exits`, so its follower ends with it);
- `… router history` prints yesterday's and today's radio samples (UTC) as a summary: a header per day, the changes between polls, and the hourly signal; `--since <day>` and `--until <day>` choose the days (at most 90), `--json` prints the document the app reads. It reads the daemon's files and never the M7, so it works while the daemon is stopped.

### Layout regression preview

`apple/LayoutPreview` is a separate, Debug-only app that compiles the real
console views and decodes the repository's `serving.json` fixture. Its bundle
identifier and preferences are separate. It runs no `mooringctl`, reads no
deployment or Keychain, and replaces the daemon controls with an explicit
unavailable result. It is not a deployment or a live-service acceptance test.

Build it without stopping the serving daemon:

```sh
xcodegen generate --quiet --spec apple/LayoutPreview/project.yml
xcrun xcodebuild -quiet -project apple/LayoutPreview/MooringLayoutPreview.xcodeproj \
  -scheme MooringLayoutPreview -configuration Debug \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath target/layout-preview \
  CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=YES build
open target/layout-preview/Build/Products/Debug/MooringLayoutPreview.app
```

Use the fixture picker for unavailable usage, a usage report, no users, a
retry countdown (a simulated command exit; the preview runs no command), a
latched violation (the exit down for an address outside the carrier prefixes,
found 36 hours before the state's "Since") and a latch behind another reason
(the same latch, with the exit down for a foreign network on en0). For those
two, check the overview's exit card and the Exit screen.
Four more show the SIM's network: **SIM changed** (the M7 reports a SIM
named 1p on 234-30 where a SIM without a name on 234-20 is on record),
**Network changed, same SIM name** (a SIM without a name on 234-10), **No
network on record yet** (a record begun again after one that could not be
read) and **Network taken at the operator's word** (the fixture's network,
taken with `sim accept-network` ten minutes before the status). For the
first two, check the notice on the overview's SIM card, on the SIM screen
and above the Exit screen's carrier check; for all four, the "SIM and
network" section of the SIM screen and its footnote, and for the last the
time's label, "Taken on record".
A second picker, **Daemon**, shows the banner above the screens and the
Daemon menu for each state of the daemon's registration and start: not
started, waiting for approval, the apply job not started beside a started
daemon, a start waiting for launchd, the round of a new build, the apply
job's repair, a refused daemon, a refused apply job, a start that was not
completed, and records that tell nothing. The preview registers nothing and
runs no `launchctl`.
Check the column titles and first row on screen, select a user, switch pages,
and change to **No users** while its inspector is open. The inspector must
close, and restoring the users must not restore a stale selection. Check both
the ordinary and zoomed window. An accessibility tree that contains the text
does not establish that the pixels are visible.

On macOS 27.2 (2026-11-04), the former table-local `.inspector` reproducibly
created an additional titlebar background at the table's origin, covering the
header and first row. A one-point inset and hiding the table's scroll-edge
effect did not fix it. `ConsoleView` now owns the selection and attaches the
inspector to the whole detail pane, including its banners. This placement was
checked on screen with the real views and fixture data; the shipped daemon and
app bundle were not replaced. The stream banner schedules a per-second update
only for a retry countdown; live status is updated by the model.

## 4. Stop

**Stop the Daemon** in the app's menu or the console's **Daemon** menu: launchd stops it and no longer starts it at login. Quitting the app does not stop the daemon.

`cargo xtask install` is refused while the daemon is registered. `cargo xtask app` and `cargo xtask clean` are refused only while it runs from the target directory, as a daemon started from the build does, or while launchd has not got it running, since nothing then tells where it runs from (section 1). A daemon started from the installed app does not hold them up.

## 5. Your own networks (2026-10-29)

The exit goes down while this Mac is joined to any network other than the M7's (design §10.2, P0-2): campus Wi-Fi, eduroam, campus Ethernet, another VPN's tunnel, a VM bridge. Two attachments are allowed: CFM's own tunnel in TUN mode, told by its addresses, and a connection you contract for yourself (your own phone's Personal Hotspot, your home broadband), which you declare once while the Mac is joined to it:

```
mooringctl exit allow-network --interface en0 --name "my phone" --personal-hotspot
mooringctl exit allowed-networks
mooringctl exit disallow-network --name "my phone"
```

`en0` is the interface joined to the network (`ifconfig`: the one with the hotspot's `172.20.10.x` address). The command prints the network's router and its link-layer address, which identify the network (the SSID cannot be read on macOS 27, so `--name` is your label only), states the policy and asks before it records anything. It refuses the interface that faces the M7, a network whose router is not resolved yet (wait a few seconds after joining), a hotspot whose router is not Apple's `172.20.10.1`, and any network on a `.ac.uk` domain: an institutional network is never allowed, whatever is declared. It also refuses, before asking, a declaration the file cannot hold (about 85 networks, 16 KiB): `exit disallow-network` withdraws one first. Each medium of the phone (Wi-Fi, USB, Bluetooth) shows another address and is declared on its own.

`exit disallow-network` takes effect at the daemon's next tick, within 2 s: withdrawn while the Mac is joined to that network, the exit goes down on that tick as `ForeignNetworkAttached` and its engines are stopped; declared again, they start at the next tick and serve once the 10 s start grace has passed and the first in-chain probe, due then, has verified the address (`Starting`, then `Verifying`, until then; the L6-own lane's acceptance step, design §16, run 2026-10-30: withdrawn 00:40:01, down 00:40:02, declared 00:40:03, serving 00:40:14 UTC). To rename the network you are joined to, or change its kind, without that: allow it under the new name first, then withdraw the old one; the same router may be declared under two names. The daemon's log records a change of the declarations it reads by counts only, `the own-network declarations changed: 1 declared, now 0`, so the log says when a network was declared or withdrawn and names none.

With the network declared the exit stays `Serving` while the Mac is joined to it, even when it holds the default route (every exit connection is bound to the M7, design §10.4), and the console's Exit screen lists it under **Allowed networks**. The declaration is Mac-local (`allowed-networks.json` beside `state.json`); if it cannot be read the daemon treats it as none, the network becomes foreign again and the exit shows `Degraded` with `own networks unreadable` while it serves: `exit allowed-networks` names the fault. The store never writes a file it would refuse to read, so that fault is a hand edit (or a file past its 16 KiB bound): mend or remove `~/Library/Application Support/Mooring/allowed-networks.json` by hand and declare the networks again.

## 6. Payments from the portal (2026-11-11)

Once the portal sells plans through Stripe, the daemon asks it every five minutes for the orders to grant and records what it grants in `payments/ledger.json` (design §9.6, `docs/portal-contract.md` §5). Nothing in `state.json` changes: a user's expiry and quota as the console and the portal snapshot show them include what they paid for.

On the portal's host, make the token; it is printed once:

```
mooring-portal --db <file> pull-token
```

On this Mac, point the pull at the portal and paste the token at the prompt (it is not echoed), or pipe it in with `--stdin`:

```
mooringctl portal connect --origin https://<the portal's name>
mooringctl portal payments
```

`portal payments` prints the pull's settings, the cursor, the last pull and any stop, and every order with what Mooring did: a service period, a traffic pack for that billing cycle, or why a grant was held. Refunds and disputes are listed. A dispute changes nothing and never suspends the user, as you decided on 2026-11-11; answer it at Stripe. A refund in full takes back, from the time the portal recorded it, what the order gave that the user had not used yet, as you decided on 2026-11-12: the rest of a month (all of it if it had not begun), with any month queued after it moved as much earlier, and of a pack what the user had not used of it at the refund's time. A pack's refund first waits for the usage: the pack counts in full until the usage the daemon collects reaches a few minutes past the refund's time, which is within about ten minutes of the refund when the usage is current and later while a node cannot be reached. Traffic that cannot be placed after the refund counts as used. A REALITY download that was open at the refund is counted only when its connection closes, and a node cannot tell it from one begun later. So, as you decided on 2026-11-12, what a node counts of the user's REALITY downloads after the refund counts as used at the refund too, until that node's Xray has started again (a `node apply` that changes its configuration, as the nightly run's is when it suspends or resumes someone there, or the node's restart after an upgrade) or the billing cycle ends. That costs you this: until then the user may be given up to the refunded pack's bytes once more, as REALITY downloads, which a pack they buy later is not charged for. By itself it keeps nobody in service: unless they buy another pack or you raise their quota, a user whose use has reached their quota without the pack is suspended at the next nightly run all the same. You decided the same day to keep it without a time limit: a limit would again count a download open longer than it after the refund. If the usage has a fault, and is not merely behind, `daemon.log` says so once, by the fault's kind, and the refund waits on. If the pack's billing cycle ends first, nothing of it is taken back. What a user used is not recovered, so a pack bought later does not pay for it. The next nightly run suspends the user at expiry or for quota if that leaves them there. A partial refund changes nothing. `portal payments` shows under each order what each refund took back, marks each refund that still waits for the usage and each whose pack still takes in REALITY downloads, with the nodes, and counts both; the log has a line when a refund is recorded, one when its wait ends, and one when a node's Xray has started again or the cycle has ended, by the order alone (design §9.6). A traffic pack counts only in the billing cycle it was granted in, as you decided on 2026-11-12: what the user has not used of it when that cycle ends is not carried over, and the days its plan names are only recorded.

- **Rehearse first.** In Stripe's test mode the portal's journal says so, and Mooring grants nothing from it unless you rehearse: `mooringctl portal rehearsal on`, pay with Stripe's test cards, check `portal payments` and the console, then `mooringctl portal rehearsal off`, which takes the rehearsal's grants out at once, and `mooring-portal discard-test-payments` on the portal's host before real payments are taken. The cursor carries on.
- **It pulls only while the Mac is on no foreign network** (the pull goes the Mac's own way, so never over campus Wi-Fi or eduroam). The daemon's log says when it waits.
- **A stop** (the portal answered 409, 401 or 400, or a page contradicted the ledger) holds until you change the pull's settings: `portal connect` again (with a new token after a 401), or `portal rehearsal`. The log line names the reason. After a 409 the portal's journal is not the one pulled before (a database restored from a backup, say): find out which journal is right before connecting again; Mooring never lowers its cursor.
- **A held grant** (`unknown_user`, `user_revoked`) names a payment Mooring did not grant: refund it at Stripe.
- `mooringctl portal disconnect` stops the pull and deletes the token; the ledger stays, and what it granted still counts.

The daemon's log has a line for each grant, hold, refund, dispute, failure and stop, by order id and user id.

The ledger keeps a user's orders only while the deployment holds the user: once the user is removed (section 7), the daemon deletes their orders at its next tick and logs how many, naming no one.

## 7. The nightly apply job (2026-11-12)

**Start the Daemon at Login** also registers Mooring's apply job (`com.bill.mooring.apply`), and **Stop the Daemon** unregisters it; the menu shows it as **Apply job: runs nightly at 19:20 UTC** (an app built since 2026-11-13 says **Apply job: macOS refuses its start, so it does not run** while launchd's record shows that, below). launchd runs `mooringctl apply --pending` from the app every hour at minute 20; the job acts only between 19:15 and 19:45 UTC (03:15 to 03:45 Beijing time, inside the 3 to 6 a.m. window the agreement and the user guide state), so once a night, in summer and winter time alike. A firing that launchd delivers late, after the Mac slept through 19:20 UTC, does nothing, and the job runs the next night (design §13.6).

A run, in this order:
1. **Suspends** each active user whose expiry has passed or who used up their quota (their own, the automatic one, or the one their paid month gives), dated at the run; and **resumes** each user whose suspension's cause has gone: suspended for quota in an earlier billing cycle; suspended for quota in this cycle and since given a pack, a paid month or a higher quota that covers what they used (only while the daemon's usage figures are current: with a node unreachable, the next cycle); or suspended at expiry and since paid (or given a later expiry). A pack too small to cover the use is reported, and the user stays suspended. Resumes go earliest suspension first, while fewer users are active than the cap allows; a user the cap holds back stays suspended and is reported, and you decide. A user you suspended yourself, or for an abuse review, is never resumed by the job.
2. **Removes** each user revoked 13 months ago.
3. **Applies** every node behind the deployment's generation, as `mooringctl node apply` does. A node that cannot be reached (lon1 while its SSH is down) is reported, and nothing before it waits on it.

Run it at once, whatever the time, with `mooringctl apply --now` (add `--json` for one JSON line); a run already going makes another refuse. The console's Nodes screen shows each pending apply, since when and how long it has waited.

Its log is `~/Library/Logs/Mooring/apply.log`: one line when a run starts, then the counts (suspended, resumed, held back, kept suspended, removed) and each node's outcome. It names no user, since a log can outlive the 13 months the agreement keeps a user's records; `apply --now` prints the users by id. The job refuses its policy step, and only that, when the payment ledger or the usage file cannot be read, or when a suspension is dated after now (a clock that stepped back): the report says why. While a node cannot be reached the daemon has no usage report, so no quota is checked that night, and the report says so; expiry suspensions and resumes still go.

After a new build is installed, launchd refuses the job as it refuses the daemon, but only when it starts the job, which is at minute 20: a stop and start that bring the daemon back do not repair the job. Measured on 2026-11-13 with a throwaway app (design §5.1): left alone, the job is refused at its first firing after the install, ends with `last exit code = 78` at the next, and does not run until a **Stop the Daemon** and **Start the Daemon at Login** made after that, while an app built before that day still shows it as registered.

An app built since 2026-11-13 repairs the job in the round that starts a new build, by starting it twice itself (section 1). It also reads launchd's record of the job when it opens, when the console comes to the front and every five minutes. If macOS refuses the job while the daemon runs, a banner says **The nightly apply job does not run** and offers **Repair the Apply Job**: the app starts the job once more if it was refused only once, then unregisters and registers both the daemon and the job, which takes up to a minute and stops the daemon for a few seconds, so the exit restarts with it. Until the repair the night's run does not happen, and a night already missed is not made up: run `mooringctl apply --now` if it should not wait for the next. If the daemon is registered and the job is not (its registration failed; the menu gives the reason after "Could not change it"), the banner says **The nightly apply job is not started** and offers **Start the Apply Job**, which registers it and carries the start through.

By hand, with any build: start the job twice, about 20 s apart, in the minute you wait for the daemon's 78 (section 1): `launchctl kickstart gui/$(id -u)/com.bill.mooring.apply`. The command prints nothing; `launchctl print gui/$(id -u)/com.bill.mooring.apply` shows `job state = spawn failed` after the first and `last exit code = 78: EX_CONFIG` after the second, and the **Stop the Daemon** and **Start the Daemon at Login** that follow bring the job back with the daemon. Check it after the next minute 20 with the same `launchctl print`: `last exit code = 0`, and `runs` one more each hour. `job state = spawn failed` or `last exit code = 78` there means that the job does not run: start it by hand until it shows 78, then choose **Stop the Daemon** and **Start the Daemon at Login** once more. A start by hand of a job that is not refused runs it, and outside its window it does nothing: do not install a new build between 19:15 and 19:45 UTC. Mooring's own job has not been through this: at the deployment of 2026-11-13 its record was new, the build before having carried no job, and launchd ran it from its first firing.

**Removing a user at their request.** `mooringctl user forget <uid>` removes a revoked user at once, with their label, alias and agreement record; the daemon then deletes their usage history and payment orders. It says what goes and asks first (`--yes` to skip the question), and cannot be undone. The bare id stays in `state.json` for a few weeks, until no node can still name it. Only a revoked user can be forgotten.

## Troubleshooting

**`the Mooring daemon is not running`:** the daemon is not started, or it stopped.
- Start it from the app's menu (section 2).
- Run `launchctl print gui/$(id -u)/com.bill.mooring.daemon` to see its state and last exit, and read the last lines of `~/Library/Logs/Mooring/daemon.log`.
- `job state = spawn failed` with `last exit code = 78: EX_CONFIG`, and no new line in the log, means launchd refused the app's `mooringctl` under another build's launch constraint, as it does at the first start after every new build is installed (section 1). An app built since 2026-11-13 says so in its banner, "macOS refuses the daemon's start", and **Finish Starting** there carries the start through. By hand: **Stop the Daemon**, then **Start the Daemon at Login**. Either way macOS asks again for the keychain and may ask for local network access. With `job state = spawn failed` but no 78 yet, wait for the 78 first: launchd has the record replaced only after its second failed start.

**The exit is `Degraded` with `PowerHelperExited`:** the power helper ended, so nothing keeps the Mac awake. The daemon's log says why and how it ended ("the power helper ended: … (exit status …)"), and the daemon starts it again a minute later ("the power helper started again").

**The daemon stops at its start with "the power helper … could not be started" or "did not report the power source":** the app lacks the helper, or it failed. Build and install the app again (section 1).

**"The daemon did not name its control protocol" or "the daemon speaks control protocol N and this mooringctl speaks M":** the daemon runs another build than the app, as after the app was replaced while the daemon kept running. **Stop the Daemon**, then **Start the Daemon at Login**, in the app's menu. In Terminal, use the `mooringctl` inside the app (section 3).

**"The router adapter is not set up":** the M7 is not pinned, its password is not stored, or the pin records no interface (one made before 2026-10-23). The daemon's log names which; run section 0's command for it.

**The router screen says "The Mac could not poll the M7":** the keychain or the kernel's tables failed. The daemon's log names which.

**"The M7 is unreachable":** the daemon's log names why ("router poll failed: the M7 is unreachable: …"). Check the adapter and `ifconfig en9`. With a deployment, "the exit's interfaces do not resolve: no interface matches the egress selector" means the Mac does not see the adapter at all. If the M7 answers `ping 192.168.1.1` from Terminal but the daemon cannot reach it, local network access was refused. Allow it under System Settings › Privacy & Security › Local Network, then wait for the next poll. "router poll succeeded" marks when the M7 answers again.

**"The M7 refused the login":** store the password again with `router set-password`, as in section 0.
