<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: swap day (the 1pMobile SIM goes into the M7)

This runbook is for the operator. It takes the pilot from "the 1pMobile SIM has arrived" to "users connect through it", and lists what must be in place before that day.

The design is §7 (the plan and its cycles), §10.1 and §10.2 (the daemon, preflight, probes, latches), §13.2 (provisioning) and §15.6 (the M7). Every command runs from Terminal.app's own shell in the workspace root, with the signed `mooringctl` (`cargo xtask mooringctl` builds `./target/signed/mooringctl`; below it is written `mooringctl`). `en9` stands for the Mac's interface to the M7, the USB Ethernet adapter: check it with `ifconfig`, it is the one with the address `192.168.1.x`.

What this build does not do yet: per-user usage (the status says it is unavailable, `missing_ledger`), the Mac's report to the phone, and the alert notices. None of them is needed for traffic to flow.

## 0. Before the SIM arrives

Do these in order; each is done once. They run over the M7's current line (the old SIM), never over a campus network (design §10.2, P0-2).

### 0.1 The engines

Download the hosted engine build that matches `engines.lock.toml`'s pins (run 39941124325, 2026-10-23, which built the engines and the target scanner and verified them against the pins) into a new directory, check it, and install it where the daemon runs `mooring-exit` from:

```
mkdir -p ~/mooring-engines/out
gh run download 39941124325 -R billlza/mooring -n engines-xray-v26.9.30-sing-box-v1.14.2 -D ~/mooring-engines/out
cargo xtask engines-verify ~/mooring-engines
ditto ~/mooring-engines/out ~/Library/Application\ Support/Mooring/engines
```

`engines-verify` must print `every engine output matches engines.lock.toml`. The daemon checks `engines/darwin-arm64/mooring-exit` against its pin again before every start, and `node apply` checks the node's engines the same way: a file changed after the check never runs.

### 0.2 The daemon

```
cargo xtask app
open target/app/Mooring.app
```

Then **Start the Daemon at Login** from Mooring.app's menu, as in `console.md`, section 2 (on a Mac that ran the development agent before, stop that first, as that section says). While a daemon from an earlier build is registered, `cargo xtask app` refuses: choose **Stop the Daemon** first, and start it again from the new build (`console.md`, section 1). `cargo xtask app` also builds `./target/signed/mooringctl`, the same bytes as the app's copy: use that one for every command below, so that the keys it makes in the keychain are the daemon's to read without asking. Until a deployment exists the daemon serves the router console; at its first poll after `exit init` it serves the exit instead. Install this build before `exit init`: a daemon built before the exit runtime stops when it finds a deployment.

### 0.3 The deployment

```
mooringctl exit init --interface en9 --cycle-anchor <YYYY-MM-DD> --flow-cap 1024
```

The cycle anchor is the day you will buy the Unlimited Data Boost (cycles are 30 days from it). It can be corrected later with `sim set-anchor` (section 2, step 5). The summary it prints shows the SIM thresholds: a warning at 200 GB and a hard stop at 240 GB per cycle, twice of which stays below the 500 GB rolling line (design §7). It records no carrier check, and the exit starts disabled: it serves nothing until section 0.7 or section 2 records a check and enables it.

### 0.4 lon1

```
awk '$2 == "ssh-ed25519" {print $2, $3}' ops-local/known_hosts > ops-local/lon1-host-ed25519.pub
mooringctl node new lon1 --role primary --host-key ops-local/lon1-host-ed25519.pub
cargo build -p mooring-agent --release --target x86_64-unknown-linux-musl
mooringctl node adopt lon1 --address <lon1's IPv4> --interface en9 --root-identity ~/.ssh/mooring_m2b_ed25519 --agent target/x86_64-unknown-linux-musl/release/mooring-agent
```

`ops-local/known_hosts` holds lon1's host key, checked against the fingerprint Mythic Beasts' control panel shows; `node new` takes it as a `.pub` line. The address is in `ops-local/vps-lon1.md`. **`node adopt` removes your own root key from lon1**: afterwards only Mooring's operations key logs in, forced to the agent, and the Mythic Beasts control panel is the way in if it is lost (its web console, or a reinstall). It runs `Bootstrap`, then checks the running system (`Hello`: Debian 13, a 6.12 kernel, bbr and fq) and records lon1 `Adopted`; no reboot is needed. If it stops after `Bootstrap` (it names the step), fix the cause, for example by rebooting lon1 from the control panel, and run it again with `--resume` in place of `--root-identity`.

Then the REALITY target. None of Mythic Beasts' own names qualifies (each answers HTTP/1.1 only, redirects `/`, or resolves to two addresses), so find one in lon1's /24 with the pinned scanner (design §11.7). It dials by the Mac's default route: turn Wi-Fi off first (section 0.6), so that it leaves over the M7. It makes two handshakes at a time and is done in about ten minutes; its warning about `Country.mmdb` only means the country column stays empty:

```
mkdir -p ops-local/scan
(cd ops-local/scan && ~/mooring-engines/out/darwin-arm64/realitlscanner -addr <lon1's IPv4 ending in .0>/24 -thread 2 -timeout 5 -out lon1-neighbours.csv)
```

Each row of `lon1-neighbours.csv` is an address that completed TLS 1.3 with h2, and the name on its certificate. Take a name that resolves to exactly that address (`dig +short A <name>`). `--same-asn` and `--not-cdn` hold when the address is in lon1's network, AS44684 (Mythic Beasts), which `--evidence` shows, for example `https://bgp.he.net/ip/<address>`. Check it from lon1 and set it with that attestation:

```
mooringctl node target check lon1 <candidate host> --interface en9 --engines ~/mooring-engines/out
mooringctl node target set lon1 <host> --interface en9 --engines ~/mooring-engines/out --same-asn --not-cdn --evidence <url>
```

lon1's first configuration is applied with its first users, in section 0.5: a configuration that serves only the probe has nothing to carry.

### 0.5 The users

Your own test user first (section 0.7 connects with it), then each pilot user (at most 5 active in all):

```
mooringctl user add --client cfm05
mooringctl node apply lon1 --interface en9 --engines ~/mooring-engines/out
mooringctl user agree <user id>
mooringctl user export <user id> --format singbox --out <file>
```

`user add` asks for the label at the terminal, so run it in Terminal.app. Every `user add` is a configuration change, so `node apply` follows it; add every user first and apply once. The first apply is lon1's first configuration: it installs the engines, the tunnel and the firewall, and the node's gate stays closed until the Mac's WireGuard handshake is live. The export's `--out` must be in a folder Time Machine excludes, outside iCloud Drive, the Desktop and Documents (`delivery.md`). Deliver each file by the channels of `delivery.md`; the user imports it into CFM.

### 0.6 The Mac and the M7

- The Mac is on no other network: Wi-Fi off, no campus Ethernet, no VPN, Tailscale quit, no virtual machine (its `bridge100`), CFM's TUN mode off. The daemon checks this (design §10.2, P0-2) and keeps the exit down, naming the interface, while any of them has an address.
- The M7's Wi-Fi radio and its Wi-Fi and Ethernet offloads are off, so the SIM meter counts every byte (`router status` shows them; the status marks the meter a lower bound otherwise).
- The Mac stays on mains power and does not sleep (`pmset -g` shows `sleep 0`).
- The Mac does not restart or log out by itself: automatic installation of macOS updates is off (System Settings, General, Software Update). The daemon is a login item of your session: after a restart it runs again once you log in (FileVault needs that login), and it does not run while you are logged out.
- Whatever the Mac itself downloads also goes over the SIM and counts against its cycle: keep iCloud Drive and Photos sync and large downloads off this Mac.

### 0.7 Test the whole chain on the current SIM

The M7's current SIM still has data, so the whole chain can be proved before the 1pMobile SIM arrives:

```
mooringctl exit observe --interface en9
mooringctl exit record-carrier --prefix <the current carrier's cidr> --pairing paired
mooringctl exit enable
mooringctl status --json
```

Look the observed address up as in section 2, step 4, in the current carrier's pool. Within a minute the exit is `serving`. If `mooringctl` was rebuilt after `node new`, macOS asks once for each of the node's keys when the engines first start (the dialog `console.md` shows for the M7's password); choose **Always Allow**. Import your own test user's file into CFM 0.5.0 on another Mac (this one stays on the M7 alone), on any network, turn on 中国大陆直连 as `user-onboarding.md` says, connect, and browse: a page that shows your address shows the one `exit observe` printed, because the traffic leaves by the M7's line. Then:

```
mooringctl exit disable
```

The bytes of these days fall in the cycle before the Boost's, so they do not count against the first 1pMobile cycle.

## 1. Check before the swap

```
mooringctl status --json
```

The exit is `disabled` (it starts so, and section 0.7 ends so), which is right before the swap. The router panel shows the M7.

## 2. Swap day

0. **Keep the exit disabled** (section 1; if it is not, `mooringctl exit disable`): with the old carrier check recorded, the new SIM's address would be latched as a violation and every gate closed with a hold (a retry would undo it, but there is no need).
1. **Buy the Boost** in the 1pMobile app. Note the UTC date: it is the cycle anchor.
2. **Swap the SIM.** Power the M7 off, put the 1pMobile SIM in, power it on. Wait until `mooringctl router status --interface en9` shows a data service. If none comes within a few minutes, check that mobile data is on in the 1pMobile account (its network settings can turn data off), then give the M7 1pMobile's APN in its web page: APN `data.uk`, user name `user`, password `one2one`, authentication CHAP (1pMobile's own help pages, read 2026-10-23).
3. **Observe the carrier address:**
   ```
   mooringctl exit observe --interface en9
   ```
   It prints the address lon1's reflector sees, for example `lon1: the reflector sees 31.94.12.34 (no carrier check is recorded yet)`. Run it a few times over some minutes. If the address changes between runs while staying in one range, the carrier pools addresses: use `--pairing unpaired` below; otherwise `paired`.
4. **Record the carrier check.** Look the address up in the RIPE database (`whois -h whois.ripe.net <address>`) and take the `inetnum` range of EE's public pool that holds it, never the whole ASN. Record it as one or more CIDR prefixes, replacing the old SIM's check if section 0.7 recorded one, and apply (the replacement is a configuration change):
   ```
   mooringctl exit record-carrier --prefix <cidr> --pairing paired --replace
   mooringctl node apply lon1 --interface en9 --engines ~/mooring-engines/out
   ```
   Without an earlier check, leave out `--replace`, and no `node apply` is needed. Then `exit observe` again: each address must read `inside the recorded carrier prefixes`.
5. **Correct the cycle anchor**, if the Boost was bought on another day than `exit init` was given:
   ```
   mooringctl sim set-anchor <YYYY-MM-DD>
   mooringctl node apply lon1 --interface en9 --engines ~/mooring-engines/out
   ```
   It is a configuration change, so the node is applied again. The SIM meter keeps its bytes per day, so no byte is lost or moved.
6. **Enable the exit:**
   ```
   mooringctl exit enable
   mooringctl status --json
   ```
   Within a few seconds the exit is `starting`, with the egress, the carrier check (the address, inside the prefixes) and `mooring-exit`'s and `mooring-probe`'s pids; 10 s after the engine starts the first in-chain round runs, and the exit is `serving` with the verified address, or `degraded` naming each probe that failed (node, protocol, stage). Each node's row shows its latest report or why it is unreachable. The daemon's log (`~/Library/Logs/Mooring/daemon.log`) has one line per state.
7. **Ask a user to connect** with the file they imported. lon1's gate opens once the Mac's WireGuard handshake is live.

## 3. When something is wrong

- **`degraded`:** the exit serves, with a problem. `node_probe_failed` names a node, a protocol and the stage: `prober_unavailable` means `mooring-probe` is missing or does not match its pin (section 0.1); `carrier_address_unstable` means the carrier's address changed during the probe twice running (consider `--pairing unpaired`, section 2 step 3); `connect`, `read` or `parse` point at the node or the chain. `watch_stale` means the node's watch has stopped writing its status. `on_battery`: the Mac lost mains power.
- **`down` with a reason:** the reason says which check failed (design §14). `egress_interface_absent`: the M7 is unplugged or has no address. `foreign_network_attached`: an interface is named; take it off. `direct_probe_failed`: the line or lon1's reflector does not answer. `engine_spawn_failed`: `engines/darwin-arm64/mooring-exit` is missing or does not match its pin (section 0.1). `engine_config_rejected`: the daemon's log has the engine's own words. `secrets_unavailable`: macOS had to ask to let `mooringctl` use a key in the keychain and could not show the question; at the Mac, logged in with the screen unlocked, the daemon tries again within 2 s and the question appears: choose **Always Allow**.
- **A violation** (`down` with `violation`): the carrier address left the recorded prefixes, was a node's address, or (with `paired`) the chain's address differed from two equal direct probes around it. The engine stopped at once and every node's gate was closed, with a hold. It stays down until you act: find the cause (the M7 switched its WAN to Wi-Fi? the carrier changed its pool?), fix it or record the new prefixes, then
  ```
  mooringctl exit retry
  ```
  The daemon clears the latch, probes afresh, asks the nodes to clear their holds, and starts the engine if the address passes. A node halted because the egress showed its own address stays halted; resume it only after finding out why.
- **SIM hard stop** (`down` with `sim_cap_reached`): the cycle's bytes reached 240 GB. The exit stays down until the next cycle starts; nothing is to be done.
- **`the Mooring daemon is not running`** (from any `mooringctl` command that asks it): you are logged out, or the daemon was stopped from the menu. Log in, or **Start the Daemon at Login** from Mooring.app's menu; the daemon resumes the exit as it was, enabled or not.
- **Stop the exit** at any time: `mooringctl exit disable` (the daemon stops the engine within 2 s), or stop the daemon: **Stop the Daemon** in Mooring.app's menu.
