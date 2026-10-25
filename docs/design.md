<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Mooring design

**Status.** Design, revision 8 (2026-10-15): M1 is committed (4a95ee0, 2026-10-08), the console foundations and revision 6 code with it (71af715, 2026-10-09), and revision 7's router adapter and first `mooringctl` commands with their first live run (89d2cdf, 2026-10-15). Revision 3 added the user decisions D-3 (Xray v26.9.30 with REALITY e1986a4) and D-7 (build host). Revision 4 brought the document into line with the M1 code (`crates/`, `xtask/`, `contract/`): where the code is stricter, or where the pinned upstream source contradicted revision 3, the code is authoritative and this text says what it does. It also recorded the decisions D-8 (rotation order) and D-9 (where CFM acceptance is checked). Revision 5 recorded the operator-console review of 2026-10-08:
- facts that need no decision: the plan terms and units of EE, then the candidate line (§19.1, now history), the M7's Plugged-In mode and Ethernet path (§2), Durham's IT regulations (§10.2), this MacBook's power facts (§10.3), and the accounting accuracy limits (§11.5);
- the console design (§15): `MacStatusV1`, what is shown and what is deliberately not recorded, the read-only router adapter, the event journal and the alert machine;
- the code that landed with it: state version 2 with suspension, user policy, public aliases, agreement records, an active-user cap, the SIM plan record with a bill day and a stop policy, and the uplink baseline (§7); the per-node credential-uniqueness check `DuplicateCredential` (§8.1); and the protocol-1 console frames `UsageSeries`, `Events` and the extended `StatusV1` (§11.1);
- the operator decisions F1–F20 (§20), each with a recommended default and then marked pending;
- M2 split into M2a (the M7 alone, from 2026-10-09) and M2b (needs an hourly VPS) (§22).

Revision 6 records the operator's decisions of 2026-10-08 and the code that carries them:
- **Decided (§20):** F1, the line: SMARTY Unlimited Data Only, after EE declined the order at its credit check, reopened on 2026-10-17 when the operator decided to leave SMARTY after its uplink run (M2.md); F2, a hard stop at 300e9 SIM bytes with a warning at 240e9; F3, at most 5 active users; F4, automatic quotas from 6 active users, latched per cycle; F5, remote viewing through a viewer role; F6, the alert channels (ntfy on one topic, Healthchecks.io, a 09:00 digest); F12, superseded; F15, no operator traffic over Janet or eduroam; F16, bytes and times only. D-1 is accepted for a pilot of at most 5 active users, with F20 pending. D-8 and D-9 are confirmed by the M1 commit 4a95ee0. On 2026-10-09 two points were decided by the recommended default, following F4/F6 as stated: whom F4's N counts (the users active now and those suspended for quota in the current cycle) and F6's single ntfy topic (§20.2). Every other F and D decision stays pending.
- **Facts:** SMARTY's terms, billing, units, radio bands and APN, with sources and dates (§19.1). EE's facts stay in §19.1 as history; EE is not the line. Every statement about the exit line now refers to SMARTY on Three's network.
- **Code (§22, "Revision 6"):** an unlimited plan without a fair-use line, whose stop is mandatory and unbounded by any line (§7); the pilot constants `PILOT_SIM_WARN_BYTES`, `PILOT_SIM_HARD_STOP_BYTES`, `PILOT_MAX_ACTIVE_USERS`, `AutoQuotaPolicy::PILOT` and `AlertSettings::pilot()`; P0-1 by type (`SimPolicy::new` takes a plan, and `Deployment::new` refuses an unrecorded one) and by the store (a change that edits the SIM policy must leave its plan recorded); the F4, F5 and F6 records in state version 2 (automatic quotas, viewers, and alert channels with one ntfy topic for the deployment and two Healthchecks checks per channel node in the Keychain); the viewer role with its Operator-hold-only emergency stop (§11.1); the Mac report `MacReportV1` (§15.9); the Level-0 notice grammar, notices and digest (§15.8); the dead-man ping rule (§15.8); and host profile 2 with the unprivileged `mooring-view` account and `viewer_authorized_keys` (§8.6).

**Revision 7** records the M2a findings of 2026-10-13 (`docs/measurements/M2.md`): the M7's JSON endpoint and login, the plaintext secrets in its status document, its unreliable clock, the operator's settings, and the battery kept installed. It adds the MR7450 allowlist parser and redactor (`daemon-core`'s `router::netgear`) and the router status reshaped to what the M7 reports (§15.6). It also adds `macsys` (the kernel's interface, routing and neighbour tables, and the terminal echo guard) and the first `mooringctl` commands (`router pin | set-password | status | capture`, macOS only), tested against a loopback stub on this Mac and first run against the M7 on 2026-10-14 (§15.6, §22 M2a).

**Revision 8** (2026-10-15) records F7, F9, F10 and F11, which the operator delegated to the recommended best-practice default after the onboarding review of 2026-10-15 (§20.2), and the code that carries F9:
- **F9:** `user export` requires the user's acceptance of the agreement revision the build ships (`AgreementVersion::CURRENT`, revision 1), and otherwise refuses with `AgreementNotAccepted`, after the status check and before anything about the file (§9.2, §14). Delivery is by file only: in person by AirDrop, or in an AES-256 disk image, on a USB stick or sent, whose passphrase is spoken over an end-to-end encrypted call; never a QR code, HTML page, URI or subscription, and nothing about the service over WeChat, QQ or iMessage to a mainland-China Apple ID. The user accepts the agreement aloud on that call (§9.4).
- **F10:** macOS CFM only, on a 0.5-line release with CFM's mainland China direct switch, which the user guide tells users to turn on (§20.2). The switch is committed as `d828f92` on CFM's topic branch `feat/mainland-direct-routing` (2026-10-16), meant for 0.5.0 and in no release yet (§19).
- **F11:** no subscription. With the M8 pilot's single node a block means a rotation and a new file for every user; every user holds both nodes only from M9 (§13.4).
- **F7:** retention takes its recommended default, because the agreement (F9) states it to users (§15.5, §20.2): a node keeps usage bins for 48 hours and a monthly file until 7 days after its month (§11.5), and a revoked user's records on the Mac go 13 months after the revocation, or at once on the user's request (§15.7); a node's expire on their own schedule (§11.5).
- The engines' Go pin moves to 1.27.2 (§4). Three of the runbooks the pilot needs before M8 are written: `delivery`, `user-onboarding` and the new `user-agreement`; `exit-host`, `power-cut` and `sim-plan` are not yet (§6, §22).
- The review of these changes on 2026-10-15 set what M5 builds for them: `user agree` as a bookkeeping record that keeps the generation and never lowers a record (§7, §15.3); the revocation time in the state, so that a revoked user is deleted on time (§15.7); the Mac's data and export folders kept out of Time Machine (§12); and an apply job that runs at 03:20 China time in summer and winter alike (§13.6). A test pins the agreement's text, which cannot change without a new revision (§9.2).

**Revision 9** (2026-10-22) builds the console's first slice, the router console, and records the decisions it needed and the macOS behaviour it met:
- **The daemon runs before `exit init`** (§5.1, §10.1): with no deployment there is no exit to serve, but the router adapter needs none, so `mooringctl daemon --router-interface <bsd>` polls the M7 every 60 s and serves the console's status on `run/control.sock` (requests `status` and `subscribe`). With a deployment present this slice refuses to start (`DeploymentNotServed`): the exit's side of the daemon is not built, and it never reports a deployment it does not run.
- **The console's document is `ConsoleStatus`** (§15.1, §15.2): `no_deployment` (the router alone, versioned) or `deployed` (`MacStatusV1`), printed by `mooringctl status [--follow] --json` and snapshotted in `status.json`. Fixtures in `contract/console-fixtures/`.
- **Mooring.app's first screens** (§15.3, M7): `apple/project.yml` and `apple/Packages/MooringKit`, an overview and the router screen, in English and Simplified Chinese; every other screen says it needs a deployment. Its Codable mirror refuses any key or variant the Rust types refuse, and refused a `deployed` document whole until it mirrored `MacStatusV1` (done 2026-10-23, M7, §22).
- **Local network privacy applies to the LaunchAgent** (§5.1, §15.6 rule 10): measured 2026-10-22, the agent's connection to the M7 failed with `EHOSTUNREACH` while the same binary reached it from a shell. Apple's TN3179 says macOS exempts launchd daemons and Terminal tools but not agents, which must name their responsible app (`AssociatedBundleIdentifiers`, or `SMAppService`); the app declares `NSLocalNetworkUsageDescription`.
- **The M7's SMARTY-line values are read** (§15.6 rules 1 and 2): `LteService`, `4G`, `4GPLUS`, and a secondary entry of band 0 and bandwidth `Unknown`, counted as an unassigned slot. `RouterUnavailableReason::LocalFailure` names a poll that failed on the Mac.
- **The M7 on its battery** (§15.6 rule 2, M2.md): on 2026-10-22 it reported the charge source `None` and, within minutes, the power state `Standby`; each made every poll refuse the M7's answer until it was added (`ChargeSource::NoSource`, `PowerState::Standby`). The router screen now shows the charge source on its own row, so a battery-powered M7 no longer reads as a full battery that is not charging.
- **After the slice's review** (2026-10-22, four read-only reviews: architecture, the Rust implementation and tests, security and robustness, the app and tooling): the request and each reply line have a deadline for the whole line (§10.1); `status --follow` treats a status older than 240 s as stale and ends with Mooring.app only when asked (`--until-parent-exits`, §10.1); the settings the exit needs off are decided once, in `daemon-core` (`RouterStatus::advisories`), and carried in the document (§15.1, §15.6 rule 8); the app reads its stream on threads of its own with read(2), splits it on 0x0A bytes only, and shows a refused line as not live; the app and its `mooringctl` are signed with the hardened runtime, the agent is restarted no sooner than a minute apart, `cargo xtask app` restarts a loaded agent on the new build, `cargo xtask clean` is refused while it is loaded, and `cargo xtask ci` runs MooringKit's tests (§5.1, §16). What the reviews found and was left, with its reason, is in §10.1 and §15.1.

The pure Rust core is built and tested on this Mac; no engine has been built, and nothing has been run on a VPS or provisioned. Any statement not confirmed in source code or a primary document is marked *(inference)*, and each one is tied to the test lane or milestone that will prove it. Evidence is cited as `file:line` at a named commit, or as a URL with the date it was checked. Pinned upstream trees used for citations:

| Tree | Commit |
|---|---|
| sing-box v1.14.2 | `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` (clean checkout, no local modifications) |
| Xray-core v26.9.30 (prerelease) | `b26a91de4f3294e26a0ad0a970b81a386a41f789`, built with `xtls/reality` replaced by `e1986a4` (§4.2) |
| XTLS/REALITY | `e1986a4d31ca33c087a72ab4644aef1295693b69` (parent of `8cdf7bf9`, which Xray v26.9.30 pins) |
| Linux | v6.12 `net/ipv4/{route.c,fib_frontend.c,fib_trie.c}` |
| sing-quic (as pinned by sing-box v1.14.2 `go.mod:53`) | `v0.7.1-0.20260924092235-6a3a24d65b99` |
| CFM 0.4 line | `ac981c3` (sing-box 1.14.1) |
| CFM 0.5 line | `502adf9`, which tag `v0.5.0` points to (CFM 0.5.0, build 50030, sing-box 1.14.2). It contains `f340fae` (REALITY requires uTLS) and `e6c9e05` (the committed `support_x25519mlkem768` opt-in). The export contract (`docs/cfm-contract.md`, `contract/cfm-manifest.toml`) is pinned at `502adf9`; until 2026-10-18 it was pinned at `3157ef9`. |

**What Mooring is.** Mooring lets a small number of trusted users in mainland China reach the internet through the operator's UK mobile connection. Their traffic exits from a NETGEAR Nighthawk M7 Pro (MR7450) with a SMARTY SIM (Hutchison 3G UK Limited trading as SMARTY, on Three's network with Vodafone coverage sharing; §19.1), attached to the operator's Mac. SMARTY's APN is IPv4 only (help 1155220), the line's IPv4 is expected to sit behind CGNAT *(inference; M2b records it)*, and the MR7450 has no inbound IPv6 controls. The Mac therefore cannot accept connections from China. Instead, a rented Linux VPS faces China, and the Mac dials out a tunnel to that VPS and acts as the exit.

---

## 0. Decisions at a glance

| Area | Decision |
|---|---|
| Product | **Mooring**. Repository `mooring`, licensed GPL-3.0-or-later, separate from CFM. Bundle id `com.bill.mooring`; lab builds use `com.bill.mooring.lab`. Branch names are neutral (`main`, `feature/<area>`, `fix/<area>`). No tool, generator or attribution markers appear anywhere. Check the name for collisions before creating the repository. |
| Topology | CN user (CFM) → **London VPS**, serving VLESS+REALITY+Vision on TCP/443 and Hysteria2 on UDP 61000 (hopping across 61001-62999) → **kernel WireGuard `wgexit`** → **Mac** running a userspace sing-box WireGuard endpoint. The Mac dials out, and its sockets are bound to the **M7 wired interface** → SMARTY (Three's network) → internet. |
| VPS steering | Xray's only exit outbound is bound to `wgexit` (SO_BINDTODEVICE). Routing uses `ip rule oif wgexit lookup 77` with `default dev wgexit table 77`. `accept_local=1` is set on `wgexit`. An **nft owner guard** (`meta skuid`) rejects any connection either engine originates outside its allowed paths, which makes the steering kernel-enforced. An nft output **gate** fails client connections fast while the Mac is away. |
| Engines | **VPS:** Xray-core **v26.9.30 with REALITY pinned to e1986a4** handles REALITY, routing, DNS and accounting. sing-box **1.14.2** runs the Hysteria2 inbound only, and hands each user to Xray over loopback. **Mac:** sing-box **1.14.2** runs as two processes: `mooring-exit` (WireGuard endpoint and bound egress) and `mooring-probe` (in-chain probe clients). Every engine is built from pinned source with one Go toolchain and upstream's release flags. |
| Tunnel uplink | `SameAsExit` (the M7) is the default. `Separate(home interface)` is an explicit setting. Mooring never switches between them automatically. `Separate` may only name a connection the operator contracts for (their own home broadband). It must never name an institutional network: on 2026-10-08 this Mac's only other uplink was Durham University Wi-Fi (Janet AS786, NAT, no IPv6), whose IT regulations limit use to authorised users and academic purposes. On that network the exit runs `SameAsExit` only. Revision 5 (P0-2, §10.2): from M2b on, the exit Mac joins no Durham network at all (Wi-Fi forgotten, no eduroam, no campus Ethernet) while any exit or test tunnel runs, and operator monitoring and control traffic never crosses Janet. |
| Exit hardware | The M7 runs in **Plugged-In mode** (battery removed, powered by its own adapter through its only USB-C port), and production data uses its **2.5GbE port** through a USB-C Ethernet adapter on the Mac (§2). Its Wi-Fi radio, offloads and UPnP are off, and firmware is installed by hand. Mooring reads the M7's status and never writes its settings (§15.6, §18). Revision 7 (M2a, 2026-10-13): the operator keeps the battery installed for now, a recorded deviation from Plugged-In mode, and the Mac reaches the M7 through a gigabit USB adapter. |
| Line (F1, 2026-10-08) | **SMARTY Unlimited Data Only**, £20 a month, rolling monthly, a physical SIM in the M7 (§19.1). It has no fair-use line and no speed cap, so the operator's hard stop is the only volume guard (§7). The pilot records a warning at 240e9 and a hard stop at 300e9 SIM bytes (F2), at most 5 active users (F3, D-1), and automatic quotas from 6 users sharing the cycle's budget (F4: the users active now and those suspended for quota in the current cycle), which stay dormant under that cap unless suspensions for quota this cycle bring the count to six. |
| Console | `mooringctl … --json` is the only API. `Mooring.app` renders the daemon's `MacStatusV1` stream (§15). There is no web panel and no new listener. The console shows bytes, times and states per opaque user, node and protocol, never destinations, users' IP addresses or M7 identifiers. Remote viewing (F5) and the alert channels (F6) were decided on 2026-10-08: a read-only viewer role on each node for the operator's phone, whose only action is an emergency stop with the Operator hold (§15.9), and ntfy push notices, Healthchecks.io dead-man checks and a daily 09:00 digest, all Level 0 (§15.8). |
| Egress verification | **Mandatory carrier check.** Every observed egress IP must fall inside the carrier prefixes (SMARTY on Three's network) recorded on the line in the field spike (M2b). In addition, `Paired` mode brackets each in-chain probe between two direct probes. Direct probes run every 30 s and in-chain probes every 300 s. A violation stops the Mac engine (fail closed). |
| Rust | `mooringctl` (CLI, LaunchAgent daemon and bound SSH dialler) is one signed binary with one keychain identity. `mooring-agent` is a static musl binary on the VPS: forced-command SSH handler, transaction runner, watch loop and reflector. There are eight library crates, plus the test-only `mooring-fixtures`. |
| Swift | `Mooring.app` provides the menu bar, SMAppService registration, a status stream read from the CLI, and notifications. `mooring-power`, a child of the daemon, holds NetworkClientActive and PreventUserIdleSystemSleep and reports sleep and wake events. Swift never handles secrets. |
| CFM export | One file per user. The default is sing-box `{"outbounds":[...]}` with an SPKI pin. Clash YAML containing only `proxies:` with a DER `fingerprint` is optional. REALITY always carries `utls` or `client-fingerprint`. Shapes are selected by each user's CFM client line. `user export` requires the user's acceptance of the current agreement revision (F9). The file is the only form: in person by AirDrop, or in an AES-256 disk image, on a USB stick or sent, whose passphrase is spoken over an end-to-end encrypted call; never a URI, QR code, HTML page or subscription (F9, F11, §9.4). |
| Clients (F10) | macOS CFM only, on a 0.5-line release with CFM's mainland China direct switch, which the user guide tells users to turn on: the nodes deny `geoip:cn` and `geosite:cn` (§8.2), and an outbound-only file sends every flow to the node. |
| VPS | London, Debian 13 amd64, 1 vCPU and 1 GiB, with a dedicated public IPv4 configured on the interface. There is one primary node plus a standby on a different ASN; the M8 pilot runs the primary alone, and the standby comes in M9 (F11). |

---

## 1. Threat model and trust boundaries

### 1.1 Assets

| Asset | Where it exists | Level |
|---|---|---|
| User traffic content and metadata | The VPS terminates the proxies, the Mac sees only destination IPs, the carrier (SMARTY on Three's network) sees the exit flows and their TLS SNI, and Cloudflare's DoH resolvers see every name the exit resolves, from the line's address (`dns-exit`, §8.2) | 2 |
| Users' China source IPs | VPS only. The inner source on the tunnel is always 10.77.k.1, and the Mac's peer accepts only that source (`allowed_ips` /32) | 2 |
| SIM-holder attribution (all exit traffic is legally the SIM holder's) | The Mac deny list (authoritative) and VPS policy | 2 |
| Node keys: REALITY private key, Hysteria2 TLS key, the VPS's WireGuard key | Mac Keychain and that VPS | 2 |
| Per-user, per-node credentials | Mac Keychain, that VPS, that user's export file until it is imported and deleted, then the Keychain vault of that user's CFM (§9.4) | 2 |
| SSH operations key | A file on the Mac, mode 0600, excluded from backups | 2 |
| M7 admin password; the M7's status document, which carries in plaintext the admin password, the Wi-Fi and cradle passphrases, the IMEI, ICCID, IMSI and phone number, SMS bodies and senders, cell identifiers, GPS and the clients' addresses (M2a, §15.6) | The M7, and the Mac's Keychain (a login is needed, M2a) | 2 |
| The operator's Mac: files, Keychain, other keys, LAN | Mac | Impact equivalent to Level 3 |
| Engine and blob hashes | Both | 1 (detects accidental corruption) |
| Accounting and status | Both | 0 |

### 1.2 Adversaries

**A compromised VPS or a malicious provider**
- *Can:*
  - see the flows and China IPs of that node's users;
  - impersonate that node to its users;
  - push public-destination TCP and UDP out of the carrier IP, limited by the Mac's deny list and the SIM cap;
  - read and post to the deployment's one ntfy topic, a Level-1 secret every channel node holds, until the operator replaces it (§12); retiring the node does not revoke it.
- *Cannot:*
  - use credentials on the other node, because every access credential is per node;
  - reach the Mac's loopback, the LAN, the M7 admin page or the carrier's CGNAT range, because the Mac rejects them by final IP and that rejection is tested directly over `wgexit` (T-deny-mac);
  - learn users' real names, which exist only on the Mac;
  - learn the home broadband IP, unless the operator chose `Separate` mode;
  - reach the Mac's files: its only surface is a userspace WireGuard and gVisor stack inside `mooring-exit`, sandboxed if the M5 spike passes.

**The GFW, or anyone holding a user's export file**
- *Can:* identify and block that node, or use that one user's credentials on that node.
- *Mitigations:* after a leak, reissue the user's credentials (`user reissue`); after a seizure, revoke the user and rotate the node (§9.4, §13.5); keep a standby (from M9, F11); deliver by file only (§9.4).

**A malicious user**
- *Can:*
  - use the exit within policy;
  - saturate the shared uplink (neither engine supports per-user rate limits, which is an accepted risk);
  - open many flows, up to the node-wide flow cap (§8.5).
- *Cannot:* chain through a node to multiply SIM usage, because node IPs are denied to every identity except the probe (§8.2), and cannot reach VPS-local services.

**CFM running on the same Mac.** CFM's NetworkExtension sets `includeAllNetworks=false` and `enforceRoutes=false` (CFM `HostBridge.swift:1603-1608`). Interface-bound sockets should therefore bypass its tunnel *(inference; proven in M2 and L6-bypass)*. If that ever changes, the carrier check fails and the exit stops.

**The carrier** (SMARTY, on Three's network, whose radio may be Vodafone's under VodafoneThree sharing, §19.1) sees WireGuard metadata and the exit flows. This is inherent to the design.

**Same-user processes on the Mac, or a compromised Mac.** Either means total compromise. The data-protection keychain gives no prompts and keeps secrets out of backups, but the entitled `mooringctl` will export secrets for any process running as the same user. The forced-command SSH key is a robustness control (typed operations, no ad-hoc drift), not a boundary against the operator's own machine.

**Failure domains.** Hysteria2 reaches the exit through Xray over loopback, so an Xray outage takes down both protocols on that node. The standby node is the redundancy.

### 1.3 Controls deliberately not added

| Not added | Reason |
|---|---|
| WireGuard pre-shared key | It protects tunnel metadata against a future quantum attacker, but the carrier already sees the same destinations in clear on the exit leg. |
| HMAC or signatures on bundles and agent messages | SSH already authenticates both ends. |
| Key generation on the VPS (other than its SSH host key) | It gains nothing against a compromised Mac, which holds root SSH, and it would need a second renderer. |
| Encryption at rest on the VPS | The provider has root. |
| fail2ban, port knocking, SSH 2FA, GeoIP allowlists for SSH | OpenSSH has had PerSourcePenalties on by default since 9.8, and the Mac's CGNAT source changes. |
| Rate limits on TCP/443 | They are themselves a fingerprint (REALITY README). Only TCP/80, UDP/443 and the reflector port are limited per source, at levels far above browser use. |
| Blocking ICMP | It breaks path-MTU discovery. |
| nft block of the metadata service (169.254.169.254) | Bootstrap replaces the SSH host key that was injected through user-data (§13.2), so user-data holds no live secret afterwards. |
| LocalAuthentication gating of `user export` | Any same-user process can already read the operations key file. The gate would add a prompt without creating a boundary. |
| Restricting the reflector to the carrier's source prefixes | A Wi-Fi offload on the M7 would then show up as a timed-out probe rather than as `OutsideCarrierPrefixes`, which turns a detectable violation into an ambiguous one. A per-source limit is used instead (§11.4). |
| Regex log redactor | Engines run at log levels that do not emit per-flow lines. The canary lane checks this, and stderr tails are scrubbed by exact substring against the bundle's known secrets (§15). |
| CAP_NET_ADMIN or SO_MARK for Xray | The owner guard enforces the same thing with no privilege on the internet-facing process. |
| Provider API token in Mooring (v1) | It would be a long-lived credential able to create and destroy servers. The operator's own tooling holds one key, outside Mooring (D-10). |

---

## 2. Topology, data path and congestion control

```
 CN user: CFM 0.4 (sing-box 1.14.1) / 0.5 (1.14.2)
   │ TCP 443 VLESS+REALITY+Vision            │ UDP 61000 (+61001–62999 hop) Hysteria2 (salamander, BBR)
   ▼                                         ▼
 ┌──────────────── London VPS (Debian 13, kernel 6.12) ────────────────────────────────┐
 │ mooring-xray (Xray v26.9.30)  ◄── 127.0.0.1:10443 VLESS ── mooring-hy2 (sing-box)     │
 │   outbounds: deny (default) · exit = freedom, SO_BINDTODEVICE wgexit                 │
 │              · camo-80-out / camo-u443-out = freedom redirect → REALITY target IP    │
 │ ip rule pref 10000 oif wgexit → table 77 (default dev wgexit); wgexit accept_local=1 │
 │ nft: input default-drop (by daddr) · owner guard (skuid) · gate @exit_closed         │
 │      · per-source limits on 80/udp443/27900 · exit flow cap · hop redirect           │
 │ wgexit 10.77.k.1/30, UDP 27820, peer AllowedIPs 0.0.0.0/0, no Endpoint (roaming)     │
 │ mooring-watch (sole gate opener, holds, accounting, target check)                    │
 │ mooring-reflect (TCP 27900)                                                          │
 └──────────────────────────────▲──────────────────────────────────────────────────────┘
        WireGuard UDP, dialled OUT by the Mac over the tunnel uplink (default: the M7)
 ┌──────────────── Mac (macOS 27, MacBookPro18,2, user session) ───────────────────────┐
 │ Mooring.app ─► `mooringctl status --follow --json` / `mooringctl <action> --json`    │
 │ mooringctl daemon (LaunchAgent; control socket run/control.sock)                     │
 │   ├► mooring-exit  (sing-box: wg-<node> endpoints → deny rules → egress, bound)      │
 │   ├► mooring-probe (sing-box: 127.0.0.1:471xx → exported probe clients, bound)       │
 │   └► mooring-power (Swift: IOPM assertions, sleep/wake events)                       │
 └──────────────────────────────┬──────────────────────────────────────────────────────┘
                                ▼ 2.5GbE via a USB-C adapter (never Wi-Fi) → M7 Pro, Plugged-In (offload off) → SMARTY 5G on Three (CGNAT) → internet
```

**Who sends on each leg.** Every hop splits congestion control, because the VPS terminates TCP and the Mac's gVisor stack terminates it again.

| Leg | Download sender (destination → CN) | Upload sender (CN → destination) |
|---|---|---|
| Destination ↔ Mac | The destination's own congestion control, over the 5G **downlink** | macOS CUBIC over the 5G uplink, RTT ≈ 20 ms |
| Mac ↔ VPS, `SameAsExit` | **gVisor Reno with SACK/RACK over the 5G uplink — the bottleneck** | VPS kernel BBR over the 5G downlink |
| Mac ↔ VPS, `Separate` | gVisor Reno over the home uplink | VPS BBR over the home downlink |
| VPS ↔ CN, REALITY | Linux BBR with fq | The client OS's TCP |
| VPS ↔ CN, Hysteria2 | sing-quic BBR | The client's QUIC BBR, forced because the server replies "auto" |

Evidence:
- gVisor defaults to Reno: sagernet/gvisor `tcp/protocol.go:540-541`. sing-tun never sets a congestion option (`stack_gvisor.go:217-300`).
- The server forces BBR when `ignore_client_bandwidth` is set with no bandwidth configured: sing-quic `hysteria2/service.go:290-306`.
- The endpoint routes flows the VPS starts by inbound tag: `protocol/wireguard/endpoint.go:226-246`.

**How the M7 is attached (revision 5).** Facts from the NETGEAR Nighthawk M7 Pro/Ultra user manual 202-12721-02 (June 2025), cited by printed page:
- The M7 has one 2.5G RJ45 Ethernet port, one USB-C port and two TS-9 antenna ports (p. 9).
- **Plugged-In mode** is NETGEAR's mode for a fixed location: remove the battery, leave the back cover off for cooling, and power the M7 from a wall adapter through its USB-C port. The manual advises against leaving a battery-powered M7 plugged in for long periods (pp. 12-14, "Charging best practices" and "Set up Plugged-In Mode for fixed usage"). Computer USB ports supply less current than NETGEAR's adapters (p. 12).
- The USB-C port therefore carries power, not data. **Production data goes over the 2.5GbE port**, through a USB-C Ethernet adapter on the Mac; this MacBookPro18,2 has no built-in Ethernet. Revision 4's "USB-C or 2.5GbE" becomes 2.5GbE.
- The Ethernet port is **disabled by default**. Enabling or disabling it restarts the M7. In Plugged-In mode it stays enabled for as long as the device is plugged in; on battery it sleeps after two minutes without a connection (pp. 22, 47-48).
- Whether the M7's USB data interface is RNDIS, for which macOS has no driver, is recorded once in M2a for the record only. Nothing depends on it. *(The RNDIS guess rests on a sibling model.)*
- **M2a (2026-10-13).** The Mac's adapter is a gigabit USB adapter (`en9`, 1000baseT); the M7 reports `power.ethernetSpeed` `100M`, whose meaning is unknown and which Mooring does not read. The operator keeps the battery installed for now (a deviation from Plugged-In mode, recorded in M2.md). The M7's firmware was updated over the air on 2026-10-09, an update the operator started from the device's Settings, and after a power cut with the battery out it powered on by itself, reaching its home screen in about 60–70 s.

**The line in the M7 (revision 6).** SMARTY's radio and access facts (§19.1, read 2026-10-08):
- 5G on 3.5 GHz (band n78); 4G on 700, 800, 1400, 1800 and 2100 MHz (bands B28, B20, B32, B3 and B1) (help 4670061, 9 Dec 2025). Whether SMARTY's 5G is standalone or non-standalone is not stated; M2a records which the M7 attaches with.
- The APN is `mob.asm.net`, IPv4, with no username or password (help 1155220, 18 Mar 2026).
- Since August 2025 SMARTY customers are moved automatically, on the same SIM, onto combined Three and Vodafone coverage (VodafoneThree network sharing; help 10235435, 5 May 2026), so the M7 may attach to a Vodafone mast.

The thermal, firmware, SIM PIN and power-cut facts are in §10.3 and §19, and the setup steps in M2a (§22).

---

## 3. Performance budget

Everything in this section is *(inference)* unless a source is cited.

**Assumptions.** Round-trip times: China↔London C ≈ 280 ms (WonderNetwork: 260–268 ms typical, 315 ms peak); VPS↔Mac over the 5G line M ≈ 40 ms; Mac↔destination D ≈ 20 ms. The VPS↔REALITY target RTT T must be at most 2 ms; this is a hard requirement.

**Time to first byte.** For an HTTPS GET with a warm DNS cache:
- REALITY: about 1.30 s, or about 1.42 s at peak. REALITY dials the target on every connection (`REALITY tls.go:168`), so a target 20 ms away would add about 40 ms to every connection.
- Hysteria2 with a warm session: about 0.74 s.

**Throughput in `SameAsExit` mode.**
- The 5G uplink median is about 20.2 Mbps nationally on Three's network, against 16 Mbps on EE's (Opensignal via ISPreview, 29 Jan 2026; re-fetching the report on 2026-10-08 returned HTTP 429, so neither figure was re-verified). A national median says little about the exit site, which M2a and M2b measure; p10 may be about 5 Mbps.
- At MTU 1280, payload efficiency is 1228/1340, about 91.6%.
- That leaves about 15–18 Mbps of user payload **in total** at Three's median (about 12–14 Mbps at 16 Mbps, the uplink of the T-impair profile, §16), shared by every user's downloads *and* uploads.

**SIM volume (revision 6).**
- SMARTY's Unlimited plan has no fair-use line and no speed restriction ([SMARTY-PG] p11, §19.1), so the operator's hard stop is the only volume guard (§7). The pilot records a warning at 240e9 and a hard stop at 300e9 SIM bytes, in decimal bytes (F2; `PILOT_SIM_WARN_BYTES`, `PILOT_SIM_HARD_STOP_BYTES`).
- In `SameAsExit` mode each byte served costs about 2.1× on the SIM, the recorded estimate `SimFactor::SAME_AS_EXIT_ESTIMATE` (2100 ‰) until M8 measures the factor (§15.4). The 300e9 stop is then about 143e9 bytes served per cycle (300e9 × 1000 / 2100 ≈ 142.9e9), and the warning about 114e9. Automatic quotas divide that served budget (§15.3).
- In `Separate` mode the factor is about 1.04×, or about 288e9 bytes served per cycle at the same stop. This is the largest available gain.
- SMARTY counts usage in binary units (1 GB = 1024 MB, 1 MB = 1024 kB, 1 kB = 1024 bytes), per full MB, including re-sent packets and flow-control overhead ([SMARTY-PG] p23). The thresholds are decimal (F2), so this matters only when reconciling against SMARTY's own usage view (§15.3): the 300e9 stop is about 279.4 GB in SMARTY's units.
- Probing costs about 1 GB per month: in-chain probes every 300 s, direct probes every 30 s.

**MTU.** The MTU is fixed at **1280** in v1. M2 only confirms that the outer path MTU is at least 1340.

**Keepalive.** The keepalive is **10 s** (about 1 MB per day) until M2b measures the line's UDP NAT timeout (SMARTY on Three's network). After that it must lie in [5 s, NAT_timeout/2], and never above 60 s, which keeps three keepalives inside the watch's 180 s handshake window (`Keepalive`, §7). Measured cellular CGNAT UDP timeouts have a median of 65 s and a range of 10–200 s (arXiv 1605.05606).

**Policy defaults.** Each of these is a switch, and M3 confirms each by an A/B test:
- `block_quic = true`: UDP/443 to destinations is denied at the VPS. Browsers then fall back to TCP, which is split at the VPS and at the Mac.
- `routeOnly = true`: destinations are never rewritten.

**VPS sysctls.**
- `fq` and `bbr`.
- `tcp_slow_start_after_idle=0`.
- `tcp_notsent_lowat=131072`.
- `rmem_max` and `wmem_max` at 7500000.

**Fail-closed latency.** These are measured bounds, not promises. When the gate is closed, Xray freedom retries each dial 5 times, sleeping 0, 100, 200, 300 and 400 ms between attempts (Xray v26.9.30 `proxy/freedom/freedom.go:293`, `common/retry/retry.go:23-62`).
- A client connection to an IP literal therefore fails in about 1.0–1.5 s plus the China-leg RTT.
- A domain with a cold cache takes longer, because each DoH lookup through `exit` is retried the same way. L4 measures and records this bound.

**No shaping in v1.** cake/IFB and autorate are M10, which runs only if pilot data justifies them.

---

## 4. Engines, pins, builds and supply chain

| Artifact | Pin | Role |
|---|---|---|
| Xray-core | **v26.9.30** `b26a91d…` + `replace xtls/reality => e1986a4` | VPS: REALITY, loopback inbound, routing, DNS, stats |
| sing-box | **v1.14.2** `af6e64c…` | VPS: `mooring-hy2`. Mac: `mooring-exit` and `mooring-probe` |
| Go | **1.27.2**, with the darwin-arm64 and linux-amd64 tarball sha256 values pinned in `engines.lock.toml`. CFM moved to 1.27.2 for the Go advisories of 2026-10-08 (`f5b425d`, 2026-10-10) and builds the same gVisor fork with `with_gvisor` (CFM `scripts/dependency_pins.env:37-38,65` at `f5b425d`). Both values were checked on 2026-10-15 against `https://go.dev/dl/?mode=json&include=all` and the `.sha256` files at `https://dl.google.com/go/`, and the darwin-arm64 value against CFM's pin. A Go point release with security fixes is pinned again and rebuilds every engine (§4.4). | All engine builds |
| govulncheck | Newest stable at M0, version and module sum pinned (CFM pins v1.6.0, `dependency_pins.env:42-43` at `f5b425d`) | Vulnerability gate |
| Geodata | `geoip.dat` and `geosite.dat` from the official `Xray-linux-64.zip` of v26.9.30, sha256 recorded in `engines.lock.toml` at the first build (Level 1) | `geoip:cn` / `geosite:cn` |
| RealiTLScanner | v0.2.3, built from a pinned commit with the same Go, sha256 in `engines.lock.toml` | Operator-run target discovery |
| Debian | 13 (trixie), the current point release at M2; kernel 6.12 series | VPS OS |
| Rust | 1.98.1 (`rust-toolchain.toml`) | All Rust |
| Swift | 6.4 via `xcrun` (Xcode 27), never the bare `swift` on PATH | App and power helper |

### 4.1 Build recipes

All builds run through `cargo xtask engines-build`, with `GOTOOLCHAIN=local`, `-mod=readonly`, `CGO_ENABLED=0` and `-trimpath`.

**Xray** (linux-amd64, plus linux-arm64 for the local lanes). Flags from upstream `xray-release.yml:208-218`:
```
go build -trimpath -buildvcs=false -gcflags="all=-l=4" \
  -ldflags="-X github.com/xtls/xray-core/core.build=v26.9.30 -s -w -buildid=" -o xray ./main
```

**sing-box.** Flags from upstream `release/LDFLAGS` and `release/DEFAULT_BUILD_TAGS` (re-read at af6e64c):
```
go build -trimpath -tags "<role tags>,badlinkname,tfogo_checklinkname0" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.2' \
            -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=" ./cmd/sing-box
```

| Binary | Target | Role tags |
|---|---|---|
| `mooring-exit` | darwin-arm64 | `with_gvisor,with_wireguard` |
| `mooring-probe` | darwin-arm64 | `with_quic,with_utls` |
| `mooring-hy2` | linux-amd64/arm64 | `with_quic` |

**Darwin is built purego.** Upstream builds darwin with `CGO_ENABLED=1` (`sb-build.yml:538-542`). M0 and L6 verify `check`, interface binding and gVisor on darwin without cgo. Switching to cgo would be a reviewed decision.

**Gates, enforced permanently in `xtask engines verify` and the release verifier:**
- Two clean builds produce byte-identical **unsigned** outputs, and those match the sha256 values in `engines.lock.toml`. Darwin binaries are compared before codesign.
- `go version -m <bin>` shows the pinned Go version, the pinned main module (since 2026-10-23), `-trimpath`, `CGO_ENABLED=0`, the target, Xray's gcflags and the exact tag set (including `badlinkname,tfogo_checklinkname0` for sing-box). It cannot show the ldflags: under `-trimpath` cmd/go records none (go1.27.3 `src/cmd/go/internal/load/pkg.go:2469-2481`, go.dev/issue/52372; found by the first hosted run, 2026-10-23), and a recorded `-ldflags` is refused as a toolchain change to review. The ldflags are checked by their effects instead: every binary's build ID is empty, as the `-buildid=` inside the single `-ldflags` argument makes it, and the binaries built for the runner print their `-X` version stamps (`xray version`, `mooring-hy2 version`); RealiTLScanner has no version variable, so its recipe stamps nothing and it is never run for one. `godebugDefault`, `-checklinkname=0` and `-s -w` leave no stamp of their own; the pinned digests hold the bytes they produce.
- Upstream package tests pass under the pinned Go: Xray `proxy/vless` and `transport/internet/reality`; sing-box `protocol/hysteria2` and `protocol/wireguard`. RealiTLScanner has no tests at its pinned commit. If either fails, a reviewed commit pins the newest Go 1.26 patch (go1.26.9 on go.dev on 2026-10-15) and records the reason.
- `govulncheck` runs with the exact role tags against each engine's module graph. A reachable finding blocks the release until a reviewed dependency bump lands (§4.4).

**Binary names.** The sing-box binaries ship as `mooring-exit`, `mooring-probe` and `mooring-hy2`. The sing-box name appears only in `ThirdPartyNotices`, because sing-box's LICENSE (lines 16-17) adds a naming term.

### 4.2 Xray v26.9.30 with REALITY pinned to e1986a4 (user decision, 2026-10-08)

**The constraint.**
- sing-box clients, including CFM 0.4 (1.14.1) and 0.5 (1.14.2), strip the X25519MLKEM768 key share unless CFM's opt-in is set, and always send client version 1.8.1 (`common/tls/reality_client.go:145-158,186-188`).
- REALITY commit 8cdf7bf9 (2026-09-08) rejects any ClientHello without an X25519MLKEM768 share before X25519, with no configuration switch. Xray v26.9.30 (`b26a91de`, a prerelease) pins exactly that commit (`go.mod:23`). sing-box #4520 reproduces the failure.

**The decision.** Build Xray v26.9.30 from source with `go.mod replace github.com/xtls/reality => github.com/xtls/reality@e1986a4d31ca33c087a72ab4644aef1295693b69`. The user chose this over v26.3.27 stable on 2026-10-08.
- `e1986a4` is the direct parent of 8cdf7bf9. The two differ only in `tls.go`: 8cdf7bf9 adds the mandatory-hybrid check and nothing else (`git diff e1986a4 8cdf7bf -- tls.go`).
- At `e1986a4` the server takes a separate X25519 share first, and otherwise the X25519 half of X25519MLKEM768 (`tls.go:215-235`). It therefore accepts both current CFM clients (classical only) and hybrid clients (CFM with `support_x25519mlkem768`, Xray ≥ v25.5.16, mihomo with the opt-in).
- When the target selects X25519MLKEM768, the server performs a real ML-KEM-768 encapsulation (`handshake_server_tls13.go:115-130`). The outer session is post-quantum only when the client sends the hybrid share **and** the target negotiates it (§11.7 records the target's group).
- `e1986a4` includes the PR #36 panic fix (`record_detect.go`) and the PR #33 17 KiB target-record buffer.
- The CFM 0.5 session verified this in real interop on 2026-10-08: e1986a4 accepts hybrid off (X25519) and hybrid on (X25519MLKEM768); 8cdf7bf rejects hybrid off.

**Cost, stated plainly.** v26.9.30 is a prerelease, and the replace directive departs from upstream's pinned dependency. Both are recorded in `engines.lock.toml`. M0 must prove: the replaced module builds with `-mod=readonly`, upstream `proxy/vless` and `transport/internet/reality` package tests pass, `git merge-base --is-ancestor e1986a4 8cdf7bf9` holds, and T-xray-lock passes.

**Exit path.** Drop the replace and track upstream stable once both hold: an Xray stable release contains the mandatory-hybrid rule, and every Active user's client line has the `RealityMlkemOptIn` capability with exports carrying it (§7, §9). CFM's 0.5 line implements that opt-in (`tls.reality.support_x25519mlkem768`, Clash `reality-opts.support-x25519mlkem768`, chrome fingerprint only).

**Mitigations that remain:** target qualification (§11.7), `MemoryMax` and the start limit, the `EngineCrashLoop` and `TargetDegraded` signals, and the standby node.

### 4.3 Licences (not legal advice)

- **Xray** is MPL-2.0. REALITY's `LICENSE-Go` is BSD-3. Ship the notices and a pointer to the exact source commit.
- **sing-box** is GPL-3.0-or-later with the naming term. GPL §6 obligations apply only if binaries are conveyed to others. Uploading to the operator's own VPS is not conveyance *(inference)*. If Mooring is ever distributed, the corresponding source is the tagged repository plus the pinned upstream commits.
- **Geodata licences** are checked in M0.

### 4.4 Dependency-bump policy

**Go engines.**
- A reachable govulncheck finding is fixed by a reviewed bump of that module to its latest stable version (`go get <module>@<stable>`). The `go.mod`/`go.sum` diff is recorded as a patch under `engines/patches/` with its sha256 in `engines.lock.toml`, in the same way CFM's 0.5 line carries `native/macos/patches/sing-box-v1.14.2-security-dependencies.patch`. At `f5b425d` that patch takes `golang.org/x/crypto` from upstream v1.14.2's v0.54.0 to v0.57.0 and `golang.org/x/net` from v0.57.0 to v0.60.0 (`:714-727`): x/crypto v0.57.0 and x/net v0.59.0 came with a dependency refresh at `49a16d4` (2026-09-25), and x/net v0.60.0 with `f5b425d` for the Go advisories of 2026-10-08. Whether Mooring's sing-box and Xray builds need any of these bumps is for M0's govulncheck run to decide *(inference: at least x/net, whose advisory the same upstream pin carries)*.
- A Go point release with security fixes triggers a rebuild of every engine.
- govulncheck runs on every output with its own tags and target in every hosted engine build (`cargo xtask engines-govulncheck`), and the build runs again monthly and before every release. A reviewed bump is listed in the lock's `security-bumps`; `engines-prepare` makes the go.mod/go.sum patch from the lock on the hosted runner, scans the patched trees, and the patch is reviewed against sum.golang.org and pinned before any build uses it.

**Rust.** `cargo deny` runs with `multiple-versions = "deny"`.
- Direct crypto dependencies use one generation: `x25519-dalek 3.0.0`, `ed25519-dalek 3.0.0`, `sha2 0.11.0`, `getrandom 0.4.x`, `rand_core 0.10` (crates.io index, 2026-10-08).
- Transitive duplicates outside our control, such as `ring 0.17.14` → `getrandom 0.2`, are listed as `skip` entries, each with a reason and an upstream link. `multiple-versions-include-dev = true`, so dev-only duplicates (proptest's `rand_core 0.9`) count too and the list matches `cargo tree -d`. At M1 the entries are `getrandom@0.2.17`, `getrandom@0.3.4`, `rand_core@0.9.5` and `syn@2.0.119` (`deny.toml`).
- `cargo xtask deny-skips`, a `ci` step, asserts that the skip list equals the duplicates actually present for the `[graph]` targets, with the older versions skipped and the newest kept, so no skip entry can go stale.

---

## 5. Processes, units and ports

### 5.1 Mac

| Process | Started by | Responsibilities |
|---|---|---|
| `Mooring.app` (Swift, LSUIElement; login item via `SMAppService.mainApp`) | The user, or login | Registers the agent with `SMAppService.agent(plistName: "com.bill.mooring.daemon.plist")`. Shows `AgentNotEnabled{status}` with a link to Login Items when the status is `.requiresApproval`. Consumes `mooringctl status --follow --json`, a typed JSON-lines stream. Runs `mooringctl … --json` for actions. Never reads secrets or daemon files. |
| `mooringctl daemon` (Rust LaunchAgent) | launchd | Interface resolution, preflight, rendering, supervising both engines, probes and verdicts, latches, the SIM meter, the sleep drain, the control socket. It is the **only** process besides the CLI that reads secrets (same binary, same keychain identity). *(Revision 9)* Before `exit init` there is no exit to serve, and it runs as the router console: it polls the M7 every 60 s (§15.6) and serves the console's status (§10.1, §15.1), on the interface given as `--router-interface <bsd>` until 2026-10-23, and since then (M7) on the one the router pin records (`router pin --interface`, the pin's version 2). The slice built in revision 9 did only that, and refused to start while a deployment existed. *Built 2026-10-23 (M5c):* with a deployment it runs the exit, at once if the deployment is there when it starts, or from its next poll when `exit init` creates one: it resolves the interfaces, checks for foreign networks, meters the SIM, supervises `mooring-exit` from the support directory's `engines/` (the hosted build's `out/`, checked against the pin compiled into it before every start), probes, latches and tells the nodes (§10.2), polls the M7 through the egress, and publishes the deployment's status. *Since then:* `mooring-probe`, the in-chain probes and the node polls (M5d), and the power helper and the sleep drain (M7, §10.3). |
| `mooring-exit` | daemon | Receives its config on stdin (`check -c stdin`, then `run -c stdin`; `cmd/sing-box/cmd_run.go:53`). Runs the WireGuard endpoints (one per node, at most 2) and the bound `egress`. |
| `mooring-probe` | daemon | Receives its config on stdin. Runs the loopback probe inbounds and the exported probe outbounds. A failure here maps only to `NodeProbeFailed`; it never takes the exit down. |
| `mooring-power` (Swift) | daemon; stdin is its lifetime pipe | While the exit is enabled and the Mac is on AC, holds `NetworkClientActive` and `PreventUserIdleSystemSleep`. `PreventSystemSleep` is not used: the macOS 27 SDK `IOPMLib.h:1014-1023` marks it deprecated and unsupported. Emits `will_sleep`, `did_wake` and `power_source`, and calls `IOAllowPowerChange` when the daemon acknowledges. Releases everything and exits at EOF. *Built 2026-10-23 (M7):* `apple/Power` over MooringKit's `MooringPower` library, built by Xcode beside the app's executable (`Contents/MacOS/mooring-power`) and signed by `xtask app` as `com.bill.mooring.power`, with the hardened runtime, before the bundle. Its protocol is one JSON line each way, at most 256 bytes (`daemon-core::power`, pinned by `contract/power-fixtures/protocol.json`, which the Swift tests read): `power_source`, `assertions{held}`, `will_sleep{id}` and `did_wake` out; `hold` and `allow_sleep{id}` in. Its first line is the power source, and the daemon waits 5 s for it: a helper that does not start, or whose first line within those 5 s is not the power source, stops the daemon, since the bundle that carries the daemon carries the helper. A sleep the daemon has not answered within 25 s proceeds anyway, inside IOKit's 30 s window. A helper that ends later, or cannot be written to, degrades the exit (`PowerHelperExited`) and is started again 60 s later; a closed one is reaped, and killed if it has not exited within 1 s, so none is left a zombie. The daemon no longer reads `/usr/bin/pmset`. |

**Bundle layout.** The data-protection Keychain needs an entitled bundle with a provisioning profile, following the CFM ProxyAgent pattern (`project.yml:340-356`).
```
Mooring.app/Contents/
  MacOS/Mooring
  Library/LaunchAgents/com.bill.mooring.daemon.plist      BundleProgram → Library/Helpers/MooringAgent.app/Contents/MacOS/mooringctl
  Library/Helpers/MooringAgent.app/Contents/
    MacOS/mooringctl         keychain-access-groups <TEAM>.com.bill.mooring.secrets, embedded.provisionprofile
    MacOS/mooring-power
    Helpers/MooringExit.app/Contents/MacOS/mooring-exit     App Sandbox (network.client) if the M5 spike passes
    Helpers/MooringProbe.app/Contents/MacOS/mooring-probe   App Sandbox (network.client + network.server) if the spike passes
    Resources/vps/{amd64,arm64}/{mooring-agent, xray, mooring-hy2}, geodata/{geoip.dat,geosite.dat}, MANIFEST.json
  Resources/ThirdPartyNotices.txt
```

**LaunchAgent plist.**
- `ProgramArguments=[mooringctl, daemon]`, `KeepAlive=true`, `RunAtLoad=true`, `ProcessType=Standard`, `ThrottleInterval=10`.
- `SoftResourceLimits.NumberOfFiles` is set above the exit flow cap plus headroom. It defaults to 16384 and is fixed from M2 data.
- `AssociatedBundleIdentifiers=com.bill.mooring`.

**Local network privacy (revision 9).** macOS applies it to launchd agents: TN3179 ("Understanding local network privacy", read 2026-10-22) says macOS allows local network access to launchd daemons, root and command-line tools run from Terminal or over SSH, and that the daemon exception does not apply to agents; an agent not installed with `SMAppService` names its responsible app with `AssociatedBundleIdentifiers`, whose `NSLocalNetworkUsageDescription` the alert shows. Measured 2026-10-22 on macOS 27.0.1: an ad-hoc-signed `mooringctl router capture --anonymous` started by launchd as an agent, with no association, failed to connect to the M7 with `EHOSTUNREACH` ("host unreachable"), while the same binary from a shell reached it and passed the identity check. So the plist names the app (above), `Mooring.app`'s `Info.plist` carries `NSLocalNetworkUsageDescription`, and the first poll asks the operator to allow it. TN3179 also notes that macOS tracks the identity by code signature, which an ad-hoc signature does not keep across builds *(inference: a rebuilt development app may be asked again)*, and that a process that exits at once after a refused connection never shows the alert; the daemon does not exit.

**Development install (revision 9; since 2026-10-23, M7, the app registers the daemon).** `cargo xtask app` builds `target/app/Mooring.app` with the signed `mooringctl` at `Contents/MacOS/mooringctl` (the entitled `MooringAgent.app` helper above waits for M5's data-protection keychain) and the daemon's plist, `apple/App/LaunchAgents/com.bill.mooring.daemon.plist`, at `Contents/Library/LaunchAgents/` (copied unprocessed by an Xcode copy phase, and checked byte for byte by `xtask app`). The plist runs `BundleProgram` `Contents/MacOS/mooringctl` with the arguments `mooringctl daemon`, `KeepAlive` and `RunAtLoad`, `ProcessType` `Standard`, `ThrottleInterval` 60 s (a daemon that keeps failing asks the M7 at most once a minute, §15.6 rule 7), `ExitTimeOut` 5 s, `SoftResourceLimits` `NumberOfFiles` 16384, and `AssociatedBundleIdentifiers` naming the app; it names no interface and no log. Mooring.app registers it with `SMAppService.agent(plistName:)` when the operator chooses **Start the Daemon at Login**, and unregisters it with **Stop the Daemon**; while it is not registered, or waits for approval in Login Items (`AgentNotEnabled`), the console says so above every screen. *Measured 2026-10-23 on macOS 27.0, with a throwaway agent under another label:* an ad-hoc-signed app's registration was enabled at once (no approval; macOS notified "background item added"), and unregistering removed the job (Background Task Management keeps a disabled record of it). A never-registered agent reports `.notFound`, one unregistered since `.notRegistered`; the app reads both as not registered. *Corrected 2026-10-24:* that test's rebuild signed the same bytes again, so its cdhash did not change, and its finding that a registration lasts a rebuild and `launchctl kickstart -k` starts the new executable does not hold for a changed executable. The registration pins the executable's code signature, an ad-hoc one by its cdhash (`launchctl print` shows `LWCR = { "reqs" => { "cdhash" => { "$in" => [ … ] } } }`). After the first real rebuild, on 2026-10-23, launchd refused every start of the new `mooringctl` (job state "spawn failed", last exit code 78 `EX_CONFIG`, properties "needs LWCR update"), 204 times in three hours, until the app registered the daemon again (**Stop the Daemon**, then **Start the Daemon at Login**), which pins the new cdhash. So `cargo xtask app`, which would replace the executable the daemon runs, is refused while the daemon is loaded, before anything is built, and so is `cargo xtask clean`, which would delete it: the operator stops the daemon, builds, and starts it again from the new build, and macOS asks again for the keychain, the ad-hoc signature having changed. The daemon reads the M7's interface from the router pin (version 2 records it; a version-1 pin, written before 2026-10-23, is read as one without an interface, and the router console then says it is not set up until `router pin --interface <bsd>` records it, without asking again for the same address) and writes its own log (§15.10), so the development install differs from a release's only in its signature. The app and its `mooringctl` are signed ad hoc with the hardened runtime (`--options runtime`), which refuses injected libraries: that `mooringctl` is the code the keychain item trusts, and without it a process of the same user could load a library into it (`DYLD_INSERT_LIBRARIES`, set for launchd's next start) and read the M7's password unprompted. *Until 2026-10-23* `cargo xtask agent-install <bsd>` wrote a plist with `--router-interface <bsd>` and `StandardErrorPath` to `target/launchd/` and loaded it with `launchctl bootstrap gui/<uid>`, so it lasted until logout; a Mac that ran it stops that agent once (`launchctl bootout gui/<uid>/com.bill.mooring.daemon`) before the app registers its own under the same label (`docs/runbooks/console.md`).

The exit runs only while the operator is logged in. After a FileVault reboot, someone must log in first.

### 5.2 VPS units

| Unit | User | Capabilities | Content |
|---|---|---|---|
| `mooring-xray.service` | `mooring-xray` | `CAP_NET_BIND_SERVICE` | `xray run -c /etc/mooring/current/xray.json`, `XRAY_LOCATION_ASSET=/opt/mooring/engines/geodata/current`. `BindsTo=` and `After=wg-quick@wgexit.service nftables.service`. `ExecCondition=agent halted-check`. |
| `mooring-hy2.service` | `mooring-hy2` | none (port 61000) | `mooring-hy2 run -c /etc/mooring/current/hy2.json`. `After=mooring-xray.service nftables.service`. `ExecCondition=agent halted-check`. |
| `wg-quick@wgexit.service` | root | — | `/etc/wireguard/wgexit.conf` → `current/` |
| `nftables.service` | root | — | `/etc/nftables.conf` → `current/` |
| `mooring-watch.service` | `mooring-watch` (group `mooring`) | `CAP_NET_ADMIN` only | The **only** process that opens the gate. Holds, accounting, target checks, status. 5 s loop. `Restart=always`, `RestartSec=2`, `StartLimitIntervalSec=0`, `ExecStopPost=agent gate-close`. |
| `mooring-reflect.service` | `DynamicUser=yes` | none | `agent reflect` on `<VPS4>:27900`, the uplink's address, which it reads at start as `Hello` does (M4e) |
| `mooring-alert.service` and its timer *(plan, M4; decision F6)* | `DynamicUser=yes` | none | Sends the ntfy notices the Mac rendered (§15.8) and pings the Healthchecks checks that `dead_man_pings` selects, with curl to the fixed origins `https://ntfy.sh` and `https://hc-ping.com`. The deployment's ntfy topic and the node's own check UUIDs arrive through `LoadCredential=`. The digest timer is `OnCalendar=*-*-* 09:00:00 Europe/London`, rendered from `AlertSettings` (§7). No unit renderer exists yet; it is built with the agent in M4. |
| sshd | root, forced command only; the viewer as `mooring-view` | — | `restrict,command="/usr/local/lib/mooring/agent/current serve-ssh --role ops"`. Host profile 2 (§8.6) adds the unprivileged `mooring-view` account: its keys come from `viewer_authorized_keys` with `restrict,command="… serve-ssh --role viewer"`, and its `Match User` block forces the same command |
| chrony, unattended-upgrades | Debian | — | Time sync for `maxTimeDiff`. Security updates, with automatic reboot at 20:00 UTC (04:00 China). |

**Hardening on the engine, watch and reflect units.**
- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`.
- `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`.
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, `RestrictNamespaces`, `LockPersonality`, `SystemCallArchitectures=native`.
- `LimitNOFILE=65535`.
- `ReadWritePaths` covering only the unit's own directories.

**Memory and restart limits.**
- `mooring-xray`: `MemoryMax=600M`, `TasksMax=1024`, `Environment=GOMEMLIMIT=480MiB`.
- `mooring-hy2`: `MemoryMax=200M`, `TasksMax=512`, `GOMEMLIMIT=160MiB`.
- These values are initial and are tuned in M4/M8.
- Engine units use `Restart=on-failure`. `StartLimitIntervalSec=600` and `StartLimitBurst=5` go in `[Unit]`.

**Built 2026-10-23 (M4e): the units are host-profile files.** Every unit above that is Mooring's (`mooring-xray`, `mooring-hy2`, `mooring-watch`, `mooring-reflect`, `mooring-txn-recover.service`, the oneshot that runs `agent txn-recover` at boot after the ruleset, the tunnel and both engines, and `mooring-target-check.service` with its hourly timer, §11.7) is a file of host profile 2 (§8.6), with its exact text pinned by agent-proto's tests: installed by `Bootstrap`, converged by every transaction and enabled with `nftables.service` and `wg-quick@wgexit.service`. The text is the same on every node: the reflector reads its address itself. The alert unit and its timer come with the alert slice. What the text adds to the table:
- The engines' `ExecCondition` runs as root (`+`), because `halted.json` is the state group's and an engine's user cannot read it (a marker it cannot read would count as halted and never let it start). They start only once a generation is installed (`ConditionPathExists` on their configuration), and a drop-in for Debian's `wg-quick@wgexit.service` skips the tunnel until then, so before the first `Apply` a boot leaves no failed unit (checked in a Debian 13 VM on 2026-10-23).
- The watch runs as `mooring-watch` in the group `mooring` with `CAP_NET_ADMIN` only, `ProtectSystem=strict`, and `ReadWritePaths` exactly the directories its account or group may write (`/var/lib/mooring/{gate,stop,watch,usage}` and `/run/mooring`, derived from the layout below); its `ExecStopPost` runs as root. In the VM, `nft`, `wg`, `systemctl show` and `chronyc -n tracking` all worked from inside that sandbox.

### 5.3 Ports

Debian's `ip_local_port_range` is 32768-60999. Every fixed port lies outside it, and the hop ranges lie above it. This is a model invariant (`PortPlan`, §7), checked against the range `Hello` reported at adoption, which the plan records. Each `Apply` header carries that range, and the agent refuses the transaction with `PortPlanConflict{recorded, live}` if the live range has changed since.

| Port | Proto | Owner | Exposure |
|---|---|---|---|
| 22 | tcp | sshd (forced command) | public (`ip daddr $VPS4`) |
| 80 | tcp | Xray `camo-80` → target IP:80 | public, per-source connection cap |
| 443 | tcp | Xray REALITY | public, no limit |
| 443 | udp | Xray `camo-u443` → target IP:443 | public, per-source new-flow limit |
| 61000, with 61001-62999 redirected to it | udp | Hysteria2 listener 0 | public |
| 63000-64999 | udp | reserved for Hysteria2 listener 1 (a future second obfs) | closed in v1 |
| 27820 | udp | kernel WireGuard | public |
| 27900 | tcp | reflector | public, per-source limit |
| 10085 | tcp | Xray StatsService | 127.0.0.1 |
| 10443 | tcp | Xray `hy2-loop-in` | 127.0.0.1 |
| Mac 47101 and up | tcp | `mooring-probe` inbounds | 127.0.0.1 (the macOS ephemeral range is 49152-65535) |

**Side benefit** *(inference)*. The GFW's QUIC filter skips datagrams whose source port is not above their destination port (USENIX Security 2025). Destination ports of 61000 and up therefore leave most client ports uninspected. Salamander remains the primary protection.

---

## 6. Repository

```
mooring/
  LICENSE  README.md  CHANGELOG.md  SECURITY.md
  Cargo.toml  Cargo.lock  rust-toolchain.toml  deny.toml  rustfmt.toml  .cargo/config.toml
  engines.lock.toml        Go tarball sha256; engine tag+commit; role tags; ldflags; patches+sha; geodata zip sha; per-target output sha256
  engines/patches/         reviewed go.mod bumps and the optional REALITY replace (empty at M0)
  crates/
    model/       mooring-model        pure types and invariants: SPECIAL_V4, PortPlan, newtypes, Secret<T> (zeroize, redacted Debug),
                                      SecretRef, SecretEntry, SecretSnapshot, ResolvedInterfaces, EgressCheck, verdict precedence,
                                      target::qualify, Bookkeeping, the one SHA-256 helper (Sha256Digest::of, SpkiSha256::of),
                                      the kinds! macro, exact-capacity zeroizing writers; forbid(unsafe)
    keys/        mooring-keys         UUIDv4, x25519 (REALITY b64url / WG b64), ShortId, passwords, rcgen P-256 cert (pins are derived
                                      by export), ed25519 + OpenSSH key encoder (openssh-key-v1, known_hosts, SHA256 fingerprint)
    export/      mooring-export       pure: CFM sing-box JSON + Clash YAML emitters by ClientProfile; shape enumeration; certificate
                                      pin derivation and runtime cert checks
    agent-proto/ mooring-agent-proto  request/response/error types, framing, ManagedFile, HostProfile, WatchConfig, PROTOCOL, frozen core,
                                      the VPS contract names (src/vps.rs), StderrTail; revision 6: the Mac report (src/report.rs),
                                      the notice grammar (src/notice.rs), the dead-man ping rule (src/deadman.rs)
    render/      mooring-render       pure: VPS bundle, Mac exit config, Mac prober config (MacProbeOutbound), cloud-init;
                                      the model <-> agent-proto conversions (src/wire.rs)
    store/       mooring-store        state.json (shared read lock, exclusive write lock + CAS + atomic write + migration chain);
                                      SecretStore trait; in-memory impl (the data-protection Keychain impl is M5); revision 7: the
                                      router identity file `router-identity.json` (src/router_pin.rs)
    fixtures/    mooring-fixtures     (test-only) four deterministic fixture deployments with their secrets and resolved
                                      interfaces, for goldens; never a normal or build dependency
    macsys/      mooring-macsys       macOS only (cfg(target_os = "macos"): empty elsewhere), the ONLY crate with unsafe (libc only). Built in revision 7: interface index, the IPv4
                                      default routes and neighbour table (PF_ROUTE sysctl), so the gateway's link-layer address, and the
                                      terminal echo guard. Built 2026-10-22 for fieldkit (M2b): the interface list (NET_RT_IFLIST2:
                                      name, own link-layer address, flags, MTU, if_data64 byte counters, IPv4 addresses) and the
                                      open-files limit (RLIMIT_NOFILE). Later: the PF_ROUTE monitor (M5)
    daemon-core/ mooring-daemon-core  daemon state machine, verdicts, probe primitive, latches, control protocol; traits for interfaces,
                                      engines, clock, power, secrets, ssh, router; console (revision 5, §15): MacStatusV1, event journal
                                      and availability, alert machine, SIM forecast, capacity monitor, the MR7450 `model.json` allowlist parser and redactor (revision 7),
                                      the foreign-network check (P0-2); revision 6: automatic quotas, push notices and the digest,
                                      the remote viewer's report
    mooringctl/  (bin) cli, daemon wiring, supervise, ssh (incl. the bound dial and its relay), provision, usage, status stream; the read-only
                       M7 HTTP client bound to the egress; journal and Mac usage files. Built in revision 7 (macOS only; elsewhere a stub
                       that exits 1):
                       `router pin | set-password | status | capture`, the bound HTTP/1.1 client, the legacy login-keychain
                       SecretStore (`LoginKeychain`) for the M7's admin password
    mooring-agent/ (bin, x86_64/aarch64-unknown-linux-musl) bootstrap, serve-ssh, txn, watch, reflect, target-check, accounting, self-test.
                 Built 2026-10-22 (M4a): serve-ssh (Hello, blobs, gate, halt, Mac report), reflect, halted-check, gate-close, self-test
                 Built 2026-10-22 (M4b): Apply, TxnStatus, Confirm, Rollback, ActivateAgent, Resume; txn, txn-revert, txn-recover
                 Built 2026-10-22 (M4c): watch (gate, holds, the viewer's stop, conditions, host readings, the journal), Events
                 Built 2026-10-23 (M4d): accounting (polls, usage files, series, retention, the canary), engines, uplink transfer; Status, Usage, UsageSeries
    e2e/         (dev-only) netns harness and lab harness; never built for release
    fieldkit/    (dev-only bin, darwin + linux-musl) M2 field measurements (the router capture is `mooringctl router capture` since revision 7); never shipped.
                 Built 2026-10-22: `serve` (the VPS side) and `env`, `udp-nat-timeout`, `nat-behaviour`, `public-ips`, `pooling`,
                 `port-ceiling`, `uplink`, `rtt` (the Mac side), §22 M2b
  xtask/         M1: ci, graph-check, kinds-coverage, deny-skips, acceptance, release-acceptance, clean.
                 Revision 7: mooringctl (builds mooringctl and signs a copy, target/signed/mooringctl, as com.bill.mooring.mooringctl; macOS only, not a ci step; §15.6 rule 10).
                 Revision 9: app (builds target/app/Mooring.app with that copy inside), agent-install <bsd> and agent-uninstall (the development LaunchAgent); macOS only, not ci steps (§5.1).
                 2026-10-23 (M7): app also checks the daemon's plist in the bundle; agent-install and agent-uninstall are gone (the app registers the daemon with SMAppService).
                 2026-10-24: app is refused while the daemon is registered (launchd starts only the mooringctl it was registered with), instead of restarting it with `launchctl kickstart -k`.
                 2026-10-22: fieldkit (builds fieldkit and signs a copy, target/signed/fieldkit, as com.bill.mooring.fieldkit, the same way; macOS only, not a ci step).
                 Later: engines {build,verify,upstream-tests,audit}, govulncheck, cfm-client, lane <name>, m0 …, release, release-verify
  apple/         project.yml (XcodeGen); Packages/MooringKit (swift-tools 6.2, macOS 15, .v6); App/; Power/; Tests/
                 Built in revision 9: project.yml, Packages/MooringKit (the console's Codable mirror, the status stream, its tests) and App/ (the overview and router screens, Localizable.xcstrings); the generated Mooring.xcodeproj is not kept
  contract/console-fixtures/   revision 9: the ConsoleStatus documents (no-deployment, no-deployment-router-unavailable, deployed)
  contract/      golden/<fixture>/…, cfm-acceptance.toml, cfm-manifest.toml, status-fixtures/*.json, cli-fixtures/*.json, agent-proto-golden/*
  lanes/         netns/{topology.sh, impair.sh, nat-profiles.sh, ablation.toml}, vm/{qemu-debian13-amd64/, lima-debian13-arm64-lab.yaml}, staging/checklist.md
  docs/          design.md threat-model.md performance.md engines.md cfm-contract.md measurements/
                 runbooks/{provision,rotate,revoke,retire,incident,console-recovery,mac-loss,delivery}.md
                 runbooks/ added in revision 5: exit-host, power-cut, sim-plan, user-onboarding (Simplified Chinese),
                 support-triage, abuse-response, carrier-swap, upgrade, capacity-review, absence, legal-notes;
                 backup-restore only if F18 adopts backups
                 runbooks/ added in revision 8: user-agreement (Simplified Chinese; its revision is AgreementVersion::CURRENT, F9).
                 user-onboarding and user-agreement are in Simplified Chinese; every other runbook, delivery included, is in English.
                 delivery, user-onboarding and user-agreement exist since revision 8; exit-host, power-cut and sim-plan, which M8 also needs, not yet
```

### 6.1 Dependency edges

`xtask graph-check` asserts exactly this edge set using the declared dependencies in `cargo metadata` (so optional and target-specific edges count). Normal and dev edges must each equal the table (`ALLOWED_EDGES` in `xtask/src/graph_check.rs`), no build edge may join two workspace crates, and a test-only crate (`TEST_ONLY_CRATES`: `mooring-fixtures`) may never be a normal or build dependency. Rows for crates that do not exist yet are the plan; each joins `ALLOWED_EDGES` with its crate.

| Crate | Depends on | Dev-dependencies (tests only) |
|---|---|---|
| `model` | — | — |
| `keys` | `model` | — |
| `export` | `model` | `keys`, `fixtures` |
| `agent-proto` | — | — |
| `render` | `model`, `export`, `agent-proto` | `keys`, `fixtures` |
| `store` | `model` | — |
| `fixtures` | `model` | — |
| `xtask` | `export` (shape enumeration for `cargo xtask acceptance`, §9.3), `model` (`Sha256Digest` for the contract files' SHA-256 values); external `toml`, which no other crate uses | — |
| `macsys` | — (libc only). A workspace member since revision 7; this row and `ALLOWED_EDGES` match | — |
| `daemon-core` | `model` and `agent-proto` for the console's pure types (§15). Built: `MacStatusV1`, the usage periods and shares, usage aggregation and activity, the SIM forecast, the capacity monitor, the alert machine, quota and expiry evaluation (with the automatic quota of revision 6), the router-status types, the foreign-network check, (revision 6) the push notices and digest (`notify`) and the remote viewer's report (`report`), and (revision 7) the MR7450 allowlist parser and redactor (`router::netgear`), and (revision 9) the console's document and control lines (`console`, `control`) and the settings the exit needs off (`RouterStatus::advisories`). Planned, with M5: the event journal and availability. They are functions of the model's records (`Deployment`, `SimPolicy`, `UplinkBaseline`, users) and agent-proto's frames (`StatusV1`, `UsageSeriesV1`). `render` and `export` join with the state machine, which renders the exit and prober configs (M5). File, Keychain, network and router I/O reach the crate through traits that `mooringctl` implements, so it has no `store`, `keys` or `macsys` edge. A workspace member; this row and `ALLOWED_EDGES` match | `fixtures` |
| `mooringctl` | `model`, `keys`, `render`, `export`, `agent-proto`, `store`, `macsys`, `daemon-core`. Built (revision 7): `model`, `store`, `macsys`, `daemon-core`; `export` with `user export` and `keys` with `user add` (M5); `render` and `agent-proto` with the node commands (M5b, 2026-10-23). A workspace member; this row and `ALLOWED_EDGES` match | `fixtures` (M5: the user commands' tests) |
| `mooring-agent` | `agent-proto` only, plus std, serde, serde_json, thiserror and sha2. **The VPS never renders.** For that reason the dead-man ping rule, which a node applies while the Mac may be gone, lives in agent-proto (`dead_man_pings`), and the notices the node sends are rendered on the Mac into agent-proto's notice grammar (§15.8) | |
| `e2e` | `model`, `keys`, `render`, `export`, `agent-proto`, `daemon-core` | |
| `fieldkit` | `model` (the types its measurements decide: `UplinkBaseline`, `Keepalive`, `Pairing`, `InterfaceSelector`), and `macsys` on macOS (the interface list and the open-files limit, 2026-10-22). This row and `ALLOWED_EDGES` match | |

**The cost of xtask's product edges (D-9).** The xtask edges are normal dependencies, so every `cargo xtask` command, `clean` and `graph-check` included, first compiles `export` and `model` and their dependencies (x509-parser among them; about 60 crates instead of serde, serde_json and thiserror), and stops if they do not compile. While the tree does not build, free the disk with `rm -rf target` instead of `cargo xtask clean`. x509-parser is also built a second time with xtask's narrower feature set, which costs space in the bounded `target/` (D-7).

Two Mac-side crates see both the model and the wire types, and each keeps its model ↔ agent-proto conversions in one module. `render` builds what a node is sent and records what it reports at adoption, in `crates/render/src/wire.rs` (adoption site, `Apply` header facts, target facts, SSH host-key lines). Rules that both sides validate (interface names, DNS names, port ranges, certificate names, HTTP statuses) are the same rule on each side, which a cross-crate property test in `crates/render/src/tests/wire_rules.rs` proves. `daemon-core` reads what a node reports to the console, in `crates/daemon-core/src/wire.rs`: instants, and an accounting principal back to its `UserId`, the inverse of render's accounting name (`Identity::email`), which a property test there round-trips for every user id. Revision 6 adds there what the Mac report sends a node: a `UserId` as agent-proto's `ReportUserId` (`report_user`), a `NodeId` as `NodeName` (`node_name`), a router band number as `ReportBandNumber` (`report_band_number`), and the alert kinds as `MacAlertKind` (`mac_alert_kind`, an exhaustive match). `ReportUserId` and `NodeName` have exactly the model's `UserId` and `NodeId` rules, which `wire_rules.rs` checks at every length and with every byte in every position of a valid id, and with property tests on arbitrary strings; `ReportBandNumber` has exactly the router's `BandNumber` rule, which `daemon-core`'s `wire.rs` checks for every `u16`.

When the Linux e2e lane exists (M3, on the research computer or hosted CI), the same check is to build `model`, `keys`, `export`, `agent-proto`, `render` and `daemon-core` for `x86_64-unknown-linux-gnu`, because that lane runs the real daemon-core. It is not implemented: `daemon-core` exists, but this Mac has only the `aarch64-apple-darwin` target, so graph-check builds the host target only.

### 6.2 Workspace policy

- Edition 2024 with `resolver = "3"`.
- `[workspace.lints]` sets `unsafe_code = "forbid"` everywhere except `macsys`, which uses `deny(unsafe_op_in_unsafe_fn)` and `// SAFETY:` comments. `macsys` cannot inherit `[workspace.lints]` (it would forbid `unsafe`), so it repeats them without `unsafe_code` and adds `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks` and `clippy::multiple_unsafe_ops_per_block`; an xtask test (`xtask/src/lint_tables.rs`) keeps the two tables equal apart from those lines and every other member on `[lints] workspace = true`. Its `unsafe` is one system call per block (`if_nametoindex`, `sysctl`, `tcgetattr`, `tcsetattr`, and reading `errno`); the routing messages are parsed by safe code. It also denies `missing_debug_implementations`, `unused_qualifications` and `unreachable_pub`, and the clippy lints `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout` and `print_stderr` (test code may unwrap, expect, panic and print: `clippy.toml`). No crate carries an `allow` or `expect` attribute.
- `clippy -D warnings`.
- `cargo deny --all-features --locked check -D warnings`: GPL-compatible licences only, and only those the graph uses (`unused-allowed-license = "deny"`); `multiple-versions = "deny"`; warn-level lints promoted to deny.
- No `*` versions. Every file carries an SPDX header. JSON goldens, which cannot hold a comment, have a REUSE `.license` sidecar; insta snapshots carry it in their description line.
- The agent links with `rust-lld` for musl *(inference; accepted in M0)*. Checked on 2026-10-22 with fieldkit: `.cargo/config.toml` sets `rust-lld` as the `x86_64-unknown-linux-musl` linker, and `cargo build -p fieldkit --release --target x86_64-unknown-linux-musl` on this Mac gave a static-pie ELF that ran on the London VPS (Debian 13). aarch64 is not checked yet.

### 6.3 Dependencies

These were the latest stable versions on 2026-10-08, except `toml` (below), locked in `Cargo.lock`. In the workspace since M1 (`[workspace.dependencies]` in the root `Cargo.toml`):
- serde 1.0.229, serde_json 1.0.151, thiserror 2.0.21
- getrandom 0.4.3, x25519-dalek 3.0.0, ed25519-dalek 3.0.0, sha2 0.11.0, base64 0.23.1
- uuid 1.27.0 with its default features only (no `v4`, no `serde`), used by `model` only: `Uuid::from_random_bytes` builds the v4 UUID with `uuid::Builder` from 16 bytes that `keys` draws through getrandom, so an entropy failure is the typed `Entropy` error. `Uuid::new_v4` is not used, because it panics when getrandom fails (uuid `src/rng.rs:57-59`). `keys` uses the uuid crate only in tests, to check version, variant and canonical text.
- SHA-256 has one helper, `Sha256Digest::of` and `SpkiSha256::of` in `model`, which `keys`, `export`, `render` and `xtask` (for the CFM importer digests) call; SHA-256 values are `Sha256Digest` everywhere on the Mac side. `render` also streams the bundle-digest encoding (§8.1) through `sha2::Sha256` directly; elsewhere `sha2` is a test-only dependency (`keys`, `export`).
- rcgen 0.14.10 with the `ring` backend (C and assembly, no C++; Mac-side only); x509-parser 0.18.1 (certificate parsing in `keys` and `export`)
- zeroize 1.9.1, ipnet 2.12.2
- toml 1.1.6 (`parse` and `serde` features only), in `xtask` only: `deny.toml` for `deny-skips`, and `contract/cfm-acceptance.toml` and `contract/cfm-manifest.toml` for `acceptance` and `release-acceptance` (§9.3). It is one release behind on purpose: when it was added on 2026-10-08, 1.1.6 was the newest release at least 14 days old, because 1.1.7 (and new toml_parser, toml_datetime and serde_spanned releases) had been published that day.
- Dev only: proptest 1.11.0, insta 1.49.0, tempfile 3.27.0, saphyr 0.1.0 (YAML round-trip checks only)

Added in revision 7 (crates.io, checked 2026-10-13; each the newest stable release at least 14 days old):
- clap 4.6.7 (2026-09-14), `mooringctl` only, `default-features = false` with `std`, `derive`, `help`, `usage` and `error-context` (no colour and no suggestions, so no terminal-detection crates); it brings clap_builder 4.6.7, clap_derive 4.6.7 (on the syn 3 already locked), clap_lex 1.1.1, anstyle 1.0.14 and heck 0.5.0. Typed subcommands; no argument carries a secret.
- socket2 0.6.5 (2026-07-13) with `features = ["all"]`, `mooringctl` only: `bind_device_by_index_v4` (IP_BOUND_IF), `connect_timeout`, read and write timeouts.
- security-framework 3.7.0 (2026-02-20), `mooringctl` only, `default-features = false` (the defaults gate newer macOS APIs and TLS options the keychain calls do not use): `passwords::{generic_password, set_generic_password_options, delete_generic_password_options}`; it brings security-framework-sys 2.17.0, core-foundation 0.10.1 and core-foundation-sys 0.8.7 (bitflags 2.13.2 and libc were locked already).
- libc 0.2.189 (2026-07-21), `macsys` only. The lock is held at 0.2.189 for every crate (`cargo update -p libc --precise 0.2.189`), because 0.2.190, which getrandom and rustix had brought in, was published on 2026-10-02.
- No HTTP or TLS crate (the M7 is plain HTTP on the LAN) and no tokio yet. No new licence: all are MIT OR Apache-2.0. `deny.toml` changes only the reason of the `syn@2.0.119` skip, which now names clap_derive among the syn 3 users.

Added with the crates that need them (later milestones):
- tokio 1.53.2 (current-thread runtime; `mooringctl` and `daemon-core` only)
- tracing

**Deliberately absent.**
- No `ssh-key` crate: its latest stable release, 0.6.7, needs sha2 0.10 and ed25519-dalek 2, which would duplicate the crypto stack. A small OpenSSH encoder is golden-tested against `/usr/bin/ssh-keygen -y -f` and `-l` instead.
- No TLS stack in our Rust code, because the reflector is plain TCP.
- No gRPC: accounting shells out to the pinned `xray api`.
- No YAML library at runtime.

---

## 7. Data model and migrations

Non-secret state lives in `~/Library/Application Support/Mooring/state.json`; lab builds use `Mooring-Lab/`. `mooring-store` (`crates/store/src/store.rs`, `ordered.rs`, `durable.rs`) is rooted at a directory the caller passes in; it never reads `HOME` and never creates the directory. Writes follow four rules:
- An exclusive lock is taken on `state.lock` (`std::fs::File::lock`, mode 0600) for the whole read-modify-write. Reads take a shared lock on the same file, so a reader never sees a state that was renamed into place before its directory was fsynced. The lock has no timeout.
- Compare-and-swap is done on the deployment's `config_generation` (a `ConfigGeneration`) or on `RuntimeIntent.revision` (a `RuntimeRevision`).
- Each write goes temp file (mode 0600) → fsync → rename → fsync of the directory (`F_FULLFSYNC` on Apple targets).
- The CLI is the only writer of `state.json`. The daemon writes only `run/` (control socket, `latch.json`, `engine-*.pid`), `status.json` and `usage/`.

`state.json` is pretty-printed JSON with a trailing newline, with the fields in the order `version`, `deployment`, `runtime`. Nodes and users are serialised as lists in id order, and viewers in key order, so a duplicate id or viewer key is a decode error (`DuplicateId`). The store writes version 2 and reads versions 1 and 2. Four golden files in `crates/store/src/tests/golden/` pin the on-disk formats:
- `state-v1.json` (an `Adopted` node) and `state-v1-every-variant.json` (the `Applied`, `Retiring`, `RetiredPendingProviderDeletion` and `Retired` stages, every version-1 user status, a `Separate` uplink, both selector variants, two Hysteria2 listeners and no SIM hard stop) pin version 1, which is never written again: both still decode with the frozen version-1 types (`crates/model/src/v1.rs`) and re-encode byte for byte.
- `state-v2.json` is the version-2 form of `state-v1.json`, and exactly what that document lifts to: the plan unrecorded, the 450e9/560e9 hard stop kept, and the revision-6 records empty (`"auto_quota": null`, `"alerting": null`, `"viewers": []`). The version-2 API can no longer build an unrecorded plan (P0-1, below), so the test lifts `state-v1.json` and checks it against the same history built through the version-2 API with the SMARTY plan, once that plan is recorded on the lifted state (`crates/store/src/tests/migration.rs`).
- `state-v2-every-variant.json` adds every version-2 variant one document can hold: the decided 1pMobile plan (`unlimited_fair_use` with a rolling 30-day window, no speed cap) on 30-day cycles from 2026-10-28 at the pilot thresholds (200e9, hard stop 240e9), the pilot cap of 5 active users, `AutoQuotaPolicy::PILOT`, alert channels on `lon1`, one viewer, an uplink baseline, users suspended for each `SuspendReason`, and users with and without a policy, alias and agreement record.
- A document holds one SIM policy, so the other plan, cycle and stop shapes (SMARTY's `unlimited` plan on a monthly rule, a per-cycle `unlimited_fair_use` line, `AcceptDeprioritisation`, a speed cap, and the capped plans with `Throttled` and `Blocked`) are pinned by the exact-encoding tests in `crates/model/src/sim.rs` (`every_policy_shape_has_a_fixed_encoding` and the rolling-line test) instead. The test fixtures (`testing::exit_site`, `mooring-fixtures`) keep SMARTY's plan at F2's first thresholds (240e9, 300e9): they check arithmetic and encodings, not the decided values, so the status fixtures in `contract/` did not change with the line.

Only the `Planned` stage is pinned by no document: the every-variant documents cannot hold it beside `Applied` and `Retiring` under the two-node cap. A serialisation change therefore needs a new version and a migration step. Revision 6 extended version 2 in place and regenerated its two goldens, because version 2 has not been committed or released (§22, "Format note"); the version-1 goldens are byte-identical.

```rust
pub enum StateFile { V1(StateV1) /* read only, lifted on load */, V2(StateV2) }
pub struct StateV2 {                            // on disk: {"version": 2, "deployment": …, "runtime": …}
    pub deployment: Deployment,
    pub runtime: RuntimeIntent,                 // Mac-only; never affects VPS digests
}
pub struct RuntimeIntent { pub exit_enabled: bool, pub revision: RuntimeRevision }
pub struct Deployment {                         // built only from DeploymentParts (try_from), which checks every
                                                // cross-entity invariant; the fields are private and read through
                                                // accessors, and an edit goes through into_parts() and try_from
    config_generation: ConfigGeneration,        // starts at 1; bumped by every change except a Bookkeeping record
    exit: ExitSite,
    policy: TrafficPolicy,
    capacity: CapacityPolicy,                   // { max_active_users: Option<NonZeroU16> }; exit init records PILOT (5; F3, D-1);
                                                // UNLIMITED (None) is what a version-1 document lifts to
    auto_quota: Option<AutoQuotaPolicy>,        // F4; exit init records Some(AutoQuotaPolicy::PILOT); None: off
    alerting: Option<AlertSettings>,            // F6; exit init records Some(AlertSettings::pilot()); None: not set up
    viewers: BTreeMap<Ed25519Pub, Viewer>,      // F5; unique by key; serialised as a list in key order
    nodes: BTreeMap<NodeId, Node>,              // at most MAX_ACTIVE_NODES = 2 active (Planned..=Retiring); retired nodes stay
    users: BTreeMap<UserId, User>,
    next_wg_index: WgIndex,                     // monotonic, never reused
}
pub struct DeploymentInit {                     // everything a fresh deployment records; exit init fills every field
    pub exit: ExitSite, pub policy: TrafficPolicy, pub capacity: CapacityPolicy,
    pub auto_quota: Option<AutoQuotaPolicy>, pub alerting: Option<AlertSettings>,
}                                               // Deployment::new(init) -> Result: PlanNotRecorded unless exit.sim.plan() is Some
pub struct AutoQuotaPolicy {                    // decision F4; AutoQuotaPolicy::PILOT = 6, 80, 2100, 80, Suspend
    pub from_active_users: NonZeroU16,          // automatic quotas apply while at least this many users share the cycle's budget: Active, or suspended for quota this cycle
    pub budget_percent: BudgetPercent,          // 1..=100: the share of the cycle's served budget those users divide
    pub sim_factor: SimFactor,                  // SIM bytes per served byte in ‰, >= 1000; SAME_AS_EXIT_ESTIMATE = 2100 (§3)
    pub warn_percent: WarnPercent,              // 1..=99
    pub action: QuotaAction,                    // Warn | Suspend
}
pub struct AlertSettings {                      // decision F6; AlertSettings::pilot() = 09:00, EuropeLondon, no channels
    pub digest_at: WallClockTime,               // "HH:MM"; PILOT_DIGEST_AT = 09:00
    pub digest_zone: WallClockZone,             // EuropeLondon ("Europe/London", tz_name())
    pub channels: BTreeSet<NodeId>,             // the nodes whose Healthchecks checks are in the Keychain and that send to the one ntfy topic; active nodes only
}
pub struct Viewer {                             // decision F5: a key pair generated on the operator's phone
    pub key: Ed25519Pub,                        // imported through Ed25519Pub::parse_ssh_authorized_key; unique among viewers
    pub label: LocalLabel,                      // Mac-only (for example "phone"); never rendered or sent
    pub added_on: CalendarDate,
}
pub struct ExitSite {
    pub egress: InterfaceSelector,              // the wired NIC facing the M7
    pub uplink: Uplink,                         // SameAsExit | Separate(InterfaceSelector)
    pub egress_check: Option<EgressCheck>,      // observed on the line (M2b), recorded once by Bookkeeping::CarrierRecorded;
                                                // None until then, and the exit serves nothing (§10.2); changed only by explicit operator action
    pub sim: SimPolicy,                         // below
    pub probe: ProbePolicy,                     // direct 30 s, in-chain 300 s, base_port 47101
    pub flow_cap: FlowCap,                      // node-wide new-flow cap into wgexit; sized from M2
    pub uplink_baseline: Option<UplinkBaseline>, // { p10_bps, p50_bps, measured_at }, 0 < p10 <= p50; from fieldkit uplink (M2)
}
pub struct SimPolicy {                          // private fields; SimPolicy::new checks the invariant below
    cycle: CycleRule,                           // Monthly { bill_day } (SMARTY's Renewal Date)
                                                // | FixedDays { days, anchor } (1pMobile's 30-day Boosts)
    plan: Option<SimPlan>,                      // None only in a policy lifted from version 1: SimPolicy::new takes a SimPlan,
                                                // so no public constructor builds an unrecorded policy (P0-1)
    warn_bytes: u64,                            // the pilot's 200e9 (PILOT_SIM_WARN_BYTES, F2)
    stop: StopPolicy,                           // HardStop { bytes } (the pilot's 240e9, PILOT_SIM_HARD_STOP_BYTES, F2)
                                                // | AcceptDeprioritisation (only with a fair-use line)
}
pub struct SimPlan {                            // the decided line (F1): SimPlan::one_p_mobile_unlimited(), terms [1PM-TC]
    pub carrier: Carrier,                       // Smarty | OnePMobile ("1pmobile")
    pub kind: PlanKind,                         // Unlimited (no line) | UnlimitedFairUse { fair_use_bytes, window }
                                                // | Capped { allowance_bytes, after: Throttled { kbps } | Blocked };
                                                // window: BillingCycle | Rolling { days } (1pMobile: 500e9 per 30 days)
    pub speed_cap_mbps: Option<NonZeroU32>,
    pub terms: EvidenceRef,                     // { url: EvidenceUrl, dated: CalendarDate }
}
pub struct EgressCheck {
    pub carrier_prefixes: NonEmpty<CarrierPrefix>, // the carrier's public pool prefixes observed on the line in M2b (RIPE inetnum evidence),
                                                   // never ASN-wide; each canonical and disjoint from SPECIAL_V4
    pub pairing: Pairing,                       // Paired | Unpaired, from the M2 pooling measurement
}
pub enum InterfaceSelector {                    // variant chosen from M2 data
    LinkAddr { lladdr: MacAddr, subnet: LanSubnet },
    GatewayLinkAddr { gw_lladdr: MacAddr, subnet: LanSubnet },
}
pub struct TrafficPolicy { pub deny_cn: bool, pub block_quic: bool, pub deny_smtp25: bool,
                           pub deny_bittorrent: bool, pub camo_forward: bool }   // all true by default
pub struct Node {
    pub id: NodeId,                             // ^[a-z][a-z0-9]{1,11}$, e.g. "lon1"
    pub role: NodeRole,                         // Primary | Standby
    pub ports: PortPlan,                        // wg 27820, reflector 27900, hy2 listeners, reserved ranges; invariant-checked
    pub wg_index: WgIndex,                      // 10.77.<k>.0/30: VPS .1, Mac .2
    pub ssh: SshPin,                            // host ed25519 key: the one-time key from `node new`, re-pinned at Bootstrap
    pub reality: RealityServer,
    pub hy2: Hy2Server,
    pub wg: WgLink,                             // vps_pub, mac_pub, keepalive (5..=60 s)
    pub lifecycle: NodeLifecycle,               // the node's address and host facts live here, from adoption on
}
pub enum NodeLifecycle {
    Planned,                                    // no payload: no address yet, and the user-data (which holds the one-time
                                                // host private key) is a 0600 file named after the NodeId, never state
    Adopted { site: NodeSite },
    Applied { site: NodeSite, applied: AppliedConfig },        // AppliedConfig { config_generation, digest }
    Retiring { site: NodeSite },
    RetiredPendingProviderDeletion { address: NodeAddress },   // the address is still denied everywhere
    Retired,
}
pub struct NodeSite { pub address: NodeAddress, pub host_facts: HostFacts }   // recorded at adoption (§13.2)
pub enum NodeAddress { Public(PublicIpv4) }    // Lab(LabAllowance) arrives with cfg(feature = "lab") in M5
pub struct HostFacts {                          // from Hello at adoption; Debian, kernel, bbr and fq are asserted, not recorded
    pub uplink_interface: LinuxIfName, pub arch: Arch /* Amd64 | Arm64 */, pub ephemeral_ports: PortRange,
}
pub struct RealityServer {
    pub public_key: X25519Pub,
    pub probe_short_id: ShortId,                // the probe identity's short id on this node
    pub target: Option<TargetSpec>,             // None until `node target set`; an Applied node requires Some
}
pub struct TargetSpec {                         // built only by target::qualify (§11.7); decoding re-checks the attestation
    host: DnsName,                              // the only REALITY serverName and the client SNI
    ipv4: PublicIpv4, key_exchange: TargetKeyExchange /* X25519 | X25519MlKem768 */, attestation: TargetAttestation,
}
pub struct Hy2Server { pub certificate: CertificatePem }   // only the certificate; the SNI and pins are derived from it
pub struct PortPlan { wg: Port, reflector: Port, hy2: NonEmpty<Hy2Listener>, reserved: Vec<PortRange>, ephemeral: PortRange }
pub struct Hy2Listener { port: Port, hop: PortRange, hop_interval: HopInterval, obfs: Hy2Obfs /* Salamander only in v1 */ }
pub struct User {
    pub id: UserId,                             // opaque, 10 base32 chars; the only id ever sent to a VPS
    pub label: LocalLabel,                      // Mac-only; never exported or sent
    pub client: ClientProfile,                  // { line: Cfm04 | Cfm05, capabilities: BTreeSet<Capability> }
    pub status: UserStatus,                     // Active | Suspended { reason, since } | RevokePending | Revoked
    pub per_node: BTreeMap<NodeId, UserNodePublic>,   // { short_id: ShortId }; while RevokePending, exactly the nodes
                                                      // that still have to commit the revocation
    pub policy: UserPolicy,                     // { expires_at: Option<UnixTime>, quota: Option<UserQuota> }; a record only
    pub alias: Option<PublicAlias>,             // xxxx-xxxx from 40 random bits (mooring-keys); no text constructor; unique
    pub agreement: Option<AgreementRecord>,     // { version: AgreementVersion, accepted_on: CalendarDate }; Mac-only;
                                                // user export requires version == AgreementVersion::CURRENT (F9, §9.2)
}
pub enum SuspendReason { Operator, QuotaExceeded { cycle_start: CalendarDate }, Expired, AbuseReview }
pub struct UserQuota { pub cycle_served_bytes: NonZeroU64, pub warn_percent: WarnPercent /* 1..=99 */, pub action: QuotaAction /* Warn | Suspend */ }
pub enum Capability { RealityMlkemOptIn /* emits support_x25519mlkem768; accepted by ClientLine::Cfm05 only */ }
pub enum Bookkeeping {                          // the only changes that keep config_generation (below)
    Applied { node: NodeId, applied: AppliedConfig },
    RevocationCommitted { user: UserId, node: NodeId },
    RetirementShutDown { node: NodeId },
    AgreementRecorded { user: UserId, record: AgreementRecord },   // M5, `user agree`
}
pub enum SecretRef {
    AlertTopic /* alert/topic: the deployment's one ntfy topic, Password material; the only reference without a node */,
    NodeRealityPrivate(NodeId), NodeWgVpsPrivate(NodeId), NodeWgMacPrivate(NodeId),
    NodeHy2Key(NodeId), NodeHy2Obfs(NodeId, ListenerIdx), NodeSshBootstrapPrivate(NodeId) /* deleted at adoption */,
    UserVlessUuid(UserId, NodeId), UserHy2Password(UserId, NodeId), UserLoopUuid(UserId, NodeId),
    ProbeVlessUuid(NodeId), ProbeHy2Password(NodeId), ProbeLoopUuid(NodeId),
    NodeDeadManCheck(NodeId) /* node/<n>/dead-man-check: Uuid */, NodeMacAliveCheck(NodeId) /* node/<n>/mac-alive-check: Uuid */,
}
```

**Where node facts live.** A node's address and host facts are unknown before adoption, so they belong to the lifecycle (`NodeSite`) rather than to `Node`. `Adopted`, `Applied` and `Retiring` carry the site; `RetiredPendingProviderDeletion` keeps only the address, which every renderer still denies; `Planned` and `Retired` carry nothing.

**Cross-entity invariants** are checked in one place, whenever a `Deployment` is built from `DeploymentParts`, including on decode (`crates/model/src/deployment.rs`):
- node and user ids, and viewer keys, are unique (`DuplicateId`, with `EntityId::Viewer` for a key);
- at most `MAX_ACTIVE_NODES` (2) nodes are active, counting `Planned` through `Retiring` (`TooManyNodes`). The bound is two because the Mac exit carries one WireGuard endpoint per node, at most two (§5.1), and the probe port span is sized for two nodes (`PROBE_PORT_SPAN`: 2 nodes × 2 protocols below the macOS ephemeral range). Rotation is ordered around it (§13.4, D-8);
- WireGuard indices are unique and below `next_wg_index`, and live node addresses are unique;
- an adopted node's port plan was checked against its host's live range (`PortPlanConflict{EphemeralRangeChanged}`);
- an `Applied` node has a target, and its applied generation is no newer than the deployment's (`GenerationAhead`);
- users hold credentials only on active nodes; a `RevokePending` user holds them on at least one node, and a `Revoked` user on none. A `Suspended` user keeps its credentials (or holds none once the nodes it held them on are retired), so its secrets stay referenced, but it is served by no node, rendered in no VPS config and refused by every export (`UserNotActive`);
- REALITY short ids are unique per node, the probe's included;
- public aliases are unique among users (`DuplicateAlias`);
- with a cap, at most `capacity.max_active_users` users are `Active` (`TooManyActiveUsers`); suspended, revoking and revoked users do not count;
- alert channels name only existing (`UnknownNode`), active nodes (`AlertChannelsOnInactiveNode`), because an inactive node's secrets are deleted with its channels. `Bookkeeping::RetirementShutDown` removes the node from `alerting.channels` together with every user's credentials on it, and drops its two Healthchecks check references through `record_with_secrets`, with the deployment's ntfy topic when the node was the last channel node. A configuration change that makes a channel node inactive (`Planned` → `Retired`) must remove the channel in the same closure, through `update_config_with_secrets`; otherwise it fails with `InvalidChange{AlertChannelsOnInactiveNode}`, as `CredentialsOnInactiveNode` does for users.

The rules up to "REALITY short ids" are version 1's, and a version-1 document is checked with exactly those (`Entities::check_version_1`), which no later version edits. The rules a later version adds (here: aliases and the cap; a lifted document has no viewers and no alert channels) are checked when the document is lifted, so a version-1 document that breaks one fails its migration (`MigrationFailed`, file untouched) instead of reading as corrupt.

**User transitions** (`User::suspend`, `resume`, `revoke`): only an `Active` user is suspended (`UserNotActive`), only a `Suspended` one resumed (`UserNotSuspended`), and an `Active` or `Suspended` user is revoked (`RevocationAlreadyStarted` otherwise), becoming `RevokePending` on the nodes holding its credentials, or `Revoked` at once when none does. The store enforces the same table on every configuration change, however the closure edits `User::status` (`UserStatus::may_change_to`): a status changes only by one of those steps, so a revocation in progress settles only through `Bookkeeping::RevocationCommitted` and never goes back, and a suspension is not re-labelled in place. A change may remove only a `Revoked` user, who holds no credentials; any other user leaves through revocation. Anything else is `UserStatusEdited{user, from, to}`, as a forged confirmation is `AppliedEdited`. `UserPolicy` (expiry and quota) is a record, not an enforcement point: exports and renders look only at the status, and moving an expired or over-quota user to `Suspended{Expired | QuotaExceeded}` is an explicit operator or daemon action. The cap (F3: 5) and the automatic quotas (F4) were decided on 2026-10-08 and are the values `exit init` records (below). A user's own `UserPolicy.quota` overrides the automatic quota, larger or smaller; `None` means the automatic quota applies when automatic quotas are on and enough users share the cycle's budget (the users active now and those suspended for quota in the current cycle, §15.3), and otherwise there is no quota. Expiry defaults are still pending, so a user's policy is `UserPolicy::NONE` unless the operator sets one. The agreement record is neither part of the policy nor a model invariant: a newly added user and a lifted version-1 user have none, and only `user export` requires it (F9, §9.2).

**SIM policy invariant** (`SimThresholds::new`, which `SimPolicy::new` uses, also on decode; revision 6):
- `0 < warn_bytes < hard stop` (`InvalidSimThresholds`).
- `AcceptDeprioritisation`, the explicit choice to run past a fair-use line, needs a recorded plan that has one, `PlanKind::UnlimitedFairUse` (`DeprioritisationNeedsFairUseLine`). An unlimited plan without a line (SMARTY's, F1), a capped plan and an unrecorded plan therefore all need a hard stop. There is no "no stop" encoding.
- A rolling fair-use line (`FairUseWindow::Rolling { days }`, 1pMobile's 500 GB per rolling 30 days) is counted across cycle boundaries, while a hard stop resets with each cycle, so one window can hold the end of one cycle and the start of the next. `SimPolicy::new` therefore bounds a hard stop by the most cycles one window can overlap, `(days - 2) / shortest + 2` for cycles of at least `shortest` days (28 for a monthly rule, the length for a fixed one): that many stops must stay below the line (`SimStopAboveRollingLine`). With 1pMobile's 30-day cycles and 30-day window that is twice the stop, so the stop must be below 250 GB. `AcceptDeprioritisation`, the explicit choice to run past the line, is not bounded so.
- With a line (a fair-use line, or a capped plan's allowance), the highest threshold (the hard stop, or the warning under `AcceptDeprioritisation`) lies below it (`SimThresholdAbovePlan`). **Without a line there is no upper bound**: SMARTY publishes no volume (§19.1), and any other number would be invented. Revision 5's `UNRECORDED_PLAN_CEILING` was EE's fair-use line, so it was removed with EE, and so was `EE_FAIR_USE_600_GIB`; tests that need a fair-use line use the same 644,245,094,400 bytes as a test-local constant (`TEST_FAIR_USE_BYTES`). What keeps the stop real is that it is mandatory and explicitly recorded: `exit init` records F2's 300e9, and changing it is an operator act (`sim set-stop`, M5). **The model knowingly admits a stop that is no stop in practice**: on a plan without a line it accepts any explicit hard stop, `u64::MAX` included, which guards the line no better than no stop would, so F2's 300 GB rests on the stop being recorded and on the guard M5 builds. That guard is an M5 acceptance item with its own test (§22 M5): `sim set-stop` refuses a stop above `PILOT_SIM_HARD_STOP_BYTES` unless the operator confirms it explicitly, so a typo such as 3e12 for 3e11 cannot pass unnoticed (§19).
- `SimThresholds::budget_bytes()` is the number of SIM bytes a cycle may use: the hard stop, or under `AcceptDeprioritisation` the fair-use line. It is derived in `new` and not serialised; the automatic quotas divide it (§15.3).

`SimThresholds` (the warning, the stop policy and the plan's line kind and bytes) is the value the console's status carries, checked on decode as the policy is.

**P0-1, by construction and by the store.** `SimPolicy::new(cycle, plan, warn_bytes, stop)` takes a `SimPlan`, so the API builds only recorded policies. A policy without a plan (`"plan": null`) exists only after lifting a version-1 document, through the crate-private `SimPolicy::unrecorded`, and in a document that holds such a lifted policy; decoding can therefore still build one. Two rules keep it from where it does not belong:
- `Deployment::new(DeploymentInit)`, which `Store::init` calls before touching any file (not even `state.lock` is created on a refusal), refuses an unrecorded plan with `PlanNotRecorded` (the store reports `InvalidChange{PlanNotRecorded}`), so an exit site decoded from JSON or cloned from a lifted state cannot start a fresh deployment.
- Every configuration change (`update_config` and `update_config_with_secrets`, both through `change_config`) that edits the exit's SIM policy must leave its plan recorded, or it is refused with `InvalidChange{PlanNotRecorded}` and nothing is written: a recorded plan cannot be un-recorded by a configuration change (a closure swapping in a decoded `"plan": null` policy, or one copied from a lifted backup), and a lifted policy cannot be retuned without recording its plan. A lifted state whose policy a change leaves as it is takes every other change.

A lifted state keeps `"plan": null` until the operator records the plan (`sim set-plan`, M5), and the M5 daemon refuses to serve until then (plan).

**Records added by revision 6 (decisions F4, F5 and F6).** Version 2 now holds them; every new key is required, and every record refuses unknown keys:
- `auto_quota: Option<AutoQuotaPolicy>` (F4, `crates/model/src/quota.rs`): `{"from_active_users":6,"budget_percent":80,"sim_factor":2100,"warn_percent":80,"action":"suspend"}` or `null`. No rule ties `from_active_users` to the cap: with the cap at 5, `TooManyActiveUsers` keeps the active users below 6, so the automatic quotas stay dormant unless users suspended for quota in the current cycle, who keep sharing its budget, bring the count to 6 (latched per cycle, decided 2026-10-09; `daemon-core` tests both, §15.3).
- `alerting: Option<AlertSettings>` (F6, `crates/model/src/alerting.rs`): `{"digest_at":"09:00","digest_zone":"europe_london","channels":["lon1"]}` or `null`. No secret is in the state: the deployment's one ntfy topic (`SecretRef::AlertTopic`, Keychain account `alert/topic`) and each channel node's two Healthchecks check UUIDs (`NodeDeadManCheck`, `NodeMacAliveCheck`) are Keychain items. `required_secrets` lists the topic exactly while `channels` is not empty, once however many nodes send to it, and each channel node's checks, so the ordered writes below put the topic before the state that adds the first channel node and delete it only after the commit that leaves none; retiring one of two channel nodes keeps it. The topic and the M7's admin password (`SecretRef::RouterAdmin`, revision 7) are the two references that belong to no node (`SecretRef::node` returns `None` for both). The ntfy server and the Healthchecks ping origin are fixed by the node's alert unit (M4), and priorities and tags are code (§15.8). The digest time is a wall-clock time in Europe/London, which the node's systemd timer reads (`OnCalendar=*-*-* 09:00:00 Europe/London`), so no Rust code converts time zones.
- `viewers: [Viewer]` (F5, `crates/model/src/viewer.rs`): each `{"key": <base64 Ed25519 key>, "label": "phone", "added_on": "2026-10-08"}`. Adding or removing a viewer is a configuration change, because every node's bundle carries the viewer keys (§8.6).
- Built in revision 7: the router admin secret `SecretRef::RouterAdmin` (Keychain account `router/admin`, `RouterAdminPassword`, `SecretEntry::RouterAdmin`, `SecretSnapshot.router_admin`), needed because M2a showed the M7's status fields require a login (§15.6). It belongs to no node and is never in `required_secrets`: `mooringctl router set-password` writes it, not a state commit (§12). Not built yet: the managed file that carries a node's alert secrets to it, which comes with the alert unit in M4 (§5.2).

**What `exit init` records (M5).** Every field of `DeploymentInit` is explicit, so nothing has a hidden default:
- the SIM policy `SimPolicy::new(FixedDays { days: 30, anchor: <the day the Boost was bought> }, SimPlan::one_p_mobile_unlimited(), PILOT_SIM_WARN_BYTES, HardStop { PILOT_SIM_HARD_STOP_BYTES })`, where 1pMobile's plan is `SimPlan { carrier: OnePMobile, kind: UnlimitedFairUse { fair_use_bytes: 500e9, window: Rolling { days: 30 } }, speed_cap_mbps: None, terms: { url: https://www.1pmobile.com/terms-and-conditions, dated: 2026-07-24 } }` (F1, 2026-10-23; SMARTY's plan, the first line, was `SimPlan { carrier: Smarty, kind: Unlimited, speed_cap_mbps: None, terms: { url: https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf, dated: 2026-08-25 } }` with a monthly rule);
- `CapacityPolicy::PILOT`, `Some(AutoQuotaPolicy::PILOT)` and `Some(AlertSettings::pilot())`, with no channel node until `alert setup` (§15.3).

Expiry defaults stay pending, and the expiry record defaults to none. A new user has no agreement record either, so `user export` refuses it until `user agree` records the current revision (F9, §9.2).

**Newtypes.** Each enforces its rule in its constructor, and deserialisation goes through the same check.
- `PublicIpv4` rejects every `SPECIAL_V4` range. CFM accepts RFC1918 and CGNAT addresses, so this is stricter.
- `ShortId`: exactly 16 lowercase hex characters, not all zero. Xray decodes `"0000000000000000"` to the same bytes as the empty short id, which any client matches.
- `X25519Pub`: 43 characters of unpadded base64url, not all zero.
- `DnsName`: lowercase ASCII LDH labels, at most 253 bytes, no trailing dot, and a top label that is not all digits.
- `PortPlan`: all ports and ranges are disjoint, including the system ports 22, 80, 443, 10085 and 10443 (`SYSTEM_PORTS`); fixed ports lie outside `ip_local_port_range`; hop and reserved ranges lie above it. A plan holds at most 2 Hysteria2 listeners and 2 reserved ranges, and records the ephemeral range it was checked against.
- `Hy2Listener`: the hop range starts at `port + 1`, because exports emit one contiguous client range (`61000:62999`). Listeners live only in `PortPlan`, so the Hysteria2 ports have a single owner, and each listener carries its own `HopInterval`.
- `HopInterval`: 5..=3600 seconds. The floor is the pinned sing-quic dialer's (`hysteria/hop.go:55-57`, "hop interval must be at least 5 seconds") and CFM 0.5's import bound (`crates/cfw-singbox-config/src/profile_validation.rs:17-18,624-660`); CFM 0.4 accepts 1..=3600. So 5..=3600 is the range every client line both imports and dials, and a plan the exports could not serve cannot be built.
- `Keepalive`: 5..=60 seconds. 5 s is the §3 floor; 60 s keeps three keepalives (the watch's rx-growth window) inside the watch's 180 s handshake limit.
- `CycleRule`: how the billing cycles fall, `Monthly { bill_day }` or `FixedDays { days, anchor }`: back-to-back cycles of `days` days, one of which starts on `anchor`. 1pMobile charges its Boosts "on a 30-day rolling basis" from the day one is bought ([1PM-TC], Definitions), so its rule is `FixedDays { 30, <that day> }`; a Boost that lapses and is bought again later starts a new run, and the operator records the new anchor. Every cycle starts at UTC midnight of its first day *(inference, as for SMARTY)*. `cycle_start` and `next_cycle_start` compute the boundaries on either side of the anchor, and `shortest_cycle_days` bounds every cycle's length for the rolling-line rule above (28 for a monthly rule).
- `PeriodDays`: 1..=366 days, a fixed cycle's length or a rolling window's (`InvalidPeriodDays`).
- `BillDay`: 1..=31, SMARTY's Renewal Date, the day of a monthly rule. SMARTY bills upfront each month: the cycle starts at SIM activation and renews on the same day each month ([SMARTY-TC] 5.20, 5.21; help 952716, 4227332). A month without that day starts its cycle on its last day (bill day 31 → 30 April and 28 or 29 February). SMARTY says that a Renewal Date on the 29th–31st falls earlier in a shorter month, but not whether it returns to that day in a longer month, so the clamp is an inference to verify at the first short-month renewal; activating the SIM on a day up to the 28th avoids it (M2a). A failed auto-renewal that is retried and taken later moves the cycle start to the day payment was taken ([SMARTY-PG] p3); the operator then records the new bill day (`sim set-bill-day`, M5). Recording it leaves every `QuotaExceeded{cycle_start}` as it was (`SuspendReason`): the record of which cycle was exceeded. Whether a suspension for quota still holds is read from when it was made (`UserStatus::Suspended.since`) against the cycle the current bill day gives: one made at or after that cycle's start holds, whichever way the edit moved the start, and one made before it has lapsed (`daemon-core`'s `quota_suspension_holds`, §15.3). SMARTY states no time of day or time zone for the renewal, so a cycle starts at UTC midnight *(inference)*. `cycle_start` and `next_cycle_start` compute the boundaries. Version 1's `CycleDay` (1..=28) maps to the same bill day.
- `BudgetPercent`: 1..=100 (`InvalidBudgetPercent`). `SimFactor`: SIM bytes per served byte in thousandths, at least 1000, because every served byte crosses the SIM at least once (`InvalidSimFactor`); `SimFactor::SAME_AS_EXIT_ESTIMATE` is §3's 2100.
- `WallClockTime`: exactly `HH:MM` with ASCII digits, 00:00..=23:59 (`InvalidWallClockTime`), stored as minutes since midnight. `WallClockZone` has one value, `EuropeLondon` (`tz_name()` is `Europe/London`).
- `CalendarDate`: exactly `YYYY-MM-DD`, a real day of the proleptic Gregorian calendar between 1970-01-01 and 9999-12-31.
- `PublicAlias`: two groups of four lowercase base32 characters joined by a hyphen (40 random bits drawn by `mooring-keys`), so it never looks like a `UserId`. It is made only from random bytes (`from_random_bytes`) or decoded from a stored alias: there is no `FromStr` or `TryFrom<String>`, so no command can take an alias typed by the operator. Any 40 bits are a valid alias, so only the random source keeps it from spelling a name.
- `LanSubnet` (the subnet in an `InterfaceSelector`): canonical, and wholly inside one private LAN class of `SPECIAL_V4` (`LAN_CLASSES`: 10/8, 100.64/10, 169.254/16, 172.16/12, 192.168/16). The Mac exit's `SPECIAL_V4` reject (§8.7) therefore always covers the M7 and home LANs.
- `LinuxIfName`: the kernel's rule (`dev_valid_name`, Linux v6.12 `net/core/dev.c`): 1..=15 bytes of printable ASCII, not `.` or `..`, without `/`, `:` or whitespace. It is exactly agent-proto's `IfName`, so a name `Hello` reports converts both ways.
- `Uuid`: canonical lowercase, non-nil, version 4, RFC 9562 variant. Every UUID is a credential, so `Uuid` has no `Serialize`, `Deserialize` or `Display`, its `Debug` is redacted, and it is zeroized on drop. A test stops compiling if it ever gains either serde trait.
- The REALITY ClientHello is export's `ClientHello { Chrome, ChromeX25519Mlkem768 }` (§9.2), not a model type.

**Missing keys are decode errors.** Every `Option` in the state (`sim.plan`, `plan.speed_cap_mbps`, `exit.egress_check`, `exit.uplink_baseline`, `capacity.max_active_users`, `deployment.auto_quota`, `deployment.alerting`, `reality.target`, `user.alias`, `user.agreement`, `policy.expires_at`, `policy.quota`; version 1's `sim.hard_stop_bytes`), and the `viewers` list, must be present: an explicit `null` means none, and a missing key fails to decode. A lost key therefore never silently drops a plan, a target or a policy.

**`Lab` variants.** Lab addresses exist only behind `cfg(feature = "lab")`, which arrives with the lab lanes (M5); M1 has no `lab` feature. There is no runtime "private address in release" error. Instead, the release verifier asserts that `cargo tree -e features -p mooringctl` contains no `lab`, and that no shipped binary contains the lab marker string.

**`ConfigGeneration` versus `RuntimeRevision`.** The two counters change for different reasons:
- Enabling or disabling the exit bumps `RuntimeRevision` only (`Store::set_exit_enabled`). Nodes never appear stale because of it.
- Every other change bumps `ConfigGeneration` (`Store::update_config`, `update_config_with_secrets`), except the `Bookkeeping` records, which the store commits with the generation unchanged (`Store::record`, `record_with_secrets`). None of them changes any rendered VPS bundle or any export that could already be made, which `crates/render/src/tests/bookkeeping.rs` checks byte for byte:
  - `Applied{node, applied}` records the generation and bundle digest a node confirmed (§11.2). While a node stays `Applied`, its applied generation is monotonic: a lower one is refused (`GenerationRegressed`), and one ahead of the deployment is refused (`GenerationAhead`). An equal one is recorded again with the digest the node confirmed: an unchanged re-apply repeats the digest, and a re-apply of the same generation after an app upgrade with new engines (§13.3) replaces it.
  - `RevocationCommitted{user, node}` drops a `RevokePending` user's credentials on a node that committed the revocation; with none left the user becomes `Revoked` (§13.5).
  - `RetirementShutDown{node}` moves a `Retiring` node to `RetiredPendingProviderDeletion` and drops every user's credentials on it (§13.4).
  - `AgreementRecorded{user, record}` records the agreement revision a user accepted (M5, below); it only lets that user's own export be made.
  - `CarrierRecorded{check}` records the line's carrier check, observed on the line, when none is recorded (M5a, 2026-10-23). The check is Mac-only: no bundle and no export carries it. A deployment can therefore be initialised, its nodes applied and its users exported before the SIM is in the M7, and the check recorded on the day it is, without a `node apply`. A recorded check is never replaced this way (`CarrierAlreadyRecorded`): replacing it would loosen the guard against a foreign egress (P0-2), so it is a configuration change.
- Only that record sets a confirmed generation. A configuration change (`update_config`, `update_config_with_secrets`) is refused with `AppliedEdited{node}` if, after the closure, any node holds an `AppliedConfig` it did not hold before, whether newly set, lowered, raised or with another digest (`crates/store/src/store.rs`, `change_config`); moving a node out of `Applied` (to retire it) is allowed, since it only withdraws a confirmation and exports then refuse the node. A closure therefore cannot forge a confirmation, even at the generation the store is about to stamp.
- Exports refuse a node whose applied generation is older than the deployment's (`NodeNotApplied{Stale}`, §9.2), so an export always matches what every node in it has confirmed. Any generation bump, including one with no VPS-visible effect, therefore needs a `node apply` of each node a user holds credentials on before that user's file can be exported again.
- Suspending, resuming and starting a revocation are configuration changes, never bookkeeping: each changes which users the nodes serve, so it bumps the generation and needs a `node apply`. A suspension keeps the user's secrets referenced, so plain `update_config` accepts it, and a resume restores the same credentials and the same export file without delivering anything new into China.
- The daemon restarts an engine only if the digest of that engine's rendered config changes. Adding a user changes the VPS bundle but not `mooring-exit`'s config, so it does not drop the exit.
- **M5 adds two records.** `AgreementRecorded{user, record}`, for `user agree` (§15.3; built 2026-10-18): an agreement record changes no bundle and no export byte (it only decides whether an export is refused, §9.2), so recording one keeps the generation and needs no `node apply`. It refuses a user who is revoking or revoked (`RevocationAlreadyStarted`), and a revision lower than the one recorded, as after a downgrade (`AgreementRegressed`), and it keeps an existing record of the same revision as it is, so the record's day stays the day of the first acceptance. A suspended user may record one. `RevokedUserRemoved{user}`, for the 13-month rule and `user forget` (§15.7): a revoked user is in no bundle and no export. The render test `crates/render/src/tests/bookkeeping.rs` then checks both like the other three. From then on a configuration change removes no user, so removal has one path.
- **Note for the daemon (M5):** a `Bookkeeping` record changes `state.json` while keeping both counters, so neither `config_generation` nor `RuntimeIntent.revision` alone detects every state change.

**`State` holds no `Secret` fields,** so no secret can be written to disk by construction: neither `Secret<T>` nor `Uuid` implements `Serialize`. Secrets are written before any state that references them. On deletion, state is updated before the secrets are removed. The store enforces this order by structure (`crates/store/src/ordered.rs`):
- `update_config` and `record` refuse any change to the set of referenced secrets (`SecretRefsChanged`).
- `update_config_with_secrets` requires the supplied secrets to be exactly the newly referenced ones (`SecretPlanMismatch`, `DuplicateSecret`) before anything is written. It writes them (a failure leaves the state unchanged: `SecretWrite`), commits the state, and then deletes the dropped secrets while still holding the lock. A failed deletion is reported as `SecretCleanup{committed, failures}`: the state is committed, and every other deletion is still attempted.
- `record_with_secrets` commits a `Bookkeeping` record and then deletes the secrets it stopped referencing, in the same way.
- No operation replaces a secret that the committed state still references: a reference held before and after a change cannot be supplied (`SecretPlanMismatch{unreferenced}`). The two planned commands that replace secrets, `user reissue` and `alert rotate-topic` (§12, §15.3), get their path in M5.

The model's `SecretEntry` (one variant per `SecretRef`) pairs each reference with the right kind of material, and both `SecretSnapshot::insert` and `SecretStore::put` take it. `mooringctl doctor` lists orphaned keychain items.

**Migrations.**
- `store::migrate` is a chain of pure functions (`V1 → V2 → …`), each golden-tested. The store reads the version first, refuses a newer one, decodes the document with its own version's schema (version 1 with the frozen types in `crates/model/src/v1.rs`, which check the version-1 invariants), then lifts it.
- `V1 → V2` invents nothing: the cycle day becomes the same bill day, the hard stop becomes `StopPolicy::HardStop` at the same byte count, the plan stays unrecorded (`plan: None`; version 1 kept no plan record), and users get `UserPolicy::NONE`, no alias and no agreement record; the deployment gets no cap (`CapacityPolicy::UNLIMITED`), no automatic quotas, no alert channels and no viewers, and the exit no uplink baseline. A version-1 SIM policy lifts by one rule (revision 6): every explicit hard stop is kept, at any value, and only a missing one is refused, `MigrationFailed{from: 1, to: 2, source: StopPolicyUnchosen}`, leaving the document untouched. With the plan unrecorded there is no line to check a stop against; revision 5 also refused a stop at or above EE's fair-use line, and that rule left with EE. Version 1's `null` was chosen before the plan's line was recorded, so it cannot stand for `AcceptDeprioritisation`, which needs a recorded plan with a fair-use line (critique C-10). The version-1 format was never released (§22, "Format note"), so no such document exists outside the goldens, and Mooring ships no repair tool for one.
- A read lifts an older document in memory only and never writes. The first write after lifting writes `state.json.bak-<from>-<to>` durably, then the migrated state.
- An unknown newer version is refused with `DowngradeRefused{found, newest}`.

**Hysteria2 certificate.** One per node, generated on the Mac by `mooring-keys` (`crates/keys/src/cert.rs`):
- ECDSA P-256, self-signed; critical `basicConstraints` `CA:FALSE`, critical `keyUsage` `digitalSignature`, EKU serverAuth, subject `CN=<sni>`.
- The single SAN `DNS:n<16 hex>.internal` is also the client SNI.
- `notBefore` = now − 1 day; `notAfter` = now + 3650 days.
- The SubjectPublicKeyInfo is the canonical P-256 encoding that sing-box hashes (`x509.MarshalPKIXPublicKey`, sing-box `common/tls/std_client.go:278-295`).
- It is never re-issued; rotation means a new node.
- Only the certificate is stored (`Hy2Server`). The SNI and both pins (`CertPins`, a derived value with no serde) are computed from it each time by `mooring-export` (`certificate_pins`, `check_certificate`), so a certificate and its pins cannot disagree.

**`SPECIAL_V4`** is one constant in `mooring-model`, used by both renderers, by `PublicIpv4` and by the tests:

`0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4`

IPv6 is refused entirely in v1.

---

## 8. Rendering

### 8.1 Principles

**Pure functions.** Rendering is four pure functions (`crates/render/src/`):
- `render::vps::bundle(&Deployment, &NodeId, &SecretSnapshot, &EngineCatalog) -> VpsBundle { node, config_generation, files, host_profile: HostProfileVersion, engines: EngineSet, site: NodeSite, digest }`. The node must be `Adopted` or `Applied` with a target. `files` holds all six `ManagedFile`s (`xray.json`, `hy2.json`, `wgexit.conf`, `nftables.conf`, `watch.json` and, since revision 6, `viewer_authorized_keys`), none optional, each a `RenderedFile`: exact-capacity zeroizing bytes plus their SHA-256, which is that engine's config digest. `EngineCatalog` holds the amd64 and arm64 artifacts, and the node's recorded architecture picks one. `VpsBundle::header(&hello)` builds the `Apply` header from the recorded site plus the unrecorded facts of the `Hello` just before it (§11.2).
- `render::vps::cloud_init(&Deployment, &NodeId, &CloudInitKeys) -> UserData` (§8.9).
- `render::mac::exit(&Deployment, &ResolvedInterfaces, &SecretSnapshot) -> ExitConfig`
- `render::mac::prober(&Deployment, &ResolvedInterfaces, &SecretSnapshot) -> ProberConfig`

**The bundle digest** is the SHA-256 of a documented, length-prefixed encoding (`docs/engines.md`, "Digests") of the host-profile version, the architecture, the uplink interface, VPS4, the ephemeral range, the four engine digests and the six files in `ManagedFile::ALL` order. It includes the engines and the host-profile version, so an `Apply` after an engine or host-profile upgrade is never answered `Unchanged`. It excludes the generation, so a generation bump with no VPS-visible change is `Unchanged`.

**Mac renders are tied to the exit site.** `ResolvedInterfaces` can only be built by `ExitSite::resolve`, which checks the egress and a separate uplink against their selectors (`InterfaceNotSelected`), the uplink mode against the configured one (`UplinkModeMismatch`) and that a separate uplink is another interface (`UplinkEqualsEgress`). Both Mac renders first call `ExitSite::require_resolved` (`InterfacesForOtherSite`), so a `SameAsExit` site can never bind the tunnel to a home uplink. The Mac configs cover `Applied` nodes only (`NoAppliedNodes` when there is none): a `Retiring` node loses its endpoint and probes, but its address stays denied.

**Closed, round-trippable config types.** Every JSON config struct is closed and also derives `Deserialize` with `deny_unknown_fields`, so the goldens round-trip; fixed engine strings are one-value types. The prober config is the exception: it embeds export's `SingBoxOutbound`, which is `Serialize`-only (credentials are never parsed back from text), so its round-trip test compares each outbound with export's own serialisation. The text formats are not serde types: `wgexit.conf` reads back through a strict layout parser, and `nftables.conf`, which has no parser, is covered by goldens and by structural tests that read the rendered rules back. Goldens (`contract/golden/<fixture>/`, from `mooring-fixtures`) cover 1, 3 and 20 users across 1 and 2 nodes, plus the cloud-init user-data. Each golden test is list-driven and also asserts that its directory holds exactly the rendered files, so a stale golden fails.

**Xray keys are checked semantically.** Xray silently ignores unknown keys (v26.9.30 `infra/conf/serial/loader.go:47-55`), so a key table is not enough. L2 runs `xray convert pb -debug -type` on every golden and asserts the semantic protobuf fields:
- the exit sockopt `interface=wgexit`, the TCP user timeout and `domainStrategy`;
- routing rule order and targets;
- DNS servers and `unexpectedIPs`;
- the policy stats flags;
- the log settings;
- the REALITY server fields.

The key table in `docs/engines.md` is documentation only. It maps every rendered key to its line in the pinned trees, as re-read in M1.

**Invalid configurations cannot be expressed.**
- `enum XrayOutbound { Deny, Exit(ExitBinding), CamoRedirect(CamoTarget) }`:
  - `ExitBinding` can only be built with `interface = "wgexit"`, `tcpUserTimeout` 30000 and `domainStrategy` `ForceIPv4`;
  - `CamoTarget` holds the target's `PublicIpv4` and a port in {80, 443}, so a camouflage outbound can only ever reach the target;
  - `deny` is serialised first, which makes it the default, and reading back refuses any reordering of the outbounds or inbounds.
- On the Mac side, every outbound and endpoint type has a mandatory `BindInterface`.
- The log-level types have no Info or Debug variant: Xray's has only `none`, sing-box's only `fatal`.
- The VPS-side names (`wgexit`, the nft table, set and counters, the engine Unix users, routing table 77 and rule priority 10000) come from one definition in `crates/agent-proto/src/vps.rs`, which the renderer writes and the agent acts on.

**Credentials are distinct per node** (`crates/render/src/vps/served.rs`). Before a bundle is rendered, every identity holding credentials on the node is compared with every other: each user with credentials there, whether active, suspended or pending revocation, and the probe. Two that share a VLESS UUID, a loopback UUID or a Hysteria2 password are refused with `DuplicateCredential{node, kind, first, second}`, which names both holders (opaque user ids or the probe, in the order they are checked) so the operator can find them without reading the Keychain. The comparison follows the engines:
- Xray keys a VLESS client by its UUID with bytes 6 and 7 cleared (`ProcessUUID`, v26.9.30 `proxy/vless/validator.go:21-25`) and keeps the last client with a given key (`:35-43`), so UUIDs equal outside those bytes are refused, and `xray run -test` would never notice the overwrite;
- sing-quic keeps the last Hysteria2 user with a given password (`hysteria2/service.go:151-157` at the pinned v0.7.1-0.20260924092235), so passwords are compared whole;
- the two UUID kinds belong to different inbounds, each with its own client table, so they are compared within their kind.

A suspended or revoking user is included because its client still holds the credential: were it equal to a served identity's, it would keep working as that identity. Its secrets are therefore required to render, as `required_secrets` already lists them. Exports read only one user's credentials and are covered through the generation rule: every node in a file has confirmed the current generation, whose bundle passed this check.

### 8.2 `xray.json` (v26.9.30 syntax; every key re-verified against the pinned source in M1)

Placeholders: `<uid>` is a user's opaque id (§7) and `<reflector>` a node's reflector port from its `PortPlan` (27900 by default). The node-address allow rule is grouped by reflector port. With `camo_forward = false` the `camo-*` inbounds, outbounds and rules are absent; every other switch of `TrafficPolicy` likewise removes its deny rule.

```json
{"log": {"access": "none", "loglevel": "none", "dnsLog": false, "maskAddress": "full"},
 "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]},
 "stats": {},
 "policy": {"levels": {
   "0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5,
         "statsUserUplink": true, "statsUserDownlink": true},
   "1": {"handshake": 2, "connIdle": 30, "uplinkOnly": 1, "downlinkOnly": 1}}},
 "dns": {"tag": "dns-exit", "queryStrategy": "UseIPv4", "enableParallelQuery": true,
         "serveStale": true, "serveExpiredTTL": 600,
         "servers": [{"address": "https://1.1.1.1/dns-query", "unexpectedIPs": ["<SPECIAL_V4…>"]},
                     {"address": "https://1.0.0.1/dns-query", "unexpectedIPs": ["<SPECIAL_V4…>"]}]},
 "inbounds": [
  {"tag": "reality-in", "listen": "<VPS4>", "port": 443, "protocol": "vless",
   "settings": {"decryption": "none", "clients": [
     {"id": "<uid@lon1 uuid>", "flow": "xtls-rprx-vision", "level": 0, "email": "<uid>@reality"},
     {"id": "<probe@lon1 uuid>", "flow": "xtls-rprx-vision", "level": 0, "email": "probe@reality"}]},
   "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
     "show": false, "target": "<target IPv4>:443", "xver": 0, "serverNames": ["<exact SAN>"],
     "privateKey": "<43 b64url>", "minClientVer": "1.8.1", "maxTimeDiff": 60000,
     "shortIds": ["<uid 16hex>", "<probe 16hex>"]}},
   "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}},
  {"tag": "hy2-loop-in", "listen": "127.0.0.1", "port": 10443, "protocol": "vless",
   "settings": {"decryption": "none", "clients": [
     {"id": "<uid loop>", "flow": "", "level": 0, "email": "<uid>@hy2"},
     {"id": "<probe loop>", "flow": "", "level": 0, "email": "probe@hy2"}]},
   "streamSettings": {"network": "raw", "security": "none"},
   "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}},
  {"tag": "camo-80", "listen": "<VPS4>", "port": 80, "protocol": "tunnel",
   "settings": {"address": "<target IPv4>", "port": 80, "network": "tcp", "userLevel": 1}},
  {"tag": "camo-u443", "listen": "<VPS4>", "port": 443, "protocol": "tunnel",
   "settings": {"address": "<target IPv4>", "port": 443, "network": "udp", "userLevel": 1}}],
 "outbounds": [
  {"tag": "deny", "protocol": "blackhole"},
  {"tag": "exit", "protocol": "freedom",
   "streamSettings": {"sockopt": {"interface": "wgexit", "tcpUserTimeout": 30000, "domainStrategy": "ForceIPv4"}}},
  {"tag": "camo-80-out", "protocol": "freedom", "settings": {"redirect": "<target IPv4>:80", "userLevel": 1}},
  {"tag": "camo-u443-out", "protocol": "freedom", "settings": {"redirect": "<target IPv4>:443", "userLevel": 1}}],
 "routing": {"domainStrategy": "AsIs", "rules": [
  {"inboundTag": ["camo-80"], "outboundTag": "camo-80-out"},
  {"inboundTag": ["camo-u443"], "outboundTag": "camo-u443-out"},
  {"inboundTag": ["dns-exit"], "outboundTag": "exit"},
  {"user": ["probe@reality", "probe@hy2"], "ip": ["<every node IPv4>"], "network": "tcp", "port": "<reflector>", "outboundTag": "exit"},
  {"ip": ["<every node IPv4>"], "outboundTag": "deny"},
  {"ip": ["<SPECIAL_V4…>", "::/0"], "outboundTag": "deny"},
  {"ip": ["geoip:cn"], "outboundTag": "deny"},
  {"domain": ["geosite:cn"], "outboundTag": "deny"},
  {"network": "udp", "port": "443", "outboundTag": "deny"},
  {"network": "tcp", "port": "25", "outboundTag": "deny"},
  {"protocol": ["bittorrent"], "outboundTag": "deny"},
  {"inboundTag": ["reality-in", "hy2-loop-in"], "outboundTag": "exit"}]}}
```

**Where the keys come from in the pinned source** (Xray v26.9.30 `b26a91de`; `docs/engines.md` covers every key):
- `loglevel: "none"`: `infra/conf/log.go:57-59` sets both the error and the access log to `LogType_None`.
- `redirect` and `userLevel` on freedom: `infra/conf/freedom.go:19-30,160-177`.
- `sockopt.domainStrategy`: `infra/conf/transport_sockopt.go:50,96-121`.
- `interface` → `syscall.BindToDevice`: `transport/internet/sockopt_linux.go:23-27`.
- DNS keys: `infra/conf/dns.go:19-35,160-173`.
- `statsUser*`: `infra/conf/policy.go:12-14`.
- `api.listen`: `infra/conf/api.go:18`.
- `tunnel` is an alias of `dokodemo-door`, and `userLevel` is a dokodemo setting: `infra/conf/xray.go:25`, `infra/conf/dokodemo.go:10-20`. Its `address`, `port` and `network` keys are aliases of `rewriteAddress`, `rewritePort` and `allowedNetwork` (`dokodemo.go:23-31`).
- REALITY settings: `infra/conf/transport_security.go:27-153`.
- Routing `user`: Xray routing docs, RuleObject.
- `maskAddress`: in stable releases since v24.9.30.

**Why each choice.**
- **`loglevel: "none"` at run time.** At `warning`, Xray would still log each failed DoH lookup at ERROR with the queried domain (`app/dns/nameserver_doh.go:155,199,207,215`) and each failed resolution (`transport/internet/dialer.go:258`). `maskAddress` masks IP addresses only, and while the gate is closed DoH fails for every uncached domain. Start-up failures still reach stdout (`main/run.go:84,95`), and the agent validates a copy forced to `warning` (§11.2 step 3), so configuration warnings still fail validation.
- **No `disableFallback`.** With no domain-scoped servers, `disableFallback` leaves only the first server ever used: 1.0.0.1 is never queried, and every lookup logs a WARNING containing the domain (Xray `app/dns/dns.go:321-344`). Without it, both addresses of the one operator are queried in parallel, and no WARNING is logged.
- **`statsUserOnline` removed.** It makes Xray keep per-user client IP lists, readable through the unauthenticated StatsService (`GetStatsOnlineIpList`). Accounting does not need it.
- **Target and camouflage destinations are IPv4 literals,** resolved and verified by `TargetCheck` (§11.7). Xray therefore never uses the system resolver on `eth0`, and the owner guard (§8.5) can list the exact target address. If the target's DNS changes, the change is detected as `TargetDegraded` and handled by re-running `TargetCheck` and re-applying.
- **Node IPs.** Only the probe identities may reach node IPs, and only the reflector port. This blocks a user from chaining a node through itself (a sing-box `detour`, or Clash `dialer-proxy`, which CFM maps to a detour), which would multiply SIM usage. It also blocks users from reaching VPS4:22 from the carrier IP. In lab builds the node IP is private, and rule 4 still admits the probe because it precedes the SPECIAL_V4 deny.
- **`domainStrategy: AsIs`.** The final inbound rule matches every user flow, so `IPIfNonMatch` would never trigger. IP rules therefore apply to IP-literal destinations. Domain destinations are protected by the DoH `unexpectedIPs` filter and, authoritatively, by the Mac's check on final IPs.
- **`ForceIPv4`, as `streamSettings.sockopt.domainStrategy`.** It errors on DNS failure; `UseIPv4` would fall back to the system resolver (`transport/internet/dialer.go:251-262`; freedom takes its strategy from the sockopt, `proxy/freedom/freedom.go:55-58,293-302`). The freedom `settings.targetStrategy` form logs a WARNING at load in v26.9.30 ("The `freedom.domainStrategy` setting is deprecated…", `infra/conf/xray.go:362-368`), because it fills the same deprecated field (`infra/conf/freedom.go:62-66`), and an outbound-level `targetStrategy` warns too (`:363-364`). Either would break the zero-WARN validation gate, so `exit` has no `settings`.
- **DoH.** It keeps the mobile leg from tampering with DNS.
- **Camouflage** uses `userLevel 1`, with short idle and one-way timeouts, plus the per-source nft limits. Both the tunnel inbounds and the freedom outbounds carry it: freedom applies its own level's policy (`proxy/freedom/freedom.go:210-211`), so without it the outbound side would keep level 0's 300 s idle timeout.
- **Identities** are `<uid>@reality` and `<uid>@hy2`, built with agent-proto's `StatsEmail`, so accounting parses exactly what was rendered; the probe is `probe@reality` and `probe@hy2`.
- **Sniffing** with `routeOnly: true` feeds routing decisions only, and never rewrites the destination.

### 8.3 `hy2.json` (sing-box 1.14.2; unknown keys are rejected upstream)

```json
{"log": {"level": "fatal"},
 "inbounds": [{"type": "hysteria2", "tag": "hy2-in", "listen": "<VPS4>", "listen_port": 61000,
   "obfs": {"type": "salamander", "password": "<listener-0 obfs, 32 random bytes b64url>"},
   "users": [{"name": "<uid>", "password": "<uid@lon1>"}, {"name": "probe", "password": "<probe@lon1>"}],
   "ignore_client_bandwidth": true,
   "tls": {"enabled": true, "alpn": ["h3"],
           "certificate": ["-----BEGIN CERTIFICATE-----", "…", "-----END CERTIFICATE-----"],
           "key": ["-----BEGIN PRIVATE KEY-----", "…", "-----END PRIVATE KEY-----"]}}],
 "outbounds": [
   {"type": "vless", "tag": "x-<uid>", "server": "127.0.0.1", "server_port": 10443, "uuid": "<uid loop>", "packet_encoding": "xudp"},
   {"type": "vless", "tag": "x-probe", "server": "127.0.0.1", "server_port": 10443, "uuid": "<probe loop>", "packet_encoding": "xudp"}],
 "route": {"rules": [
   {"inbound": ["hy2-in"], "auth_user": ["<uid>"], "action": "route", "outbound": "x-<uid>"},
   {"inbound": ["hy2-in"], "auth_user": ["probe"], "action": "route", "outbound": "x-probe"},
   {"inbound": ["hy2-in"], "action": "reject"}]}}
```

- **One inbound per listener.** Each `PortPlan` listener gets its own inbound (`hy2-in`, then `hy2-in-<n>`) on its own port, with its own salamander password (`SecretRef::NodeHy2Obfs(node, listener)`); every rule lists all the inbound tags. User names are opaque user ids (or `probe`), and the loopback outbounds are `x-<uid>` and `x-probe`.
- **The certificate and key are inline PEM** (`option/tls.go:22,28`). `sing-box check` loads TLS material while constructing the server (`common/tls/std_server.go:405-420`). A `certificate_path` under `current/` would therefore validate the *previous* generation's files, or fail on the first Apply. Inline PEM keeps each generation self-contained and also avoids the file watcher. The file is already secret-bearing, mode 0640 `root:mooring-hy2`.
- **The final rule has a condition.** A condition-less rule fails with "missing conditions" (`route/rule/rule_default.go:18-19`).
- **`up_mbps`/`down_mbps` are unset,** so the server replies "auto" and BBR is forced.
- **`masquerade` is omitted;** only salamander-keyed clients can reach the resulting 404.
- **`bbr_profile`** stays at its default unless the M3 A/B test justifies a change.

### 8.4 `wgexit.conf` (applied by `wg-quick`)

```
[Interface]
Address = 10.77.<k>.1/30
ListenPort = 27820
PrivateKey = <vps>
MTU = 1280
Table = off
PostUp = sysctl -qw net.ipv4.conf.%i.accept_local=1
PostUp = ip -4 rule list | grep '^10000:[[:space:]]*from all oif %i lookup 77$' >/dev/null || ip -4 rule add pref 10000 oif %i lookup 77
PostUp = ip -4 route replace default dev %i table 77
PreDown = ! ip -4 rule list | grep '^10000:[[:space:]]*from all oif %i lookup 77$' >/dev/null || ip -4 rule del pref 10000 oif %i lookup 77
PreDown = ip -4 route flush table 77

[Peer]
PublicKey = <mac>
AllowedIPs = 0.0.0.0/0          # replies arrive from arbitrary sources; no Endpoint (learned by roaming)
```

`ListenPort` is the node's `PortPlan` WireGuard port. The interface name, table 77 and rule priority 10000 come from agent-proto's `WG_INTERFACE`, `EXIT_ROUTE_TABLE` and `EXIT_RULE_PRIORITY`. The comment on `AllowedIPs` is not rendered.

**The rule hooks are idempotent.** wg-quick runs no `PreDown` for an `up` that fails after a hook (its exit trap only deletes the interface), and a rule that names an interface outlives it in the kernel (detached, and attached again when an interface of that name appears), so a plain `ip -4 rule add` would be refused (`File exists`) by every `up` after such a failure, and a plain `ip -4 rule del` would abort every `down` once the rule was gone, leaving the interface up. The rule is therefore added only when `ip -4 rule list` does not show it and deleted only when it does; `grep` reads its input to the end instead of quitting at the match, so `ip` never gets `SIGPIPE` under wg-quick's `pipefail`. The route hooks (`replace`, `flush`) are idempotent as they are. *Found 2026-10-25:* lon1's fourth apply of its first generation was rolled back with the left-over interface deleted by `ip link delete` (§11.2 step 8's first remedy), which left the rule; the fifth apply's `wg-quick up` was refused at the rule's `PostUp` and reached the Mac only as systemd's "control process exited with error code".

**Why `accept_local=1` is required.** The in-chain probe dials the VPS's own public IP (VPS4:27900) through `exit`.
- The SYN leaves on `wgexit`: the device-bound lookup skips the local-table route on `eth0`, because `fib_trie.c:1438` requires the nexthop's oif to match the bound device. Rule 10000 then selects table 77.
- The Mac's gVisor stack answers with source VPS4. On arrival over `wgexit`, `fib_validate_source` runs with `rp_filter=2` and a custom rule present (`fib_frontend.c:430-438`). The reverse lookup of a local source yields `RTN_LOCAL`, which is rejected as a martian unless `accept_local` is set (`fib_frontend.c:380-382`).
- With `accept_local=1` the packet passes. The loose second lookup (`:399-404`) resolves through table 77.

Threat-model effect: only the authenticated WireGuard peer, the Mac, can deliver packets with a VPS-local source, and the input chain still drops anything that is not an established reply arriving on `wgexit`. L4 T-reflector is the gating regression for this, with a mutation that removes the sysctl.

**Why an explicit `oif` route.**
- Normal traffic uses a real route, not the kernel's "assume on-link" branch.
- WireGuard's own encrypted packets are unbound, so they use the main table: no loop.
- `wgexit` missing: Xray swallows socket-option errors (§8.5), so ENODEV does not fail fast in Xray. The owner guard is what makes this case safe.

### 8.5 `nftables.conf`

The VPS is dedicated, so the product owns the whole ruleset, and every reload is atomic. The file is checked with `nft -c -f` before loading. Public services match on `ip daddr $VPS4`, not on an interface name, so a renamed NIC cannot silently drop SSH. The rendered syntax is validated by `nft -c` in L2, and its behaviour by L4 *(inference until then for the named-counter declarations, the `ct count` and dynamic-set forms, and `counter name` references)*.

*Found 2026-10-25:* the first `nft -c` of a rendered file, by lon1's agent at its first apply, refused `ct count over $FLOW_CAP` ("syntax error, unexpected '$', expecting number"), and nothing was switched. nft takes a `define`d variable only where its grammar has an expression; the counts and rates of `ct count`, `limit` and a set's size are number tokens. The flow cap is therefore written as the number, and a render test keeps every variable to an address after `ip daddr` or `ip saddr`.

The rendered file puts one statement per line; it is shown compactly here. Every port comes from the node's `PortPlan` (defaults shown), and the table, set, counter and user names from `crates/agent-proto/src/vps.rs`.

```
flush ruleset
define VPS4 = <vps4>
table inet mooring {
  counter xray_guard { packets 0 bytes 0 }                              # named counters are declared before use
  counter hy2_guard  { packets 0 bytes 0 }
  counter flow_cap   { packets 0 bytes 0 }
  counter probe_flows { packets 0 bytes 0 }                             # M4d: the accounting canary's evidence (§11.5)
  set exit_closed  { type ifname; elements = { "wgexit" } }            # closed at load; only mooring-watch removes it
  set camo_targets { type ipv4_addr; elements = { <target IPv4> } }
  set camo_tcp_src { type ipv4_addr; size 65536; flags dynamic; }       # ct count elements, TCP/80
  set camo_udp_src { type ipv4_addr; size 65536; flags dynamic,timeout; timeout 2m; }   # limit elements, UDP/443
  set refl_src     { type ipv4_addr; size 4096; flags dynamic,timeout; timeout 1m; }

  chain input { type filter hook input priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept
    iifname "lo" accept
    iifname "wgexit" drop                                               # nothing initiates into the VPS through the tunnel
    meta l4proto { icmp, ipv6-icmp } accept
    ip daddr $VPS4 tcp dport { 22, 443 } accept
    ip daddr $VPS4 tcp dport 80 ct state new add @camo_tcp_src { ip saddr ct count over 64 } reject with tcp reset
    ip daddr $VPS4 tcp dport 80 accept
    ip daddr $VPS4 udp dport 443 ct state new add @camo_udp_src { ip saddr limit rate over 50/second burst 200 packets } drop
    ip daddr $VPS4 udp dport 443 accept
    ip daddr $VPS4 udp dport { 27820, 61000 } accept                    # the WireGuard port and every hy2 listener port
    ip daddr $VPS4 tcp dport 27900 ct state new add @refl_src { ip saddr limit rate over 5/second burst 10 packets } drop
    ip daddr $VPS4 tcp dport 27900 accept }

  chain forward { type filter hook forward priority filter; policy drop; }

  chain output { type filter hook output priority filter; policy accept;
    oifname @exit_closed meta l4proto tcp reject with tcp reset          # gate
    oifname @exit_closed reject with icmpx host-unreachable
    meta skuid "mooring-xray" ct direction original oifname "wgexit" ip daddr != 10.77.0.0/16 jump exit_flow
    meta skuid "mooring-xray" ct direction original ip daddr @camo_targets tcp dport { 80, 443 } accept
    meta skuid "mooring-xray" ct direction original ip daddr @camo_targets udp dport 443 accept
    meta skuid "mooring-xray" ct direction original counter name xray_guard reject
    meta skuid "mooring-hy2"  ct direction original ip daddr 127.0.0.1 tcp dport 10443 accept
    meta skuid "mooring-hy2"  ct direction original counter name hy2_guard reject }

  chain exit_flow {
    ip daddr $VPS4 tcp dport 27900 ct state new counter name probe_flows   # no verdict: only the probe may route to a node address
    ct state new ct count over <flow cap> counter name flow_cap reject      # the number: ct count takes no variable
    accept }

  chain prerouting_nat { type nat hook prerouting priority dstnat; policy accept;
    ip daddr $VPS4 udp dport 61001-62999 redirect to :61000 }           # one redirect per listener: its hop range to its port
}
```

**Two changes from revision 3**, both *(inference until L2 `nft -c` and L4)*:
- The named counters `xray_guard`, `hy2_guard` and `flow_cap` are declared as objects; revision 3 referenced them without declaring them.
- The per-source set is split into `camo_tcp_src` (`flags dynamic`, no timeout; `ct count` elements are collected when their count drops to zero) and `camo_udp_src` (`flags dynamic,timeout`, `timeout 2m`). A set element keeps the stateful expression it was created with, so one set shared by a `ct count` (TCP/80) and a `limit` (UDP/443) would judge a source by whichever service it hit first.

**`camo_forward = false`** removes `camo_tcp_src`, `camo_udp_src` and the TCP/80 and UDP/443 accepts, and the owner guard then admits only TCP/443 to the target (REALITY's own dial).

**Owner guard (kernel-enforced steering).** Xray logs socket-option failures at Info and dials anyway: v26.9.30 `transport/internet/system_dialer.go:79-80` for UDP and `:136-137` for TCP. A missing `wgexit` would therefore send user traffic out of `eth0` from the VPS IP. The guard rejects every connection `mooring-xray` originates unless it either leaves on `wgexit` to a non-tunnel address, or goes to the REALITY target and camouflage target ports.

What the guard also does:
- It closes the path to VPS-local services through `exit`. Traffic to 10.77.k.1 is delivered via `lo`, and is rejected.
- It confines `mooring-hy2` to the loopback handoff.

**Residual risk.** If `wgexit` vanished while Xray kept running, a user flow to *exactly* the target IP on 80 or 443 would pass the guard via `eth0`. This is narrowed by `BindsTo=wg-quick@wgexit.service`, and measured by the T-no-leak variants.

**Gate.**
- Closing it rejects new and existing exit flows (the latter as soon as they send).
- WireGuard's encrypted packets are unbound and leave via `eth0`, so closing the gate never stops tunnel liveness, which is what reopens it.
- An nft reject is used instead of a route `unreachable`, because device-bound sockets take the on-link branch past unreachable routes *(inference from `route.c`; L4 tests both)*.

**Flow cap.** The flow cap (`exit init --flow-cap`, written into the rule as the number) is sized from the CGNAT port-ceiling estimate made in M2, minus headroom. Its purpose is to keep exit flows from exhausting the carrier's port allocation, which would also break the tunnel's own mappings and the probes. Hits are counted and surface as `ExitFlowCapHit`.

### 8.6 Host profile (versioned, owned by the agent)

`HostProfile{version}` holds the host constants. They are compiled into the agent and converged idempotently in every transaction (§11.2). `Hello` reports `host_profile_version`, and `node apply` refuses a node whose version is older than the bundle requires until the converging transaction commits.

`HostProfile::CURRENT` (version 2 since revision 6; version 1 was never installed on a node) is data plus the exact file text, defined once in `crates/agent-proto/src/profile.rs` for the agent and the renderer. Version 2 adds the remote viewer's account, `mooring-view` (home `/nonexistent`, shell `/bin/sh`), which the agent converges, and its sshd `Match` block (below). The shell must be a real one, because sshd runs the forced command through the login shell and `nologin` would refuse it. The other five host files keep their text; only the version number in their header changes. Its files are `/etc/sysctl.d/60-mooring.conf`, `/etc/modules-load.d/mooring.conf`, `/etc/ssh/sshd_config.d/10-mooring.conf`, `/etc/systemd/journald.conf.d/60-mooring.conf`, `/etc/tmpfiles.d/mooring.conf` and `/etc/apt/apt.conf.d/52mooring-unattended-upgrades`. Chrony is not part of the profile data; the systemd units are, since M4e (below and §5.2). The unattended-upgrades text and the effective `sshd -T` spellings that `Hello` compares are *(inference until L2/L5)*.

**`/etc/sysctl.d/60-mooring.conf`:**
- `net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`
- `net.ipv4.tcp_slow_start_after_idle=0`, `net.ipv4.tcp_notsent_lowat=131072`
- `net.core.rmem_max=7500000`, `net.core.wmem_max=7500000`
- `net.ipv4.conf.all.rp_filter=2`, `net.ipv4.conf.default.rp_filter=2`. Loose mode, because replies arrive on `wgexit` from arbitrary sources.
- `net.ipv4.ip_forward=0`

**Other files:**
- `modules-load.d`: `tcp_bbr`.
- **sshd** `/etc/ssh/sshd_config.d/10-mooring.conf` (it must sort before `50-cloud-init.conf`):
  - `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin forced-commands-only`, `AuthenticationMethods publickey`
  - `AllowTcpForwarding no`, `AllowAgentForwarding no`, `AllowStreamLocalForwarding no`, `PermitTunnel no`, `X11Forwarding no`
  - `MaxAuthTries 3`, `AllowUsers root mooring-view`
  - then, since host profile 2, a `Match` block for the viewer account. The exact file:
    ```
    # Managed by Mooring host profile 2. Local changes are overwritten.
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitRootLogin forced-commands-only
    AuthenticationMethods publickey
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    X11Forwarding no
    MaxAuthTries 3
    AllowUsers root mooring-view
    Match User mooring-view
    	AuthorizedKeysFile /etc/mooring/current/viewer_authorized_keys
    	ForceCommand /usr/local/lib/mooring/agent/current serve-ssh --role viewer
    ```
  - The keys file is root-owned and inside the transactional generation directory, so the viewer account cannot edit its own keys, and a rollback restores the matching viewer set. `ForceCommand` holds even for a key line without `command=`.
  - **The `Match` block ends at the end of the included file.** OpenSSH saves the match state before an `Include` and restores it after each included file (`servconf.c`, `V_10_0_P1`, the version Debian 13 ships). On 2026-10-09 `sshd -T -C user=…` with this Mac's OpenSSH 10.3p1, on the drop-in above followed by Debian-like main-file lines and a later `50-cloud-init.conf` with `PasswordAuthentication yes`, showed: for `mooring-view`, the viewer keys file and the forced command; for `root` and any other account, the default `AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2` and no `ForceCommand`; and the main file's later lines and the later drop-in applying to every account, with `PasswordAuthentication no` kept (first match wins). So a viewer key is never read for `root`, and no redesign without `Match` is needed. L2/L5 repeat this on Debian's build with `sshd -T -C user=mooring-view,…` and `-C user=root,…`.
  - **sshd reads the keys file as `mooring-view`, not as root.** OpenSSH drops to the logging-in user before opening `AuthorizedKeysFile` (`auth2-pubkey.c`, `user_key_allowed2`), and with StrictModes checks that the file and every directory above it, the `current` link resolved (`/etc/mooring/gen-<N>`, `/etc/mooring`, `/etc`, `/`), are owned by root or the user and writable by neither group nor others. So the file must also be readable, and the directories searchable, by `mooring-view`: M4 installs `viewer_authorized_keys` 0644 `root:root` and creates `/etc/mooring` and each `gen-<N>` 0755 `root:root`; the secret-bearing files beside it keep their own 0600 or 0640 modes (§8.2, §12), so the directory modes expose no secret. A keys file staged 0600 or 0640 like its neighbours, or a 0750 generation directory, would refuse every viewer login, which `sshd -t` and `sshd -T` cannot see, so L5 checks it with a real login as `mooring-view`.
  - `Hello`'s `sshd_mismatches` compares the profile with `sshd -T` through `sshd_effective_lines`, which yields one `allowusers <user>` line per user (`allowusers root`, `allowusers mooring-view`) and one line for every other directive (OpenSSH dumps a list one element per line; seen with 10.3p1's `sshd -T`, L2/L5 on Debian's build). **`AllowUsers` is not first-match-wins**: every `AllowUsers` line of every included file adds to the list (`servconf.c`), so a provider image's later drop-in with `AllowUsers debian` admits that account too, and `sshd -T` then prints `allowusers debian` as a third line (seen with 10.3p1 on 2026-10-09). The comparison for `AllowUsers` is therefore equality of the exact multiset of `allowusers` lines, never inclusion: an extra line is drift and is reported. `SshdDirective` gains no variant, because `HelloInfo` is frozen (§11.1), so drift inside the `Match` block is not reported by `Hello`; M4 adds a check request if it is needed.
- **`authorized_keys`** (root's): one line per role, each with `restrict,command="… serve-ssh --role <bootstrap|ops>"`. The agent refuses requests its role does not permit (`RoleNotPermitted`).
- **`viewer_authorized_keys`** (`ManagedFile::ViewerKeys`, `/etc/mooring/current/viewer_authorized_keys`), rendered by `crates/render/src/vps/viewers.rs` into every node's bundle: one line per viewer in key order, `Role::Viewer.authorized_keys_options()` (`restrict,command="/usr/local/lib/mooring/agent/current serve-ssh --role viewer"`), a space, then the key's `ssh-ed25519` form; zero bytes with no viewer. The Mac-only label is never written. Installed 0644 `root:root` (above). `docs/engines.md` maps its options to OpenSSH's sources. The golden `contract/golden/<fixture>/vps-<node>-viewer_authorized_keys.snap` exists for every fixture node, and only `2-nodes-3-users`, whose deployment has one viewer, is non-empty.
- **journald**: `Storage=persistent`, `SystemMaxUse=200M`, `MaxRetentionSec=14day`.
- **unattended-upgrades**: security origin only (`origin=Debian,codename=${distro_codename}-security,label=Debian-Security`), with automatic reboot at 20:00 in the host's time zone, assumed UTC.

**Built 2026-10-23 (M4e): what else profile 2 holds.** No node had installed version 2, so it grew in place.
- **Accounts** (`HostAccount`, created in this order by `Bootstrap` with `groupadd`/`useradd --system`, corrected with `usermod`, then read back): `mooring-watch` and `mooring-view` in the group `mooring` (`STATE_GROUP`), which no one else is in, and `mooring-xray` and `mooring-hy2` each in a group of its own. None has a home (`/nonexistent`) or a password; only the viewer has a shell.
- **The layout** (`HostProfile::directories`, owner, group and mode set by `Bootstrap`): `/var/lib/mooring` and every directory in it but the blobs are set-group-ID to `mooring` (2750), so the files root writes there (holds, the halt marker, the records, the Mac report, the installed version) are readable by the watch and the viewer without a `chown` per file; the blobs, which hold the bundle's secrets, are root's alone (0700, each blob 0600); `gate`, `watch` and `usage` are `mooring-watch`'s; and the one directory the group may write is `stop` (2770), where the viewer's stop request now lives (`/var/lib/mooring/stop/request.json`), so the viewer can neither write nor remove the holds. `/etc/mooring`, the engine store, the geodata link's directory and the agent directory are 0755 root's. Staging puts an engine's configuration in the engine's group and `watch.json` in `mooring` (each 0640), so each is read by its consumer alone; before M4e an engine could not read its own configuration.
- **A search grant** (`SearchGrant`, an `a+ … u:mooring-watch:x` line of the `tmpfiles.d` file): Debian 13 keeps `/var/log/unattended-upgrades` 0750 `root:adm`, so the watch, which reads the upgrade log's time, failed on it with `EACCES` and would have restarted without end. The grant lets it reach that file by name and nothing more: in the VM it read the time, while listing the directory and reading the log stayed refused. `systemd-tmpfiles` applies it at every boot.
- **The packages** (`PACKAGES`), one list for the user-data and `Bootstrap`.
- **chrony**: on.
- **tmpfiles.d**: `/run/mooring` (0750 root:mooring), with `gate.lock` group-writable (0660 root:mooring).
- **systemd units**: as listed in §5.2.

### 8.7 Mac exit config (`mooring-exit`; rendered in memory and sent on stdin)

```json
{"log": {"level": "fatal"},
 "endpoints": [{"type": "wireguard", "tag": "wg-lon1", "system": false, "mtu": 1280,
   "address": ["10.77.1.2/32"], "private_key": "<mac lon1>",
   "peers": [{"address": "<lon1 ipv4>", "port": 27820, "public_key": "<vps lon1>",
              "allowed_ips": ["10.77.1.1/32"], "persistent_keepalive_interval": 10}],
   "udp_timeout": "5m", "udp_nat_max": 4096,
   "bind_interface": "<uplink BSD name>"}],
 "outbounds": [{"type": "direct", "tag": "egress", "bind_interface": "<M7 BSD name>"}],
 "route": {"rules": [
   {"inbound": ["wg-lon1"], "ip_cidr": ["<every node IPv4>/32"], "network": ["tcp"], "port": [<reflector>], "action": "route", "outbound": "egress"},
   {"inbound": ["wg-lon1"], "ip_cidr": ["<every node IPv4>/32"], "action": "reject"},
   {"inbound": ["wg-lon1"], "ip_version": 6, "action": "reject"},
   {"inbound": ["wg-lon1"], "ip_cidr": ["<SPECIAL_V4…>"], "action": "reject"},
   {"inbound": ["wg-lon1"], "network": ["tcp"], "port": [25], "action": "reject"},
   {"inbound": ["wg-lon1"], "action": "route", "outbound": "egress"}],
  "final": "egress", "auto_detect_interface": false, "default_interface": "<M7 BSD name>"}}
```

There is one endpoint per `Applied` node, and every rule lists every endpoint tag in `inbound`. Node addresses cover every node whose VM still exists (`Retiring` and `RetiredPendingProviderDeletion` included). The reflector allow rule uses each node's own `PortPlan` reflector port, grouped by port (27900 by default). The TCP/25 reject follows `TrafficPolicy.deny_smtp25`, as the Xray rule does; with the default policy the output is exactly the above.

**These rules are the Level 2 boundary.** They check the **final destination IP** of every flow, so DNS rebinding cannot race them. They protect the M7 admin page, the home LAN, the carrier's CGNAT range and the Mac's loopback; `LanSubnet` (§7) guarantees that every configured LAN lies inside a rejected `SPECIAL_V4` class. Node IPs are reachable only on the reflector port, matching Xray's rule.

**Why the 127/8 and 224/4 rejects are load-bearing.**
- Traffic to the endpoint's own address is rewritten to 127.0.0.1 before routing (`protocol/wireguard/endpoint.go:231-240`).
- sing's bind control skips binding for loopback and multicast destinations (`sing common/control/bind.go`, `N.IsVirtual`).
- L4 T-deny-mac and the L6 lab lane test this path directly from the VPS side, bypassing Xray.

**Other bounds.**
- `udp_nat_max` bounds the UDP NAT state on the gVisor stack (`transport/wireguard/device_stack.go:84-88`).
- `allowed_ips` of the VPS /32 drops any inner packet not sourced from 10.77.k.1.
- `log.level` is `fatal`, because the endpoint logs every destination at INFO (`endpoint.go:243-244`).

**`mooring-exit` does no DNS.** Flows from the tunnel carry IPs, and L4 asserts that zero port 53 or 853 packets leave the `mac` namespace.

### 8.8 Mac prober config (`mooring-probe`)

```json
{"log": {"level": "fatal"},
 "inbounds": [
   {"type": "direct", "tag": "probe-lon1-reality", "listen": "127.0.0.1", "listen_port": 47101,
    "network": "tcp", "override_address": "<lon1 ipv4>", "override_port": 27900},
   {"type": "direct", "tag": "probe-lon1-hy2", "listen": "127.0.0.1", "listen_port": 47102,
    "network": "tcp", "override_address": "<lon1 ipv4>", "override_port": 27900}],
 "outbounds": [
   {"…MacProbeOutbound{ cfm: export of probe@lon1 VLESS, bind_interface: <uplink> }…", "tag": "probe-lon1-reality-out"},
   {"…MacProbeOutbound{ cfm: export of probe@lon1 Hysteria2, bind_interface: <uplink> }…", "tag": "probe-lon1-hy2-out"}],
 "route": {"rules": [
   {"inbound": ["probe-lon1-reality"], "action": "route", "outbound": "probe-lon1-reality-out"},
   {"inbound": ["probe-lon1-hy2"], "action": "route", "outbound": "probe-lon1-hy2-out"}],
  "auto_detect_interface": false, "default_interface": "<uplink BSD name>"}}
```

- `MacProbeOutbound { cfm: export::SingBoxOutbound, bind_interface: BindInterface }` is the single wrapper. The `cfm` part comes from the same emitter as user exports (`export::probe_outbounds`: the REALITY outbound and the Hysteria2 outbound of listener 0). CFM rejects dial fields such as `bind_interface` (`sing_box.rs:30-180`), so the field exists only in this Mac-local wrapper.
- Probe ports are `ProbePolicy::port_for(position among the applied nodes, protocol)`, from `base_port`; the probe ports of two nodes stay below the macOS ephemeral range. Tags are `probe-<node>-<reality|hy2>` and `probe-<node>-<reality|hy2>-out`. The direct inbound's `override_port` is the node's reflector port.
- The probe REALITY outbound always uses the classical chrome hello: upstream sing-box v1.14.2 has no `support_x25519mlkem768` (`option/tls.go:252-256`) and rejects unknown keys.
- Live probes run upstream sing-box, whose pin check verifies only the SPKI hash (`common/tls/std_client.go:137-145,278-295`). They therefore cover only the sing-box JSON/SPKI shape. Certificate validity, SAN and EKU are checked in Rust at `node apply` and at every `user export` (§9.2). The Clash/DER shape is proven only by L4 twins and L7.

### 8.9 cloud-init user-data (generated per node; mode 0600; deleted after adoption)

```yaml
#cloud-config
ssh_deletekeys: true
ssh_genkeytypes: []
ssh_keys:
  ed25519_private: |
    <one-time host key (openssh-key-v1), generated on the Mac>
  ed25519_public: "ssh-ed25519 <the node's SshPin>"
disable_root: false
users:
  - name: root
    ssh_authorized_keys:
      - "ssh-ed25519 <bootstrap key>"
package_update: true
packages:
  - wireguard-tools
  - nftables
  - chrony
  - unattended-upgrades
  - curl
```

`render::vps::cloud_init(&Deployment, &NodeId, &CloudInitKeys{host_private: OpensshHostKey, bootstrap_public})` renders it for a `Planned` node only (`NodeNotPlanned`). `render` may not depend on `keys`, so `mooringctl` passes the key text from `mooring-keys`. `OpensshHostKey::parse` decodes the file and accepts only one unencrypted openssh-key-v1 Ed25519 key with consistent check integers, matching public halves, a seed whose tail is the public key, and canonical padding (`HostKeyRule`). Its public key must equal the node's pinned host key, or the render fails with `HostKeyNotPinned`. The `ed25519_public` line is rendered from that pin, so the caller passes no separate host public key and the two cannot disagree.

User-data stays readable from the provider's metadata service for the VM's whole life, and DigitalOcean user-data cannot be changed after creation ([DO docs](https://docs.digitalocean.com/products/droplets/how-to/provide-user-data/), checked 2026-10-08). The injected host key is therefore only a first-contact pin. Bootstrap generates a fresh host key on the VPS and re-pins it (§13.2).

The bootstrap key is unrestricted root for the adoption window only, and is removed at the end of adoption.

`cloud-init schema --config-file` runs inside Debian 13 in L2. If a provider has no user-data, the CLI prints the bootstrap host-key fingerprint, and the operator compares it with the provider console before connecting.

---

## 9. CFM export and import-contract proof

### 9.1 Formats

Each user gets one file covering the nodes they hold credentials for, primary nodes first, then by node id (`mooring_export::export_user`). Each node contributes its REALITY outbound, then one Hysteria2 outbound per `PortPlan` listener, tagged `<node>-reality`, `<node>-hy2` and `<node>-hy2-<n>`. `ClientProfile` selects the shape: today `Cfm04` and `Cfm05` produce identical documents. `RealityMlkemOptIn` adds `support_x25519mlkem768: true` (sing-box) or `support-x25519mlkem768: true` (Clash), but only for client builds whose importer accepts it: `Cfm05` only, since CFM 0.4 rejects the key in both formats (`CapabilityUnsupported`).

**Default: sing-box JSON.** The root holds only `outbounds`, which is all CFM's adapter accepts (`sing_box.rs:30-180`).
```json
{"outbounds": [
 {"type": "vless", "tag": "lon1-reality", "server": "<ipv4>", "server_port": 443, "uuid": "<u>",
  "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
  "tls": {"enabled": true, "server_name": "<SNI>", "utls": {"enabled": true, "fingerprint": "chrome"},
          "reality": {"enabled": true, "public_key": "<b64url43>", "short_id": "<hex16>"}}},
 {"type": "hysteria2", "tag": "lon1-hy2", "server": "<ipv4>", "server_ports": ["61000:62999"],
  "hop_interval": "30s", "password": "<p>", "obfs": {"type": "salamander", "password": "<o>"},
  "tls": {"enabled": true, "server_name": "n<hex>.internal", "certificate_public_key_sha256": ["<b64 SPKI>"]}}]}
```
- Hysteria2 carries no `server_port`. CFM accepts that and uses the first port of the range (0.4 `subscription_import/sing_box.rs:131-152,531-541`; 0.5 `:131-158,558-568`).
- `hop_interval` is the listener's `HopInterval`, 5..=3600 s (§7).
- No `alpn` is emitted; h3 is the default on both sides.

**Optional: Clash YAML with `proxies:` only.**
- Block YAML; every string scalar is a JSON-encoded string (valid YAML 1.2 double-quoted).
- Booleans are plain `true`/`false`.
- No `udp`, `alpn`, `up`/`down`, groups, `rules` or `dns`: CFM parses those root keys strictly.

```yaml
proxies:
  - name: "lon1-reality"
    type: "vless"
    server: "<ipv4>"
    port: 443
    uuid: "<u>"
    flow: "xtls-rprx-vision"
    packet-encoding: "xudp"
    tls: true
    servername: "<SNI>"
    client-fingerprint: "chrome"
    reality-opts:
      public-key: "<b64url43>"
      short-id: "<hex16>"
  - name: "lon1-hy2"
    type: "hysteria2"
    server: "<ipv4>"
    port: 61000
    ports: "61000-62999"
    hop-interval: 30
    password: "<p>"
    obfs: "salamander"
    obfs-password: "<o>"
    sni: "n<hex>.internal"
    fingerprint: "<64 lowercase hex DER SHA-256>"
```

Revision 3 showed `type: vless` unquoted, against its own rule that every string scalar is JSON-encoded; the emitter quotes it, and CFM accepts both. CFM maps Clash `fingerprint` to a DER `certificate_sha256` pin (0.4 `subscription_import/clash/tls.rs:144-146`; 0.5 `:252-253`). The comment at `clash.rs:17-18` that says otherwise is stale. The pin stays valid because the certificate is never re-issued within a node's lifetime.

**Never emitted:** URIs, subscriptions, QR codes, HTML pages, or CFM's internal typed JSON. A VLESS+REALITY URI would import, since REALITY needs no pin, but the Hysteria2 URI importer of CFM 0.4 accepts no pin parameter (an upstream `pinSHA256` fails the import as unsupported) and refuses `insecure=1` (`subscription_import/uri.rs:240`, through `consume_certificate_verification_flags` and `reject_query_leftovers`: `subscription_import.rs:615,665`). Such a URI therefore cannot describe a 0.4 user's node, whose certificate is self-signed and pinned (§7). CFM 0.5.0 (`502adf9`, through `d828f92`) reads `pinSHA256` as a DER `certificate_sha256` pin and accepts `insecure=1` only beside it, never emitting it (`subscription_import/uri.rs:252-266`), but Mooring still never emits URIs, for the channel reasons of §9.4.

### 9.2 Guarantees enforced by types and at run time

**By the type system:**
- A REALITY proxy cannot be built without a `ClientHello`: `Chrome` or `ChromeX25519Mlkem768`, so a uTLS fingerprint is always present and the hybrid share can only come with chrome, as CFM 0.5 requires (`crates/cfw-singbox-config/src/profile_validation/tls.rs:159-174`). A missing fingerprint would fail at engine start, and the CFM 0.5 line rejects it at validation (CFM commit `f340fae`, 2026-10-08).
- A Hysteria2 proxy cannot be built without `CertificatePin`.
- `server` is a `PublicIpv4`.
- Salamander is the only obfuscation variant.
- `ShortId`, `HopInterval` and `PortRange` are newtypes; the client port range is the listener's contiguous `port..=hop.end`.
- No fields exist for features CFM rejects.

**At run time** (`node apply` and every `user export`), `mooring-export` (`crates/export/src/cert.rs`) derives the SNI and both pins from the stored certificate and checks it against what CFM's pin verifier enforces (CFM patch `common/tls/pinning.go:30-64`), each rule the same or stricter:
- the certificate parses with nothing trailing → `CertUnparseable`;
- validity covers now with a ±1 day skew margin, read as `notBefore` ≤ now − 1 day and now + 1 day ≤ `notAfter` → `CertNotCurrent`;
- the SAN is exactly one DNS name of the `n<16 hex>.internal` form, which becomes the SNI → `CertSanMismatch` (CFM accepts any matching name);
- the EKU is present and lists serverAuth → `CertEkuMissing` (CFM accepts an absent EKU);
- the SPKI is the canonical uncompressed P-256 encoding → `CertKeyUnsupported`, because CFM hashes the raw SPKI while upstream sing-box hashes `x509.MarshalPKIXPublicKey` of the parsed key, and the two agree only for a canonical key.

`mooring-export`'s `export_secret_refs` makes every check below that comes before reading a secret, in the same order and with the same errors as `export_user`, and only then lists the secrets the file needs: the user's VLESS UUID and Hysteria2 password on each node it holds, and those nodes' salamander passwords (M5, 2026-10-18). `mooringctl user export` reads exactly those from the keychain (`mooring-store`'s `read_snapshot`), after checking the file and its folder, so no secret is read for a refused user or a file that cannot be written. Every node is checked (generation, certificate, address) before any secret is read, so a stale node is reported before a missing secret of another node. A user export is also refused, in this order, when the user is not `Active` (`UserNotActive`); has not accepted the agreement revision this build ships (`AgreementNotAccepted{user, recorded, required}`: no `AgreementRecord`, or one of another revision than `AgreementVersion::CURRENT`; decision F9, 2026-10-15); has a capability its line does not accept (`CapabilityUnsupported`); holds no credentials (`NothingToExport`); or holds credentials on a node that is not `Applied` at the deployment's current generation (`NodeNotApplied{Stage | Stale}`, §7). The agreement is checked after the status, because a suspended, revoking or revoked user is refused for that whatever its record, and before anything about the file, so no node, certificate or secret is read for a user who has not agreed. The record's day is not compared with `now`: it is a calendar day without a time zone, and China's date runs ahead of UTC's from 00:00 to 08:00 Beijing time. The record is Mac-only, like the label: it is never rendered or sent, and it changes nothing in the file. `user agree` records it as a bookkeeping record that keeps the generation (M5, §7). A test pins the SHA-256 of the agreement's user-visible text for `AgreementVersion::CURRENT` (`crates/export/tests/export/agreement_text.rs`, Level 1: it detects an edit made without a new revision), so acceptances of revision N always cover the same text.

### 9.3 Contract proof (CFM's converter is never copied)

1. **Value-domain table.** `docs/cfm-contract.md` maps every emitted field to its model type and to the CFM rule, cited at pinned CFM commits. Every model type is a strict subset of what CFM accepts.
2. **Enumerated shapes gate (CI time; D-9).** `mooring_export::shapes()` enumerates every shape the emitter can produce, across protocol × format × client line × capability. A shape is the canonical form of a one-proxy document (root key included) with every variable leaf replaced by its type tag, hashed with SHA-256. At M1 there are 10 `(shape, client line)` entries: 4 for `cfm04` and 6 for `cfm05`, the extra two being the `chrome-x25519mlkem768` REALITY shapes.
   - **`cargo xtask acceptance`**, a `ci` step, reads `contract/cfm-acceptance.toml` and `contract/cfm-manifest.toml` with the `toml` crate (an xtask-only dependency) and the enumerated shapes through the xtask → `mooring-export` edge (§6.1). It fails when a manifest's importer digest is not the digest of the objects it lists, when the manifest's `[cfm.<client line>]` tables are not exactly the enumerated client lines (`ClientLines{missing, unknown}`), and when a `(shape hash, client line)` has no entry or an entry is stale (`require_recorded`). A `pending-real-cfm-import` entry counts as recorded, never as accepted; every entry is pending until M6. It reports one line with the accepted and pending counts.
   - **`cargo xtask release-acceptance`** is the release gate (`require_accepted`), which `xtask release-verify` (M7) runs; `ci` does not. It requires the same, and every entry `accepted` with evidence taken against the current **importer digest** of its line (`ImporterChanged` otherwise) by a CFM build of that line: the bundle version in the line's release line (`line`, such as `0.4`) and the sing-box core equal to the line's `sing_box_tag` (`OtherLineEvidence` otherwise). It fails until M6 has accepted every shape.
   - The importer digest is the SHA-256 of the three lines `<path> <git object id>` for CFM's `subscription_import/` (tree), `subscription_import.rs` (blob) and `crates/cfw-singbox-config` (tree) at the tracked CFM revision, recorded with its formula in `contract/cfm-manifest.toml`. A CFM importer change therefore invalidates stale records.
   - Each accepted record stores: the importer digest, the CFM build number and installed bundle version, the sing-box core, the sha256 of the exported file, the import date, the connect result (`connected`), and the sha256 of the evidence file.
3. **Goldens.** `contract/golden/<fixture>/export-*` hold byte-exact outputs for the `mooring-fixtures` deployments; CI checks their freshness and that no stray golden remains. Every user of every fixture is also checked for shape conformance.
4. **Engine-level checks.** `xtask cfm-client` reads an explicit manifest, `contract/cfm-manifest.toml`: the CFM revision, the sing-box tag, and the patch paths with their sha256 values. It fails with a typed error if the layout differs. It builds upstream and CFM-patched 1.14.1 and 1.14.2 CLI clients in a scratch directory.
   - **sing-box JSON exports** are run through `sing-box check` under all four builds, and they drive the L4 clients verbatim. The exception is the `support_x25519mlkem768` shapes: upstream sing-box has no such key (`option/tls.go:252-256`) and CFM 0.4 rejects it, so they are checked only under the CFM-patched 1.14.2 client.
   - **Clash shapes** cannot be loaded by sing-box. L4 instead runs a *JSON twin* of each Clash Hysteria2 node, carrying `certificate_sha256` (the base64 of the DER pin), on the CFM-patched clients only; `certificate_sha256` exists only in CFM's patch.
   - `docs/cfm-contract.md` states that a CFM-patched CLI stands in for CFM; it is not CFM.
5. **Real CFM.** L7 imports every shape by file into CFM 0.4 and then 0.5, run sequentially, and records the result.
6. **In production,** live probes are evidence of interoperability with upstream sing-box over the sing-box JSON/SPKI shape. They are not evidence of the CFM contract.
7. **Later.** If CFM's importer is extracted into a library on the 0.5 line (a separate CFM task), `mooring-export` adds it as a dev-dependency pinned to a full SHA and runs property-based import tests.

### 9.4 Delivery (runbooks `delivery.md`, `user-onboarding.md`, `user-agreement.md`; decided 2026-10-15)

The operator delegated F9, F10 and F11 to the recommended best-practice default on 2026-10-15 (§20.2); this section is that default.
- **The only form is a file.** `mooringctl user export <uid> --format singbox|clash --out <path>` writes sing-box JSON (the default) or Clash YAML with mode 0600, and warns if the path is under iCloud Drive. Exports are rendered on demand and never cached. A user who has not accepted the current agreement revision is refused (`AgreementNotAccepted`, §9.2): the user reads the agreement (`docs/runbooks/user-agreement.md`), and the operator records the acceptance with `user agree` (M5).
- **Never a QR code, HTML page, URI or subscription.** The reasons are the channels':
  - CFM cannot scan a QR code and registers no URL scheme, so a code or a link would still end as text that someone pastes;
  - CFM's Hysteria2 URI importer accepts no pin and refuses `insecure` (§9.1);
  - a subscription needs a new public listener and a CA certificate, which breaks the camouflage of ports 80 and 443 (§5.3, §8.2), and a leaked subscription URL would follow every rotation;
  - a QR image passes through WeChat's or QQ's servers, and through iCloud, which GCBD operates for Apple IDs in mainland China (Apple HT208352, 15 Apr 2025).
- **Channels** (F9):
  - in person, by AirDrop, or by USB stick carrying the encrypted image below (erasing flash memory does not reliably remove a plain file);
  - otherwise an AES-256 encrypted disk image (`hdiutil create -encryption AES-256 -srcfolder <dir> <name>.dmg`, which asks for the passphrase; never `-passphrase` on the command line; CFM users are on macOS), sent over any channel that does not tie it to the user's real-name identity in mainland China: never WeChat, QQ (QQ Mail included), another mainland-China mail or cloud service, or iMessage to a mainland-China Apple ID. Its passphrase is six words drawn at random from the EFF long word list (7,776 words, about 77 bits), new for every image and never chosen by a person. It is spoken once over an end-to-end encrypted call such as FaceTime Audio, never over WeChat, QQ or a carrier call into China, and never written in any message. Any server the image crosses may keep it, so the passphrase alone protects it against unhurried guessing *(inference: 77 bits is beyond offline guessing whatever `hdiutil`'s key derivation costs)*.
- **No iMessage to a mainland-China Apple ID** (F9), for anything about the service: Messages in iCloud for such an account is kept by GCBD. The plain file crosses no network but AirDrop in person.
- **Never** a screenshot, photo or QR image of an export, and never its text or any URI in a chat. The file-only rule rests on the channels, not on CFM: 0.4's import box is a single-line `<input>` (CFM `apps/cfw-tauri-shell/ui/src/app.js:2041` at `ac981c3`), but 0.5's is a `<textarea>` (`:2376` at `502adf9`) that sends any text that is not a subscription URL to `import_profile_text`, the command Import File uses (`:3787-3796`, `:3816-3825`), so a pasted document would import.
- **After import** the user deletes the file, the image and any chat copy, and the operator deletes the file and the image on the Mac. CFM keeps the credentials in its Keychain vault, and the stored profile holds only `credential_ref`s (`docs/cfm-contract.md`, "How CFM reads an export file").
- **The guide and the agreement** hold no secrets, but they describe a proxy that avoids mainland traffic, so they never cross WeChat, QQ or another mainland-China service (§15.5's reasoning: a record tying a person to a circumvention service can harm them). They are handed over in person or in an encrypted image of their own, as above, and sent as the text from each title on, without the operator notes. The user accepts the agreement aloud on the end-to-end encrypted call, and the operator then runs `user agree`.
- **Ordinary chat carries no words about the service.** WeChat or QQ may arrange a call ("a file is ready" is already too much), and nothing else. Support is a FaceTime Audio call or a meeting in person (`delivery.md`, section 9; the agreement's clause 5).
- **Re-delivery** uses the same channels: after a rotation (§13.4), a `user reissue`, a new REALITY target (§11.7), or the standby's arrival (M9). A new agreement revision changes no byte of a file (it only gates the next export), so it is not a reason to re-deliver. There is no subscription (F11). The M8 pilot has one node, so a blocked node means a rotation and a new file for every user; from M9 every user holds both nodes.
- **Leaks and seizures** (`delivery.md`, section 8; the agreement's clause 2). A copy outside these rules, a lost device, or a file handed on is a `user reissue`, applied at once, and a new file for that user alone; the nodes rotate only when blocked. A device seized or inspected by someone else is a revocation and a rotation of every node the user held (§13.5).

---

## 10. Mac runtime

### 10.1 Daemon loop

The daemon runs on a tokio current-thread runtime with a 2 s tick. Its state machine lives in `daemon-core` and is driven through traits, so the Linux L4 harness runs the same code. *Built 2026-10-23 (M5c):* `daemon-core`'s `exit::ExitMachine`, driven through `ExitPorts` (render, engine check, start, exit and stop, probe, latch, node calls), which `mooringctl` implements and the tests script; its tests run on hosted CI. *(Revision 9.)* The router-console slice has no state machine yet and uses std threads instead: one per control connection (at most 8), a condition-variable hub for the latest status, and a poll loop that sleeps on a channel from the acceptor between polls. M5 decides, when it builds the state machine, whether the deployed daemon keeps them (then this paragraph and §6.3 change) or replaces them with the runtime, in which case `mooringctl::daemon::hub` and `serve` are removed in the same change, not kept beside it. *Decided 2026-10-23 (M5c):* the deployed daemon keeps std threads and no tokio runtime: the loop (`mooringctl::daemon::deployed`, a 2 s tick), the SIM meter's thread (it reads the egress counters every 2 s whatever the loop waits for, so a slow call never widens a gap between readings), and the control socket's acceptor and connections. The loop polls the M7 only in the slot after a direct-probe round (at least 20 s before the next, `ROUTER_SLOT`), so a slow M7 never delays a probe; node calls (gate, halt, hold) are made from the loop, after the engine has stopped. The status is published when the exit's state changes and at least every 10 s.

States: `Disabled | Preflight | Starting | Verifying | Serving{ip, verified_at} | Degraded{reasons} | Down(DownReason) | Paused(Sleep)`.

Each tick does the following:

1. **Inputs.**
   - If `state.json` changed, re-read state. Neither counter alone detects every change, because `Bookkeeping` records (§7) keep both.
   - Secrets are re-read once per config generation and kept in memory.
   - `errSecInteractionNotAllowed` at read time → `Down(SecretsUnavailable)`.
2. **Interfaces.**
   - `macsys` resolves the selectors from `NET_RT_IFLIST2`.
   - Zero matches or several matches is a typed error. An IPv4 address outside the selector's subnet is `EgressSubnetMismatch`.
   - There is **never** a fallback to Wi-Fi.
   - A `PF_ROUTE` monitor triggers an immediate direct probe on any route or interface change, including a new utun.
3. **Supervision of each engine.**
   - Render, and compare the digest with the running config. If it is unchanged, nothing restarts.
   - Run `<engine> check -c stdin`. A non-zero exit → `EngineConfigRejected{stderr_tail}`, with no retry.
   - Then `run -c stdin`. An exit within 10 s → `EngineStartFailed`, with no retry until an input changes or the user chooses Retry.
   - An exit after the engine has been healthy → backoff of 1, 2, 4 … 60 s. Five such exits in 10 minutes → `EngineCrashLoop`.
   - A stale engine recorded in `run/engine-*.pid` is killed only if `proc_pidpath` matches our engine path.
   - Failures of `mooring-probe` map to `NodeProbeFailed{stage: ProberUnavailable}` only.
4. **Probes.**
   - Direct probes run every 30 s, and immediately after any route change.
   - In-chain probes run every 300 s, and 10 s after any start, wake, interface change or config change.
5. **SIM meter.** It takes deltas of `if_data64` on the egress interface and accumulates them per billing cycle in `usage/sim-<cycle>.json`, detecting counter resets. It is accurate only if the M7's Wi-Fi and offloading are off (M2 checklist); otherwise it is a lower bound.
   - *Built 2026-10-23 (M5c, `daemon-core`'s `meter`):* the meter keeps the line's received and sent bytes per UTC day in one file, `usage/sim-meter.json` (version 1, mode 0600, in a 0700 `usage/` directory), and a cycle's bytes are the sum of its days, so a corrected anchor (`sim set-anchor`) moves no byte. The kernel gives the daemon each counter modulo 2^32 and rounded down to 1 KiB (`macsys`), so every delta is taken modulo 2^32 against the reading before: a reading below the one before is a wrap when the bytes it implies fit in what the line could carry since (`MAX_LINE_BYTES_PER_SEC`, 2.5 Gbit/s *(inference)*), and otherwise counters that restarted, counted whole; a reading of another boot (`kern.boottime`) or another interface (index or link-layer address) is restarted counters too. Counting a restarted counter whole can only over-count, the safe direction for a hard stop. A day is marked short when a reading followed a gap long enough for a wrap to pass unseen (about 14 s at that rate) or the counters restarted; a cycle with a short day is reported as a lower bound. The first reading of a new meter only sets the counters it compares with. A property test checks that readings every 2 s reproduce a 64-bit count exactly from its value modulo 2^32.
   - Cycles start as `SimPolicy.cycle` gives them (§7), at UTC midnight, because neither carrier states a time of day or time zone for its renewal *(inference)*. The M7's own data-usage reset date is a day of the month (manual p. 65), so it matches only a monthly rule; with 1pMobile's 30-day cycles the M7's counter is read as a running total, never as the cycle's.
   - Traffic the M7 generates itself, such as its firmware checks, never reaches the Mac's counters *(inference)*. The meter is therefore reconciled against the M7's own counter and the operator's reading of SMARTY's dashboard or app usage history (§15.3), which counts in binary units per full MB, re-sent packets included ([SMARTY-PG] p23). Whether that view shows the GB used on an Unlimited plan, and how fresh it is, is not stated; M2a records it.
6. **Latches and status.**
   - Violation latches persist in `run/latch.json`, so they survive daemon restarts.
   - Status is written atomically to `status.json` (a snapshot for diagnosis) and pushed to `status --follow` subscribers.

**Control channel.** The socket is `run/control.sock` (mode 0600, inside the 0700 Application Support directory). It speaks `DaemonRequest = ProbeNow | Retry{scope} | WaitVerdicts{config_generation, timeout} | Status | Subscribe`, defined in `daemon-core::control`.
- The CLI is the only client.
- The Swift UI calls the CLI.
- No signals or pid files are used for control.
- Revision 5 plans two more requests for the console *(M5)*:
  - `PollNow` polls the nodes at once, when the app or the CLI wants fresh figures;
  - `Events{since}` reads the Mac's event journal (§15.7).
- *Built 2026-10-23 (M7):* the protocol line (§15.1). The daemon's first line on every connection, a busy refusal's too, is `{"control_protocol":1}` (`daemon-core::control::ProtocolLine`, `CONTROL_PROTOCOL`). The CLI reads it before any reply and refuses a daemon whose first line names no protocol (`DaemonProtocolMissing`, as one built before the line does) or another (`DaemonProtocolOther`), saying to restart the daemon from the app; nothing after that line is read. From the first release on, any change to a request, a reply or this line raises `CONTROL_PROTOCOL`.
- *Built 2026-10-23 (M5c):* `Retry` (`"retry"`), which `mooringctl exit retry` sends: the connection hands it to the loop, which runs it at its next tick, and answers `"retry_queued"`; without a deployment it is refused as `not_deployed`.
- *Built in revision 9:* `Status` and `Subscribe`, as JSON lines (`daemon-core::control`). The CLI writes one request line (`"status"` or `"subscribe"`, at most 256 bytes) and the daemon answers with reply lines, each a `DaemonReply` of at most 1 MiB: `{"status": <ConsoleStatus>}`, or `{"refused": {"reason": "busy" | "bad_request" | "no_status_yet"}}` before it closes. `Status` answers the latest status once, or `no_status_yet` before the first poll has finished; `Subscribe` sends the latest and then each new one, waiting for the first if there is none. The daemon keeps one line, the latest, and a number that grows with each, so a slow subscriber skips to the latest instead of queueing (memory stays one line however many clients there are). It serves at most 8 clients at once and refuses the next as `busy`; a request must arrive within 5 s and each reply line must be written within 10 s, each as a whole: every read waits only for what is left of the request's deadline, and a reply line is written with the socket non-blocking against its deadline, because a blocking send(2) waits for buffer space again each time the reader drains a little and SO_SNDTIMEO bounds each wait, not the call (a reader draining a long line a few bytes at a time could otherwise hold its slot without end). An idle subscription checks every 5 s that its client is still there (the end of its side, or any byte after its request, ends the connection). `mooringctl status [--follow] [--json]` is the client: it re-encodes each status it decodes, flushes every line, reports a daemon that is not running (`DaemonNotRunning`), a refusal (read even when the daemon closed before the request was sent, as a busy daemon does), a reply it cannot read, a closed stream (`DaemonClosed`) and a follow silent for 240 s (`DaemonSilent`), each exiting 1. A daemon whose poll does not finish (it waits, say, at a keychain prompt) keeps its last status and sends it again to every new subscriber, so `--follow` judges a status by its age, not by when it came: one older than 240 s by the Mac's clock is not printed, and the follow ends with `StatusStale`, naming its time; each status sets how long the follow waits for the next (240 s from when the daemon made it). With `--until-parent-exits`, which Mooring.app passes and which needs `--follow`, it also asks every 2 s whether the process that started it is still there, and once it is not (the app quit, crashed or was killed, and launchd adopted the child, so its parent id changed), or if launchd was its parent from the start, it ends with success, printing nothing more: nothing reads it any more, and it would otherwise hold one of the daemon's client slots until its next write failed or its silence ran out (observed 2026-10-22: the `status --follow` of an app ended with `SIGTERM` outlived it). Without the flag it never asks, so a follow kept running on purpose (`nohup`) outlives its shell. A line may arrive in parts across those checks, and the bound applies to the whole line.
- The daemon holds `run/daemon.lock` (an exclusive `flock`) while it runs, so a second one is refused (`DaemonAlreadyRunning`); holding it, it replaces a socket an earlier daemon left (only a socket: any other file there is left alone, `SocketPathTaken`). A `run` directory that is there already must be a directory, not a link (`RunDirNotDirectory`), and is set to 0700. Before each poll the router console checks again that no deployment exists, and once one does it serves the exit instead (M5c), rather than publish `no_deployment` beside it; an acceptor that ends stops it at once, not at the next poll. A status snapshot that cannot be written is logged once while that lasts, and its recovery is logged too. With a deployment, a state, latch or SIM meter file it cannot read stops it (none is read as empty), and so does a meter that can no longer count; launchd then starts it again a minute later.

### 10.2 Preflight, probes and verdicts

**The probe primitive.** A TCP connect, then read one line `<IPv4>\n` from a node's reflector (§11.4) within 5 s.

| Probe | Path | Purpose |
|---|---|---|
| `direct` | A socket with IP_BOUND_IF on the egress interface → each node's VPS4:27900 | The carrier's public IP as the internet sees it |
| `uplink` (`Separate` only) | The same, bound to the uplink interface | The home IP, which must differ |
| `in-chain` per node × {reality, hy2} | 127.0.0.1:4710x → `mooring-probe` → VPS → Xray `exit` → `wgexit` → `mooring-exit` → `egress` → VPS4:27900 | Proves the export shape, the live server, the tunnel, the Mac exit binding and the egress IP together |

**Preflight** runs before the engine starts. It requires all of the following:
- the egress interface resolves;
- at least one `direct` probe succeeds;
- the carrier check is recorded (otherwise `CarrierCheckUnrecorded`, M5): `exit init` runs before the SIM's prefixes are known, and the exit serves nothing until they are observed and recorded;
- the returned IP is inside `carrier_prefixes` (otherwise `OutsideCarrierPrefixes`) and is not any node's IP;
- in `Separate` mode, `uplink` succeeds and returns a different IP;
- *(revision 5; plan, M5)* the Mac is attached to no foreign network (P0-2, below). Otherwise the result is `Down(ForeignNetworkAttached{findings})`, every finding with its interface (`daemon-core`'s `foreign_networks`, built). A network is foreign when any of these holds (critique D-11):
  - an interface other than the egress, `lo0` and CFM's `utun*` holds a non-link-local IPv4 address or a global IPv6 address;
  - a default route does not go via the egress;
  - macOS Instant Hotspot has joined the operator's iPhone.

  The check is a pure `daemon-core` function over a typed snapshot of interfaces and routes, unit- and property-tested on this Mac. The `macsys` adapter that takes the snapshot is checked live in L8/M8. Lab builds exempt `bridge100` through `cfg(feature = "lab")`.
- *(revision 6; plan, M5)* the SIM plan is recorded. A state lifted from version 1 has none (§7, P0-1), and the exit stays down, with a typed reason, until `sim set-plan` records it.

Any failure keeps the engine stopped, with a typed reason.

*Built 2026-10-23 (M5c), and what the Mac's snapshot holds.* The foreign-network check runs on the kernel's interface list while the egress resolves (without it the exit is down for that already): every interface's IPv4 addresses, the egress exempt. IPv6 addresses (`macsys` lists IPv4 only), default routes and the personal-hotspot flag are not in the snapshot yet: an interface that carries a default route, and a joined hotspot, hold a routable IPv4 address, which is a finding already, so only an IPv6-only network would pass unseen. No tunnel is exempt: while CFM's TUN (or Tailscale, or a VM's bridge) is up, the exit is down with it named. The carrier address for `exit record-carrier` is observed with `mooringctl exit observe --interface <bsd>`, which asks each adopted node's reflector through the pinned M7 and says whether the address passes a recorded check. When the SIM changes, `exit record-carrier --replace` records the new carrier's check in place of the old one: a configuration change (the operator's explicit act, design §7), so every node then needs `node apply`, and a latch from the old check clears with the generation.

**The exit Mac and the university network (P0-2, revision 5).** Durham University's Student IT Regulations v2.5 apply to every student who connects to or uses University IT facilities, network access included (regulation 1.1). The document's publication date is left as "xxx"; it was read on 2026-10-08.
- Regulation 5.1 forbids doing any of the following without authorisation:
  - operating a service that redistributes access to others, including connecting equipment that routes, bridges, switches or repeats traffic from other devices or networks, or any device (such as a PC or server) configured to do so;
  - connecting to the University network any device that offers a service to others.
- Regulation 2.3 forbids unsanctioned commercial activity on University IT facilities. That matters only if payment ever happens, and it supports F3.

This is a reading of the regulations, not a ruling by the University. Hence:
- **From M2b on**, when the Mac first runs a WireGuard test exit that routes flows the VPS starts, the exit Mac joins no Durham network (campus Wi-Fi forgotten, no eduroam, no campus Ethernet) while any exit or test tunnel runs. The console review first put the cutover at M8 at the latest, which was too late (critique C-2).
- **In M2a** nothing routes, but measurements still run with Wi-Fi off. A new USB-C Ethernet adapter normally ranks above Wi-Fi in the service order *(inference)*, and background traffic hopping between interfaces would spoil the byte baseline (critique C-3).
- **Operator monitoring and control traffic never crosses Janet.** That covers management SSH, which is dial-bound to the uplink (§10.5), and any remote view (§15.9) (critique C-1). The operator decided on 2026-10-08 (F15) that no operator traffic crosses Janet or eduroam, push alerts and viewer sessions included: the phone receives alerts and views the nodes on mobile data, with Wi-Fi off on campus.
- **The Mac's own traffic then goes over the SMARTY line** and is counted by the SIM meter: macOS updates, iCloud and development sessions. Turn off iCloud Photos and Drive sync on the exit Mac. Do large downloads before cutover: macOS updates, Xcode, toolchains (critique D-7). The SIM forecast shows a line for the operator's own use (§15.3).
- The rules of the college or accommodation on running equipment in a room were not researched.

**Running checks.**
- **Every direct probe** re-checks the carrier prefixes. A violation stops the engine within 30 s, which covers the M7 switching its WAN to Wi-Fi or Ethernet offload.
- **In-chain verdict for IP `x`**, with direct probes `d1` taken immediately before and `d2` immediately after. Checks apply in this order:
  1. `x` is a node IP → `EgressIsNodeAddress`. Stop the engine, and send `Shutdown` to that node.
  2. `x ∉ carrier_prefixes` → `OutsideCarrierPrefixes`. Stop the engine.
  3. In `Separate` mode, `x` = the uplink IP → `EgressEqualsUplink`. Stop the engine.
  4. If `pairing = Paired` and `x ∉ {d1, d2}`:
     - if `d1 == d2`, the result is `EgressMismatch`. Stop the engine.
     - otherwise the result is inconclusive. Re-run the bracket once immediately. A second inconclusive result becomes `NodeProbeFailed{stage: CarrierAddressUnstable}` (Degraded). This resolves a known race explicitly; it is not a fallback.
  5. Otherwise `Verified{x}`.
- **Connect, read or parse failures** → `NodeProbeFailed{node, proto, stage}`. The node is `Degraded`, and the exit keeps serving its other nodes.

**After a violation** (steps 1–4):
1. Persist the latch.
2. Stop `mooring-exit`. This is local and needs no network. The VPS gate then closes within 3 × keepalive.
3. Send `GateSet{Closed, EgressViolation}` to every node.
4. Notify the operator.

There is no automatic retry. The latch clears only on Retry, a `config_generation` change, or a change in egress interface identity.
- *Built 2026-10-23 (M5c):* whichever of the three clears it, the nodes are asked to clear their holds (`ClearHold{EgressViolation}`) once a fresh direct probe has passed, before the engine starts; a halted node stays halted until the operator resumes it. A node call that cannot be delivered is tried again every 60 s, and one the agent refuses is not. A daemon that starts with a latch on disk sends the gate calls again, since the daemon that latched it may have ended before it told the nodes. While the engine runs, one failed direct-probe round is tolerated and a second in a row stops it (`DirectProbeFailed`); before it starts, one failed round keeps it stopped.

**Retry flow** (`mooringctl exit retry`): preflight, then `ClearHold{EgressViolation}` to each node, then start the engine, then probes.

**Calibration of the gap before the first verdict** (about 10 s). In that window a user flow can leave only through the IP_BOUND_IF `egress`, whose carrier IP preflight has just checked. VPS-IP leaks are prevented by the owner guard.

*Built 2026-10-23 (M5d):* `mooring-probe` runs beside `mooring-exit` from the same `engines/` directory, checked against its pin before each start, and restarts only when its config changes; one that cannot start is tried again at the next round, and meanwhile every probe of a round fails as `ProberUnavailable` (`Degraded`, never `Down`). The first round runs 10 s after the engine starts, then every `in_chain_every` (300 s): for each applied node and protocol, a direct probe to that node's reflector, the in-chain probe through the probe inbound on 127.0.0.1 (at most 10 s), and a second direct probe; both direct probes are judged as every direct probe is, and the three by `in_chain_verdict`, with its one immediate re-run. A violation ends the round and is latched as above. The exit is `Serving{ip, verified_at}` once a probe of the running engine has verified, and `Degraded` naming every probe of it that failed; a new engine is `Verifying` until its own round. The pinned `mooring-probe` accepts the rendered fixture config (`check -c stdin`, 2026-10-23).

**ReachabilitySuspect.** A node is marked `Degraded(ReachabilitySuspect{node})` when all of these hold:
- it had user (not probe) bytes in the last 7 days;
- it has had zero user bytes for 6 hours between 08:00 and 24:00 China time;
- its probes pass.

This is the only signal that a node may be blocked in China. Nothing happens automatically.

**WatchStale.** If a node's watch status is older than `WATCH_STALE_SECS` (30 s, agent-proto `watch.rs`) at a `Status` poll, the node is `Degraded(WatchStale)`. The node's own dead-man rule uses the same bound (§15.8).

### 10.3 Power and sleep

**Assertions.** `mooring-power` holds `NetworkClientActive`, which keeps the system awake in dark and full wake on AC (`IOPMLib.h:344-380`), and `PreventUserIdleSystemSleep`, but only while the exit is enabled and the Mac is on AC.
- On battery, the status is `Degraded(OnBattery)` and sleep is allowed.
- Mooring never changes `pmset` or any system setting.

**Will sleep:**
1. The helper sends `will_sleep`.
2. The daemon **stops `mooring-exit` first**. This is local; management SSH is dial-bound and does not depend on the engine.
3. The daemon sends `GateSet{Closed, MacDrain}` to every node, with a 4 s total budget. *(Built, M7.)* Each node's call is bounded by what is left of the budget: its ssh session runs in a process group of its own, which is killed with its dialler when the budget runs out (§10.5), since ssh's own timeouts allow 15 s and more. The nodes with a site are asked in id order.
4. The daemon acknowledges, and the helper calls `IOAllowPowerChange` well inside IOKit's 30 s acknowledgement window.
5. If the budget is exceeded, the daemon records `DrainTimedOut` and sleep proceeds. The VPS detects the outage by liveness within about 30 s.

*Built 2026-10-23 (M7).* The daemon takes the helper's events at each 2 s tick, so a drain starts at most a tick after `will_sleep`. The drain's outcome is the status's `last_drain` (`Completed`, `TimedOut` when the budget ran out before or during the calls, `Failed` when a node could not be reached or refused), and `last_sleep` and `last_wake` are beside it. The exit is `Paused` from the drain until `did_wake`: no tick starts the engine in between, so no handshake can complete after the drain. The daemon lets the sleep proceed (`allow_sleep`) once the paused status is published. A helper that ends while the exit is paused wakes it, since its sleep has either proceeded or died with it. The helper was checked live on this Mac: the hold shows both assertions as "Mooring exit" in `pmset -g assertions`, the release removes them, and the end of its input ends it with status 0. A real sleep and drain against a node is not yet exercised: this Mac never sleeps (`sleep 0`, below).

**Drain semantics on the VPS.** `MacDrain` records the `latest-handshake` value at drain time. It clears only when that value *changes*, meaning a handshake completed after the drain, and rx has grown. Because the engine is stopped before the drain, no handshake can complete in between. Comparing for change avoids the one-second resolution of `wg show dump`.

**Did wake:** re-resolve interfaces → preflight → start → probes. **Target: `Serving` within 10 s of wake.**

**Lid closed.** Clamshell sleep without an external display is unknown on macOS 27; M2 and M7 measure it. The documented options are closed-display mode on AC, or the operator's own `pmset` choice. Until it is measured, the lid stays open.

**A crashed daemon** closes the helper's stdin, and the assertions are released.

**This Mac as a server (facts, 2026-10-08; revision 5).**
- `pmset -g cap` on this MacBookPro18,2 (macOS 27.0, 26A428) lists no `autorestart` and no `acwake` capability. `pmset` therefore cannot set this Mac to power on, or to wake, when mains returns, and advice to run `pmset -a autorestart 1` does not apply here (critique A-30).
- `pmset -g custom` shows `sleep 0` and `displaysleep 0` on both AC and battery. With these settings the Mac never sleeps on battery either, so `Degraded(OnBattery)` does not lead to sleep as this section assumes. A screen lock tied to display sleep also never triggers (critique C-5, C-14). Mooring never changes these settings (§18). The operator's choice is F19, and `pmset -g` and `pmset -g cap` are recorded in `docs/measurements/M2.md`.
- **Charge Limit** (80–100 %) exists on Apple silicon from macOS 26.4. A Mac with a limit set still charges to 100 % occasionally (Apple support 102338, 9 Apr 2026). For a Mac on AC around the clock, set it to 80 %.
- From macOS 26.1, **Background Security Improvements** install whatever the Software Update settings say (eclecticlight.co, 6 Nov 2025). Whether they force a restart is unverified. A restart leaves the exit down until someone logs in, because FileVault needs a physical login (§5.1).

**Power cuts (critique C-5).** On a mains failure the Mac switches to battery and becomes `Degraded(OnBattery)`; it does not lose power. In Plugged-In mode the M7 has no battery and drops at once, so a UPS keeps the exit up through a short cut (F8). While the operator keeps the battery installed (revision 7), the M7 rides through a cut on it *(inference: until it drains; M2a's drill times it)*. FileVault matters only after a restart or a drained battery.

With the battery out, it powered itself on when mains returned and reached its home screen in about 60–70 s (M2a, 2026-10-13); the time until data flows is timed with the SMARTY SIM. The manual says only that connecting a computer's USB cable powers on a switched-off hotspot (p. 22), and it describes powering on with the Power button (p. 15).

A SIM PIN, if enabled, must be entered at every power-on (manual p. 62), which defeats unattended recovery. That trade-off is F17.

### 10.4 CFM coexistence

Every socket the Mac exit opens is interface-bound: the WireGuard endpoint, `egress`, the probe outbounds, the direct probes and management SSH. CFM sets `includeAllNetworks=false` and `enforceRoutes=false`, so these sockets should bypass its default route *(inference)*.

Two lanes prove this, both with tcpdump showing zero exit or probe packets on CFM's utun:
- **L6-bypass** (this Mac, today): Wi-Fi stands in for the physical interface, with a public destination, CFM's TUN on, in system-proxy mode, and with both off.
- **M2** (the real M7).

The L7 lab cannot prove the bypass, because a VM subnet is a connected route that is more specific than any TUN default. If CFM ever enables `includeAllNetworks`, the carrier check turns into a violation and the exit stops.

### 10.5 Management SSH from the Mac

```
/usr/bin/ssh -F /dev/null -i <ssh/<node>/ops_ed25519> -o IdentitiesOnly=yes
  -o ProxyCommand="<mooringctl> ssh-relay <ssh/<node>/relay-<pid>-<n>.sock>"
  -o UserKnownHostsFile=<ssh/<node>/known_hosts> -o StrictHostKeyChecking=yes
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ClearAllForwardings=yes
  -o ForwardAgent=no -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 root@<ipv4>
```

- `/usr/bin/ssh` is OpenSSH_10.3p1 on this Mac.
- Agent responses are capped at 1 MiB, and control characters in every remote string are escaped before display or logging.
- The daemon makes only these remote calls:
  - `GateSet` on a sleep drain or a violation;
  - `Shutdown` on `EgressIsNodeAddress`;
  - `ClearHold` on Retry;
  - a `Status`/`Usage` poll every 10 minutes (*built 2026-10-23, M5d:* `Status`, in the slot after a direct-probe round; a node that does not answer is shown unreachable since its first failed poll in a row, with its cause, and one whose watch had not written for more than 30 s by its own clock degrades a serving exit as `WatchStale`; ssh's own failures are one `Transport` until the runner tells a changed host key apart);
  - *(revision 5; plan, M5)* with that poll, or on `PollNow`, an incremental `UsageSeries` pull from the last stored bin and an `Events{since}` read from the last stored event (§11.1, §15);
  - *(revision 6; plan, M5)* with that poll, a `PutMacReport` push of the remote viewer's report to each node (F5, §15.9), and, once M4 adds the request, the notices the Mac rendered (§15.8).

  Everything else is an explicit CLI action.
- Every call leaves over a connection bound to the M7's interface, never over Wi-Fi or Janet (P0-2, §10.2).
- *Built 2026-10-23 (M7):* a session may carry a deadline, and only the sleep drain's does (§10.3). the session's connection opens within what is left of it, and ssh then runs in a process group of its own, which a watcher kills with its ProxyCommand when the deadline passes; a session killed before its reply arrived whole fails as `PastDeadline` (`AgentUnreachable::Timeout` in a poll), and a whole reply stands. Every other session runs in the caller's process group, as before, so Ctrl-C in a terminal still ends ssh with `mooringctl`. A group whose members are all exiting as the deadline passes (`killpg` answers `EPERM`) ended by itself.
- *Built 2026-10-23 (M5b):* the dialler is `mooringctl dial-bound --interface <bsd> %h %p`, the interface given to the node command rather than resolved from the uplink selector. Before it connects it checks that the interface's default gateway is the pinned M7 (the check `exit init` makes), so a connection cannot leave by Wi-Fi or campus Ethernet; it binds the socket to that interface (`IP_BOUND_IF`) and relays stdin and stdout. The ssh line above also carries `-o BatchMode=yes`, so ssh never asks at the terminal. Each request is one session, as the forced command serves one; ssh's stderr is escaped and capped at 4 KiB, and a session without a reply is reported with ssh's exit status and that stderr.
- *Revised 2026-10-23 (the first live `node adopt` of lon1):* the dialler could not run as ssh's ProxyCommand. On macOS 27.0.1 the kernel's neighbour table, which proves the gateway is the M7, was empty to `mooringctl dial-bound` under `mooringctl`'s ssh, from Terminal.app and from other shells alike, while `mooringctl` itself, ssh, and a ProxyCommand under a shell's ssh all read it; a copy of `mooringctl` signed with the operator's Apple Development identity read none, even itself. So the process that starts ssh now does what the dialler did. It checks that the interface's default gateway is the pinned M7 when a node command or a daemon poll begins (`M7Egress`, which only that check makes, so no session can be opened through an unchecked interface), and opens each session's TCP connection itself, bound to that interface (`IP_BOUND_IF`), within `ConnectTimeout` or what is left of the session's deadline. ssh's ProxyCommand, `mooringctl ssh-relay <socket>`, connects to a one-time Unix socket in the node's directory (`ssh/<node>/`, 0700), which is unlinked as soon as it connects, and relays its standard input and output there; the process that opened the connection splices the socket to it. Once ssh closes its standard output, the relay stops: it no longer waits for a ProxyCommand that never connected, and the node's connection is shut, so a node that keeps its end open cannot hold the session. A relay socket that cannot be bound or served fails the session as `Relay`, before ssh's own failure; a splice that ended in an error is noted after ssh's stderr. The M7 check therefore runs once per command or poll rather than before every connection; every connection is still bound to the checked interface.
- *Revised 2026-10-24 (the second live `node adopt` of lon1):* the adopt over the relay timed out after the identification exchange ("Connection to UNKNOWN port 65535 timed out"). Two faults in `ssh-relay` caused it, both measured with the real binary. Its sending thread read standard input through the process's `Stdin`, whose lock `main` holds for the whole command, so it waited for ever and none of ssh's bytes reached the node. And it wrote the node's bytes through `Stdout`, which Rust line-buffers: the server's identification line went out at its newline, while the binary packets after it waited in the buffer until the node closed the connection. `ssh-relay` now relays over standard input and output of its own (duplicated descriptors, unbuffered and unlocked), and the relay flushes after every read in both directions whatever its output buffers. The session tests had run nc in place of `ssh-relay` and the relay's own tests wrote into memory, so neither could see these. An integration test now runs the real binary as ssh does (`crates/mooringctl/tests/relay`), and a unit test relays through a line-buffered writer.

---

## 11. VPS runtime

### 11.1 Agent protocol (`mooring-agent-proto`, `PROTOCOL = 1`)

**Framing** (`crates/agent-proto/src/framing.rs`).
- One SSH session per request.
- stdin carries one JSON line, at most 1 MiB, with `deny_unknown_fields`. `PutBlob` is followed by exactly `len` raw bytes, at most 128 MiB, then end of input.
- stdout carries one JSON line, at most 1 MiB: `{"Ok": <Response>}` or `{"Err": <AgentError>}`.
- A non-zero exit is a transport failure or crash, which the Mac classifies separately.
- Unknown fields are rejected at every level, an `Option` field missing on the wire is rejected rather than read as absent, and every validated value (`Sha256Hex`, `TargetHost`, `StderrTail`, …) is checked again on receipt. Readers never panic on arbitrary input.
- `Request` is `PutBlob{sha256, len} | Line(LineRequest)`. On the wire the split is invisible, but `write_request` takes only a `LineRequest` and only `write_put_blob` writes a `PutBlob`, with its payload, so a `PutBlob` without its bytes cannot be expressed.
- A malformed frame is `ReadError::Malformed{cause, line, column}`. It carries no decoder text, so a hostile reply cannot put VPS-supplied names or control characters into a Mac-side error.

**Roles.** The forced command passes `--role bootstrap|ops|viewer` (`Role::permits`, which names every request kind).
- The bootstrap role may send only `Bootstrap`.
- The viewer role (decision F5, 2026-10-08; §15.9) may send `Status`, `Usage`, `UsageSeries`, `Events`, `MacReport` and `GateSet`, and `GateSet` only with the Operator reason: its emergency stop. It can never reopen the gate, clear a hold, apply, halt or resume, so resuming is done from the Mac. Its key logs in as the unprivileged `mooring-view` account (§8.6), never as root.
- Everything else, `RevokeBootstrap` and `PutMacReport` included, is `ops`-only. The ops role may send every request except `Bootstrap`.
- `Request::authorize` checks the kind first (`RoleNotPermitted{role, request}`), then, for a `GateSet`, the reason with `Role::may_close_gate_for` (`GateReasonNotPermitted{role, reason}`). That rule is an exhaustive match over every role and every reason, so a new role or reason cannot compile without a decision, and a test proves it agrees with `permits`: a role may send `GateSet` exactly when it may close the gate for some reason. A typed subset of requests for the agent's viewer handler is an M4 addition, made when that handler exists.

**Frozen upgrade core.** `Hello`, `HaveBlobs`, `PutBlob`, `ActivateAgent` and `Confirm`, **and their success replies** (`Hello(HelloInfo)`, `Blobs{present}`, `BlobStored{sha256}`, `AwaitingConfirm{generation}`, `Confirmed{generation}`), never change across protocol versions: a newer Mac decoding with `deny_unknown_fields` must parse an older agent's replies. Through `HelloInfo` this also freezes the shapes of `HostFacts`, `Holds`, `Halt`, `SshdDirective` and `AcceptLocal`; a later protocol adds a request rather than changing them. Requests and replies have byte-exact wire goldens in `contract/agent-proto-golden/`, and a cross-version test runs against the previous release's agent binary, which is kept as a fixture (M4). The same directory pins the protocol-1 frames the console reads (`Status`, `UsageSeries`, `Events`) and, since revision 6, the Mac-report frames (`PutMacReport`, `MacReport`), request and reply, marked as not frozen; a test requires the directory to hold exactly the pinned frames. `AgentError` is not frozen: a Mac that meets an error variant it does not know reports a protocol mismatch.

**Requests:**
- **`Hello`** returns `HelloInfo`:
  - `protocol`, `agent_sha`, `host_profile_version`;
  - `host: HostFacts`: the uplink interface, `vps4` (the single IPv4 on the uplink, which the Mac compares with the address it dialled, proving VPS4 is on it), arch, `ip_local_port_range`, Debian major release, kernel, congestion control and qdisc;
  - `wgexit_accept_local`: `NoInterface | Disabled | Enabled`;
  - `sshd_mismatches`: the profile's sshd directives whose effective `sshd -T` value differs (empty when sshd enforces all of them);
  - the halt marker, if any, and the current holds;
  - `client_ip`, the Mac's IPv4 from `SSH_CONNECTION`.
- **`HaveBlobs{blobs}`** returns `Blobs{present}`, the stored and verified subset; an agent defect therefore leads to a re-upload rather than a skipped upload. **`PutBlob{sha256, len}`** returns `BlobStored{sha256}`.
- **`Bootstrap{expected_agent_sha, bootstrap_pubkey, ops_pubkey}`** (bootstrap role): returns `BootstrapDone{host_pubkey}`. `bootstrap_pubkey` (added in M4e; `Bootstrap` is not frozen) names the key that keeps a line restricted to the bootstrap role until `RevokeBootstrap`: sshd does not tell the agent which key logged in.
- **`RevokeBootstrap`** (ops role): returns `BootstrapRevoked`.
- **`Apply(BundleHeader{config_generation, digest, host_facts, host_profile_version, files, engines})`** returns `TxnLaunched{generation}`, or `Unchanged{generation}` (§11.2). `files` is `BundleFiles`, every `ManagedFile` mandatory; its JSON equals a `ManagedFile` → SHA-256 map. Then `TxnStatus{generation}` returns `TxnStatus{generation, state}`, `Confirm{generation}` returns `Confirmed{generation}`, and `Rollback` returns `Reverted{generation}`.
- **`ActivateAgent{sha}`** returns `AwaitingConfirm{generation}` (§11.2).
- **`Status`**, **`Usage{month}`**, **`TargetCheck{host, xray}`** return `StatusV1`, `UsageV1` and `TargetFacts` (§11.7). `xray` (added in M4e; `TargetCheck` is not frozen) names the stored Xray blob that runs `xray tls ping`: a node is checked before its first `Apply`, when no generation holds an Xray.
  - `StatusV1` also carries `accounting_at` (the latest accounting poll, `null` before the first), `last_active` (per accounting email, the latest poll at which its counters grew), `engines` (per engine unit: `NRestarts` and `Inactive | Active{uptime_secs, go_heap_bytes}`, where `go_heap_bytes` is Xray's Go runtime heap from `statssys`, not RSS, and `null` for Hysteria2), `host` (uptime, one-minute load in thousandths, available memory, free disk, journal size, reboot required, last unattended upgrade, chrony synchronised) and `transfer` (the uplink's bytes this UTC month from persisted deltas, the resets detected, and the time counting began).
- **`UsageSeries{from, to, resolution: FiveMin | Hour | Day}`** returns `UsageSeriesV1{range, bins}`: per bin, the bytes of every accounting email whose counters grew, and no other entry or bin. The range is whole bins of at most 144 five-minute, 168 hour or 35 day bins (`ValueError::RangeTooLarge` on construction and receipt). The model bounds no user count, so a reply is bounded by entries instead: at most 9,600, which with the longest emails and counters is at most `MAX_USAGE_SERIES_REPLY_BYTES` (1,034,713 bytes), a compile-time assertion below the 1 MiB frame. A full range fits for up to 27 users active in every bin; a range holding more entries is refused with `SeriesTooLarge{fitting_bins}`, and a range the agent does not hold completely with `SeriesNotRecorded{recorded}`, never answered with zeros.
- **`Events{since}`** returns `EventsV1{events, end}`: at most 4,096 journal events numbered `since` or later, each `{seq, at, kind}` (condition raised or cleared, gate opened or closed, hold recorded or cleared, halted, resumed, committed, engine restarted, host booted), and the number the next event will get. Events are paged by number because many can share a second. The journal is pruned only from its oldest end, so a page's numbers are consecutive and a gap inside one is refused (`ValueError::Events`); a first number above `since` shows pruned events, and an `end` below it a reset journal. A change in a raised condition's data is not an event; `Status` shows the current data.
- **`PutMacReport(MacReportV1)`** (ops only; revision 6) stores the Mac's report for remote viewers, replacing the previous one, and returns `MacReportStored{at}`, echoing the report's time. **`MacReport`** (ops and viewer) returns `MacReport(StoredMacReport{received_at, report})`, with the node's receipt time, or `MacReportMissing` when none is stored, never a default (§15.9). A report holds at most `MAX_REPORT_USERS` (1024) users and `MAX_REPORT_ALERTS` (256) alerts, so its encoding is at most `MAX_MAC_REPORT_BYTES` (178,954 bytes since revision 7, whose radio carries the data service type and separate LTE (four) and NR (three) readings; the band number is a `ReportBandNumber`, 1..=999, at most three digits), and compile-time assertions keep both the request and the reply inside their 1 MiB frames.
- **`GateSet{reason: MacDrain | EgressViolation | Operator}`** only closes the gate and records the hold; no request opens it. It returns `GateClosed{holds}`, and only once both are true: the ops role records the hold and closes the gate itself. The viewer role may send only `GateSet{Operator}` (roles, above), which the watch carries out (§11.3), so it is answered `GateClosed` only after the handler has read the Operator hold back and found the gate closed, and otherwise, after at most `VIEWER_STOP_WAIT_SECS` (15 s, three watch ticks), `GateStopUnconfirmed{waited_secs}`: a stop that was only queued is never reported as done. **`ClearHold{hold: EgressViolation | Operator}`** returns `HoldCleared{holds}`, whether or not the hold was present.
- **`Shutdown{reason: EgressIsNodeAddress | Operator | Retire}`** returns `Halted(Halt)`, and **`Resume{config_generation}`** returns `Resumed{generation}`. Each response answers exactly one request kind, and the Mac treats any other pairing as a protocol error.

**Paths never appear in requests.** `ManagedFile` is a closed enum: `XrayConfig`, `Hy2Config`, `WgConf`, `Nftables`, `WatchConfig` and, since revision 6, `ViewerKeys` (`/etc/mooring/current/viewer_authorized_keys`, which sshd reads for `mooring-view`, §8.6). The agent maps each variant to a fixed path (`/etc/mooring/current/…`; `wgexit.conf` and `nftables.conf` are reached through `/etc/wireguard/wgexit.conf` and `/etc/nftables.conf`). `BundleFiles` carries the new file's digest as `ViewerKeys`; `Apply` is not frozen, so its header may change.

**One definition of the VPS names.** `crates/agent-proto/src/vps.rs` defines `WG_INTERFACE` (`wgexit`), `NFT_TABLE` (`mooring`), `NFT_GATE_SET` (`exit_closed`), `NftCounter` (`xray_guard`, `hy2_guard`, `flow_cap`, and since M4d `probe_flows`), `EngineUser` (`mooring-xray`, `mooring-hy2`), `VIEWER_ACCOUNT` (`mooring-view`), `EXIT_ROUTE_TABLE` (77) and `EXIT_RULE_PRIORITY` (10000). The renderer writes them and the agent acts on them, so neither side can rename one alone.

**Blobs** are content-addressed in `/var/lib/mooring/blobs/<sha256>`, and each hash is verified on receipt (Level 1).

**Concurrency.** A second transaction while one runs gets `Busy{generation}` (flock on `/run/mooring/txn.lock`).

### 11.2 Transactions with commit-confirm

`Apply` returns `TxnLaunched{generation}` as soon as the work is launched. The work runs as `systemd-run --unit=mooring-txn-<gen> --collect agent txn <gen>`, so a dropped 5G link or SSH session cannot leave a half-applied state. `TxnStatus{generation}` reports `TxnState`: `Running{stage}` (`Preconditions`, `Stage`, `Validate`, `Swap`, `Apply`, `HealthGate`), `AwaitingConfirm`, `Committed`, `Reverted`, or `Failed{error: AgentError}`. A launched transaction that fails reports its `AgentError` inside `Failed`: a precondition or validation error (nothing was switched), `RolledBack`, `RollbackFailed` or `RevertedUnconfirmed`. There is therefore one error vocabulary, at the cost of allowing pairs the agent never produces (for example `Failed{RoleNotPermitted}`).

The header's host facts are the node's recorded site (uplink, VPS4, arch, port range) plus the unrecorded facts of the `Hello` just before the `Apply` (`VpsBundle::header`). The bundle carries no port plan, so the agent checks the plan's premise, the port range, instead.

1. **Preconditions:**
   - the node is not halted → otherwise `NodeHalted`;
   - the bundle's `host_profile_version` is at most the agent's own (`HostProfile::CURRENT`) → otherwise `HostProfileUnsupported{required, supported}` (M4e): activate the agent that carries the profile first;
   - the live host facts equal `BundleHeader.host_facts` → otherwise `HostFactsChanged{field}`, naming the first differing fact;
   - the live `ip_local_port_range` equals the range the port plan was checked against → otherwise `PortPlanConflict{recorded, live}`;
   - every blob is present and its hash matches.
2. **Stage** into `/etc/mooring/gen-<N>/` and `/opt/mooring/engines/store/<sha>/`, including the files of the host profile version (`gen-<N>/host/`, with the version, M4e).
3. **Validate.** Any failure → `StageValidation{tool, stderr_tail}` and nothing is switched.
   - `xray run -test -c` with `XRAY_LOCATION_ASSET` set to the **staged** geodata, run on a copy forced to `loglevel: warning`;
   - `mooring-hy2 check -c` on a copy forced to `level: warn`;
   - `nft -c -f`;
   - `wg-quick strip` (only its stderr is judged: its stdout is the configuration, private key included);
   - a check that every staged sysctl key exists under `/proc/sys`;
   - `sshd -t -f <wrapper>`, where the wrapper includes the staged drop-in and then `/etc/ssh/sshd_config` (sshd keeps the first value it reads, `AllowUsers` aside);
   - `systemd-analyze verify` on copies of the staged units in which `/etc/mooring/current` is the staged generation's directory: what `current` will be after the swap. As they are, the engine units name programs that do not exist before the first swap, and `verify` refuses them (seen on systemd 257 in a Debian 13 VM).

   **Zero WARN or ERROR lines** are allowed: any output line holding the word `warn`, `warning`, `error` or `fatal`, in any case, fails. `sshd -t` and `systemd-analyze verify` print nothing when they accept and their diagnostics carry no level word (`Unknown key name … ignoring` exits 0), so for them any output at all fails. The tail reaches the Mac with the bundle's secrets (the WireGuard keys; the engine configurations' `privateKey`, `id`, `password`, `shortIds` and `uuid` values) replaced.
4. **Swap** `/etc/mooring/current` → `gen-<N>` with one `rename`. A generation holds its engines and geodata as links into the engine store (`engines/xray`, `engines/mooring-hy2`, `geodata/geoip.dat`, `geodata/geosite.dat` → `/opt/mooring/engines/store/<sha>/<name>`), so the configuration, the engines and the geodata switch together. The fixed links point into `current` and never change: `/etc/nftables.conf` → `mooring/current/nftables.conf` (the first swap keeps Debian's own file as `/etc/nftables.conf.pre-mooring`), `/etc/wireguard/wgexit.conf` → `../mooring/current/wgexit.conf`, and `/opt/mooring/engines/geodata/current` (`XRAY_LOCATION_ASSET`) → `/etc/mooring/current/geodata`. Then install every host-profile file of the generation whose text differs from the installed one, and record its version (`/var/lib/mooring/host-profile.json`); a failure there is a `Swap` failure. Keep two previous generations and the store entries they use; the rest are removed before staging.
5. **Apply only what changed:**
   - `nft -f`, which leaves the gate closed until the watch reopens it;
   - `wg syncconf` (on a 0600 copy that `wg-quick strip` made, removed afterwards), or a restart if Address or MTU changed or the previous configuration cannot be read;
   - what the changed host-profile files need, in this order: `systemd-tmpfiles --create` (first, because the watch's unit needs `/run/mooring` to start: in the VM a watch started before it failed once with `EACCES`); `sysctl --system`; `daemon-reload`, the profile's units enabled, and the watch or the reflector restarted if its unit changed; journald restarted; an sshd reload. The kernel modules and the upgrade policy take effect when next read;
   - restart `mooring-xray` and `mooring-hy2` when their configuration, the engine set or their unit changed, and neither while the node is halted (a `Shutdown` that arrives mid-transaction included).
6. **Local health gate,** with a 20 s budget:
   - units are active;
   - `ss -Hltnu` shows the expected listeners;
   - `xray api statssys` responds;
   - `nft -j list set inet mooring exit_closed` succeeds;
   - the owner-guard rules are present: in `nft -j list chain inet mooring output`, a rule for each engine whose `meta skuid` match is the uid `/etc/passwd` gives its account, with its guard counter and a reject. nft lists a uid as the number unless it is given `-u` (`--guid`, nft(8)), so the check never looks for the account's name. *(Found 2026-10-25: the first real transaction on lon1 passed every earlier check and was rolled back with `HealthGate{OwnerGuard}`, because the check looked for the name.)*
   - `net.ipv4.conf.wgexit.accept_local = 1`.
7. **The confirm timer** (`systemd-run --unit=mooring-txn-revert-<gen> --on-active=120 agent txn-revert <gen>`) and the state `AwaitingConfirm`. The timer is armed once validation has passed, **before** the swap (2026-10-22, M4b), so that a transaction unit that dies between the swap and `AwaitingConfirm` is still reverted; the Mac's window is therefore 120 s less the apply and the health gate (at most about 25 s). The Mac opens a **new** SSH session and sends `Confirm{generation}`, answered `Confirmed{generation}`. That session proves reachability through the new nftables rules and sshd configuration. If the timer fires first, the agent reverts exactly as for a rollback → `RevertedUnconfirmed{generation}`. A transaction that fails after arming stops its timer, so a retry of the same generation can arm it again.
8. **If steps 4–6 fail:** swap back, re-apply what differed (the previous generation's host-profile files included, when it staged any) and re-check → `RolledBack{generation, cause}`. If that also fails, stop both engines and close the gate → `RollbackFailed{generation, cause}`. The cause is `Swap{errno} | Apply{step, stderr_tail} | HealthGate{failed}`; the failed stage follows from it, so an inconsistent stage/cause pair cannot be expressed. With no previous generation (the node's first), the rollback leaves the node serving nothing: both engines and the tunnel stopped while `current` still points at the generation, because the tunnel's stop (`wg-quick down`) reads `/etc/wireguard/wgexit.conf` through it, and `wg-quick down wgexit` run for a `wgexit` the stop left, with that configuration still in place (its `PreDown` hooks need it; a `down` that fails fails the rollback); then `current` removed, whatever the stops did; and `/etc/nftables.conf.pre-mooring` put back and loaded, so that a first ruleset that shut the operator out is undone too. The failed generation's directory is removed either way. *Found 2026-10-25:* lon1's second apply of its first generation was rolled back (step 6's owner-guard check, before its fix) with `current` already removed when the tunnel's unit stopped, so `wg-quick down` found no configuration and left `wgexit` up, while systemd reported the stop done and the unit failed; the third apply's `wg-quick up` was then refused (`wgexit' already exists`), which reached the Mac only as systemd's "control process exited with error code". The fourth apply's rollback deleted the left-over interface with `ip link delete`, which left the `PostUp` rule in the kernel, and the fifth `wg-quick up` was refused at that rule (§8.4). Hence the order above and the full `wg-quick down`; the agent's tests follow the interface through `up`, `down` and a `down` that could not read its configuration.
9. **An `Apply` whose digest equals the current generation's** returns `Unchanged{generation}` with the node's current generation. It restarts nothing, and **never changes holds or the halted state**. The bundle digest excludes the generation (§8.1), so a generation bump with no VPS-visible change is answered this way, and the Mac records it as an `Applied` bookkeeping entry at the new generation (§7).

**`Rollback`** reverts the pending change at once, exactly as the confirm timer would, and returns `Reverted{generation}`; with nothing pending it fails with `NotAwaitingConfirm`.

**One pending change, and what a dead transaction or a reboot leaves** (2026-10-22, M4b). `/var/lib/mooring/txn/pending.json` names the one change in flight and its phase: `Launched` (written by `Apply`), `Armed` (the transaction unit armed its timer) or `AwaitingConfirm`; while it exists every other change is `Busy`. Each transaction's record, `txn/gen-<N>.json`, holds its header and `TxnState` for `TxnStatus`. Every change takes `/run/mooring/txn.lock`, and a transaction unit holds it for its whole run, so a pending change found under the lock that does not await confirmation belongs to a unit that died (or was launched and has not started; it then finds nothing to run). `Rollback` and the timer revert such a change too: when `current` is already its generation, as a rollback; otherwise nothing was switched, and only its staged directory goes. Its timer is stopped first when its phase says one was armed. A reboot loses the transient timer, so `agent txn-recover`, run at boot by a oneshot unit ordered after `nftables.service`, the tunnel and both engines (installed with the other units in M4e), reverts whatever is pending → `RevertedUnconfirmed{generation}`.

**`ActivateAgent{sha}`:**
1. Install the stored blob as `/usr/local/lib/mooring/agent/<sha>` (0755) and run its `self-test`: parse its embedded host profile, open its state, print `PROTOCOL`. A failure, or any other output → `AgentSelfTestFailed`.
2. Arm the same 120 s revert timer, run by the **previous** agent, so that a new agent that cannot serve cannot block its own revert.
3. Record the pending activation, swap the forced-command link `agent/current` → `<sha>`, and reply `AwaitingConfirm{generation}`. Activation changes no configuration, so `generation` is the node's current one: `Generation::ZERO` before the first `Apply`. `ConfigGeneration` starts at 1 (§7), so every real `Apply` generation is newer.
4. The Mac's `Confirm{generation}` must be served by the new agent. A revert points the link back at the previous agent. Because the previous agent performs that revert, it must read the `pending.json` the new agent wrote: the pending record's format changes only in ways the previous release reads, which M4f's cross-version test checks. A node whose forced command has no target cannot have received the request, so an activation that finds none fails with `Io{ReadState}` before changing anything.

**Agent upgrades go to one canary node first.**

**After commit, the Mac verifies.** `mooringctl node apply` waits up to 90 s over the control socket (`WaitVerdicts`) and reports `AppliedVerified` or `AppliedUnverified{verdicts}`. There is no automatic rollback on probe failure, because the M7 may be at fault.

### 11.3 Gate, holds and halt (single owner)

**Single owner.** `mooring-watch` is the **only** process that removes `wgexit` from `exit_closed`, which is what opens the gate. The agent (handling `GateSet`, `Shutdown` and transactions) and `ExecStopPost` may only add it, the safe direction.

**Locking.** Holds and set changes are serialised by `/run/mooring/gate.lock`. The watch reads the holds and writes the set under that lock, and the agent writes a hold and closes the gate under the same lock. A stale watch decision therefore cannot reopen a gate that was just closed.

**Holds.** They live in `/var/lib/mooring/gate/holds.json`, written atomically and group-readable by `mooring`, so they survive restarts and reboots.

| Hold | Clears when |
|---|---|
| `MacDrain{handshake_at_drain}` | The handshake value changes and rx grows |
| `EgressViolation{at, generation}` | `ClearHold{EgressViolation}` arrives (the Mac's Retry) |
| `Operator{at}` | `ClearHold{Operator}` arrives |

**The viewer's emergency stop** (decision F5; plan, M4). A viewer's `GateSet{Operator}` is handled by the agent running as the unprivileged `mooring-view`, which cannot write `holds.json` or the nft set. It hands the request to the watch through a narrow request file under `gate.lock`, and the watch records the Operator hold and closes the gate. Only the ops role clears the hold, so resuming is done from the Mac.
- **The reply is the watch's result, never the hand-off.** After writing the request, the handler re-reads `holds.json` and the gate's state until it finds an Operator hold recorded at or after the request's time and `wgexit` in `exit_closed`, and only then answers `GateClosed{holds}`. If that has not happened within `VIEWER_STOP_WAIT_SECS` (15 s, three `WATCH_TICK_SECS` ticks), it answers `GateStopUnconfirmed{waited_secs}` and leaves the request in place for the watch. The phone then shows that the stop is not confirmed, so the operator knows the node may still be serving (a hung watch that is still running, so `ExecStopPost` has not closed the gate, or a watch between restarts) and stops it another way: from the Mac (`GateSet` or `Shutdown` with the ops key) or the provider's console. A stop that was only queued is never answered as success.

**Halt.** `Shutdown{reason}` works in this order:
1. It writes `/var/lib/mooring/halted.json` atomically, without taking `txn.lock`.
2. It closes the gate.
3. It stops both engines.

The engine units' `ExecCondition=agent halted-check` then prevents any restart: by systemd, by a reboot, or by a running transaction's rollback. Transactions check the marker before restarting anything. `Apply` returns `NodeHalted`, and only an explicit `Resume{config_generation}` clears the marker. The runbook requires investigating the cause first. `Resume` takes `txn.lock` like a change (`Busy` while one is pending), fails with `NotHalted` on a node that is not halted and with `GenerationMismatch{current}` unless `config_generation` is the node's current generation, so the Mac resumes only the configuration it believes is there. It then removes the marker, starts both engines (`Systemd{unit, Start}` if one does not start) and runs the health gate (`HealthGate{failed}`); the gate stays closed until the watch reopens it.

**Watch loop (every 5 s):**
1. Read the latest handshake, rx and tx from `wg show wgexit dump`.
2. **The gate opens** only if all of these hold:
   - the handshake is at most 180 s old;
   - rx grew within 3 × keepalive;
   - there are no holds;
   - the node is not halted.

   Otherwise the gate stays closed. Set membership is re-read with `nft -j` every 60 s.
3. Any failure to read WireGuard state closes the gate and records `WgReadFailed`. An `nft` failure is fatal; the unit restarts, without limit, and `ExecStopPost` closes the gate.
4. Every 60 s, accounting runs (§11.5). Every hour, the target check runs: `xray tls ping`, the h2 check, and re-resolving the target name. A failure, or an IP change, records `TargetDegraded`. *Built 2026-10-23 (M4e):* the hourly check is a unit of its own (`mooring-target-check.service` and its timer, as `mooring-watch`, §11.7), because `xray tls ping` sets no time limit and a target that does not answer must not hold up the 5 s loop; the watch reads its latest result at every tick and raises `TargetDegraded` while it is a failure about the configured target.
5. Write `/var/lib/mooring/status.json` atomically, with a timestamp the Mac uses for `WatchStale`.
6. *(Revision 5; built in M4.)* Evaluate the liveness and host-health conditions of §14, and append every transition to the event journal that `Events{since}` serves (§11.1). The thresholds are the console spec's and stay *(inference)* until M4/M8:
   - `MacSilent` once the handshake is older than `MAC_SILENT_SECS` (600 s) and no Operator hold is set. An Operator hold therefore suppresses it, and the alert rules warn when such a hold has lasted more than 24 h (§15.8; critique D-4);
   - `DiskLow` under `DISK_LOW_FREE_BYTES` (1 GiB) or `DISK_LOW_FREE_PERCENT` (10 %);
   - `ClockUnsynced` and `RebootPending`.

   The uplink transfer counters reset at the nightly 20:00 UTC unattended-upgrades reboot (§5.2), so `StatusV1.transfer` is kept as persisted deltas with reset detection. DigitalOcean also pools transfer per team (critique D-8).

**Built 2026-10-22 (M4c): how the watch does it.**
- **Before the first `Apply`** (no `/etc/mooring/current`) there is no ruleset of Mooring's and no `wgexit`: the watch runs neither `wg` nor `nft`, reports the gate closed and raises only host conditions. Otherwise it reads `watch.json` from the current generation at every tick.
- **The rx rule** uses the watch's own readings: rx has grown when a reading exceeds the one before, so after a watch restart the gate stays closed until rx grows again (at most one keepalive); a reading below the one before is a counter that restarted with the interface.
- **Under `gate.lock`, in this order:** a viewer's stop request becomes an Operator hold recorded at the tick's time, and the request is removed; until the hold is written the gate stays closed, and a request whose hold is already recorded is only removed. A `MacDrain` hold clears once the handshake differs from `handshake_at_drain` and rx has grown since the watch first saw the hold. Then the gate is set: open only with a generation installed, a live peer, no stop pending, no hold and no halt.
- **The set** is changed from the state the watch last read or set, and re-read, with the `flow_cap` counter, every `GATE_SET_REREAD_SECS`. A ruleset load that closes the gate behind the watch (a transaction's `nft -f`) therefore keeps it closed until the next re-read, at most 60 s, which is the safe direction; `StatusV1.gate` is defined as the gate as the watch last set or read it.
- **The host** is read every 60 s: `/proc/uptime`, `/proc/loadavg`, `MemAvailable` from `/proc/meminfo`, `stat -f` on `/var/lib/mooring` (available and total bytes), the bytes of the files under `/var/log/journal` (none without a persistent journal), `/run/reboot-required` and its time, the time of `/var/log/unattended-upgrades/unattended-upgrades-dpkg.log` (written only when unattended-upgrades installs), and `chronyc -n tracking`, whose leap status `Normal`, `Insert second` or `Delete second` is synchronised; a chrony that does not answer does not report the clock synchronised, so `ClockUnsynced` is raised.
- **Conditions built in M4c:** `WgReadFailed`, `NftFailed`, `ExitFlowCapHit{count}` (the counter's packets, while above zero; the Mac's alert is on its growth), `StateWrite{errno}`, `MacSilent` (kept as it was while WireGuard cannot be read, and suppressed by an Operator hold either way), `DiskLow`, `ClockUnsynced` and `RebootPending{since}`. `StatsQueryFailed` and `AccountingCanaryMissing` come with accounting (M4d), `TargetDegraded` with the target check (M4e).
- **What ends the watch:** an `nft` failure (recorded as `NftFailed` in its view and journal first) and any reading it needs but cannot take: the current generation, its `watch.json` and its record, the holds, the halt marker, the stop request, `/proc` and the host's other figures. These fail only on a broken or misdeployed host, and the restart loop with the gate closed by `ExecStopPost` is the safe response; the Mac sees `WatchStale`. A state write or journal append that fails is `StateWrite`, retried at the next tick, and never affects the gate.
- **The view** is `/var/lib/mooring/watch/status.json` (0640), written atomically at every tick: what the tick observed (boot id, generation, gate, holds, halt, the newest generation seen committed, conditions), the handshake, the latest host reading, and the observation the journal last recorded. The agent's `Status` (M4d) and the viewer's stop read it: a viewer's `GateSet{Operator}` is confirmed once the hold is recorded at or after the request and a view from a tick at or after it shows the gate closed, so the viewer never runs `nft`.

### 11.4 Reflector (`mooring-reflect`)

- A standard-library TCP listener on `<VPS4>:27900`.
- On accept, it writes the peer's IPv4 followed by `\n`, then closes the connection.
- At most 16 concurrent connections, a 2 s write timeout, no state, and no logging of addresses.
- nft limits new connections to 5 per second per source (burst 10).

The reflector answers every source on purpose (§1.3). The visible IP-echo service is a small fingerprint, revisited with M8 data.

### 11.5 Accounting

- Run `xray api statsquery` against `127.0.0.1:10085` with pattern `user>>>` and no reset (exact flags are verified in M4), plus `statssys` for uptime.
- Deltas are monotonic, and an Xray restart is detected when uptime decreases.
- Bytes are recorded per opaque email (`<uid>@reality`, `<uid>@hy2`; the probe's `probe@…` separately) into `/var/lib/mooring/usage/<YYYY-MM>.json`, written atomically. Xray keys the counters `user>>>EMAIL>>>traffic>>>uplink|downlink` and keeps the email's case, so agent-proto's `StatsEmail`, which the renderer also uses to write the emails, is case-sensitive.
- No destinations and no IPs are stored. Up to one poll interval can be lost on a crash.
- The same polls feed the time series that `UsageSeries` serves (five-minute, hour and day bins of non-zero growth) and `StatusV1.last_active`. The agent keeps each bin for 48 hours after it ends (F7, decided 2026-10-15 by delegation, §20.2); the Mac pulls every poll, so it holds them long before. Whatever the agent keeps, it refuses a range it does not hold completely (`SeriesNotRecorded`) rather than report missing bins as zero. Xray adds spliced REALITY downloads to a counter only when the connection closes, so bins and `last_active` lag long downloads.
- The Mac merges usage from all nodes next to the SIM meter.
- **Quotas** are records, not revocations (revision 5). `UserPolicy` (§7) holds a quota and an expiry.
  - A user over quota or past expiry is moved to `Suspended{QuotaExceeded | Expired}`. Suspension keeps the credentials, so a later resume delivers nothing new into China.
  - The move is an explicit action, by the operator or by the daemon's apply job (M5). Automatic quotas were decided on 2026-10-08 (F4): from 6 users sharing the cycle's budget, a user's own quota overriding the automatic one. The users sharing it are those active now and those suspended for quota in the current cycle, so the quota is latched per cycle (decided 2026-10-09): a suspension for quota never switches it off or changes anyone's share within the cycle. Any other departure, a suspension for another reason or a revocation, still lowers the count (§15.3). A suspension for quota made before the current cycle's start no longer counts, and the apply job resumes it, within the cap, at the first apply of the new cycle (§13.6). Under the cap of 5 the automatic quota stays dormant unless users suspended for quota this cycle bring the count to six (§15.3).
  - Revision 4 enforced quotas by revocation. That forced new credentials into China and broke the user's history.

**Accuracy** (Xray v26.9.30 `b26a91de`, re-read 2026-10-08):
- **Vision splice.** REALITY+Vision TCP flows to `freedom` switch to splice copy: the VLESS XRV branch sets `CanSpliceCopy = 2` (`proxy/vless/inbound/inbound.go:554-556`), and freedom sets 1 (`proxy/freedom/freedom.go:260`).
  - Splice runs only on linux and android (`proxy/proxy.go:737-739`), which includes the VPS.
  - Spliced downlink bytes are added to the user counter only when `tc.ReadFrom` returns, that is when the connection closes (`proxy/proxy.go:761-783`). The uplink is never spliced (`:273-275`, a commented-out TODO).
  - A long REALITY download therefore shows no growth until it closes, and an Xray crash loses the in-flight spliced bytes.
  - Hysteria2 handoff flows have an empty flow (§8.2) and never splice (`inbound.go:591-592`). Their counts are current.
  - What this does to the console is in §15.4.
- **Counters are registered at first dispatch.** A user's counters appear when its first connection is dispatched (`app/dispatcher/default.go:161-180`). A missing counter means no connection since Xray started, and reads as zero.
- **`statsUserOnline` would not help even if enabled.** Its online map drops 127.0.0.1 and `[::1]` (`app/stats/online_map.go:9-12,35-38`), so it could never see a Hysteria2 user, who arrives over loopback. "Active" is derived from counter deltas instead (`StatusV1.last_active`), and no IPs are kept (§8.2).
- **`statssys`** reports uptime and the Go runtime's `Alloc` and `Sys`, not process RSS (`app/stats/command/command.go:186-206`).
- **Accounting canary (critique C-11).** Reading an absent counter as zero would hide a stats policy rendered off or mismatched emails, and quotas would then never fire. After a successful in-chain probe, `probe@reality` and `probe@hy2` must exist and grow; otherwise the watch raises `AccountingCanaryMissing{inbounds}` (§14), one condition naming every inbound whose canary is missing, since a stats policy rendered off misses both at once.
  - The VPS cannot see by itself that an in-chain probe succeeded. Two ways to give it that evidence were open, an nft counter of probe flows or the in-chain probe interval in `watch.json`; M4d settled on the counter (below).
- M10's per-user source addresses on `wgexit` would give exact live per-user counts from kernel counters, which would remove the splice lag *(inference)*.

**Retention (revision 5; F7 decided in revision 8).** `usage/<YYYY-MM>.json` and the bins on the VPS have no deletion rule yet; M4 builds it, and M5 builds the Mac's, before M8, because the user agreement states them (F9). Per-user records are pseudonymous personal data: the Mac's labels re-identify the opaque ids (UK GDPR recital 26). How long each host keeps them is decision F7, decided on 2026-10-15 by delegation as its recommended default: the agent deletes each bin 48 hours after it ends, and a monthly `usage/<YYYY-MM>.json` 7 days after its month ends, so a node holds the current month and, for a week, the previous one; the history stays on the Mac (critique C-12) for the periods in §20.2. The agent also drops an accounting email's `last_active` once the email leaves its applied configuration (a suspended or revoked user). The rule is time-based, so no protocol request is needed and nothing the Mac does or fails to do can extend a node's retention.

**Gaps (M5).** A Mac that misses its pulls for longer than 48 hours (a power cut, a FileVault restart nobody logs in after) gets `SeriesNotRecorded{recorded}` for the missed range, and its ledger would refuse the gap for good (`UsageError::LedgerGap`, `crates/daemon-core/src/usage.rs`). M5 fills the gap instead: it reads `Usage{month}` for each month the gap touches, records per email the bytes those monthly totals hold beyond the bins on either side of the gap as a gap entry of that month, journals the gap, and continues. `usage.rs` has no such entry yet, and a new `LedgerStart::Continued` base cannot be it: a base counts only toward the lifetime (`Totals::base`), and `aggregate` refuses every period that starts before it (`PeriodBeforeLedger`). The month and lifetime figures stay exact, and so do the cycle's and the quotas while the gap lies within one billing cycle; a gap across a cycle's start (the bill day, §7, against calendar-month files) leaves the split of its bytes between the two cycles unknown, which the console and `policy::evaluate` report rather than guess. The gap's day, hour and five-minute split is lost, and the console marks it. A gap that also outlives the monthly file (the rest of the month plus 7 days) loses that month's split by user, which the console reports for the node and never shows as zero. The user agreement states these limits (`docs/runbooks/user-agreement.md`, clause 4).

**Built 2026-10-23 (M4d): how accounting does it.**
- **The polls.** At each reading (every `ACCOUNTING_INTERVAL_SECS`, with the host), with a generation installed and `mooring-xray` active, the watch runs the current generation's `engines/xray api statssys --server=127.0.0.1:10085`, reads the `probe_flows` counter, runs `statsquery` with `-pattern=user>>>` and no `-reset`, then `statssys` again. What the pinned source prints (checked on 2026-10-23 in `main/commands/all/api` and `common/reflect/marshal.go`): indented JSON from a reflection walker that leaves out every zero or empty field, numbers as JSON numbers, `{}` when nothing matches, counters in no order, a failure on stderr with exit status 1, and `Uptime` in whole seconds since the stats service started. A reply that is not exactly that, an email with only one of its two counters (the rendered policy counts both, and Xray registers them together), or any failure of the API is `StatsQueryFailed`. A stopped Xray (halted, or between restarts) is not asked and raises nothing.
- **Runs.** A run of Xray is the boot id and the second since boot at which its stats service started (`/proc/uptime` minus `Uptime`, within 2 s), which no clock step moves. A poll adds each counter's growth since the poll before in the same run; after a restart, all a counter holds; a counter below its reading in the same run counts from zero. A second `statssys` reporting a shorter uptime than the first means Xray restarted during the poll, which is taken again at the next reading. The node's first poll ever is only a baseline, and what was counted between a crash's last poll and the crash is lost (at most one interval).
- **Files.** `usage/accounting.json` (0640) holds the latest poll (its number, time, run, counters, probe-flow count and what it added) and the series. It is written before the month's file `usage/<YYYY-MM>.json` (0640: the month's `UsageV1` and the latest poll it took in), and a poll that a crash kept out of its month's file is added at the next poll, so every poll counts in its month exactly once. A poll counts in the month of its last second. A month's file exists from the watch's first poll in that month, so `Usage{month}` answers zeros for a month without traffic, and `NoUsageRecorded` for a month the agent never polled in or whose retention has ended.
- **The series.** A poll adds what it counted to the five-minute, hour and day bins holding its last second. A bin is held only inside one stretch of consecutive polls: from the stretch's first poll, which is only a baseline, to its latest. Consecutive means a gap of at most three intervals from the very poll the series took last, by number, so a poll the series cannot take (at or before the latest it took, after the clock stepped back) also ends the stretch; the growth across a gap goes to the month only. `UsageSeries` answers only a range whose every bin is held. Otherwise `SeriesNotRecorded{recorded}` names the bins of the most recent stretch that holds any at the requested resolution, which may lie outside the request. `SeriesTooLarge{fitting_bins}` counts bins from the range's start, empty ones included.
- **Retention.** At every reading, whatever Xray's state (a halted node keeps deleting): the month files 7 days after their month ends, the bins 48 hours after they end, the stretches no kept bin can lie in, and any temporary file a crash left in `usage/`. Reads apply the same limits, and expiry is judged at the later of now and the latest pruning, so a pruned bin is never served as one without traffic after the clock stepped back. A watch that is not running deletes nothing until it runs again.
- **`last_active`** lives in the watch's view: the latest poll at which an email grew, counted only for polls that continued a stretch (growth across a gap is not dated), and only for the emails in `watch.json`'s `emails`. That new field holds the accounting emails `xray.json` gives its clients, rendered from the same `StatsEmail`s (a render invariant compares the two), so the watch never reads `xray.json` and its secrets. An email leaves `last_active` at the first reading after the applied configuration drops it.
- **The canary's evidence.** `exit_flow` counts new flows to `$VPS4`'s reflector port in the named counter `probe_flows` (§8.5), before the flow cap and with no verdict. Only the probe identity may route to a node address (§8.2), so its growth means Xray dispatched an in-chain probe, and dispatching registers the probe email's counters. `AccountingCanaryMissing` is raised when, between two polls of one run, the counter grew and no `probe@…` counter exists (the counter is read before `statsquery`, so a counter that flow registered is visible). It clears at the first poll where a probe counter exists, and stays as it was without new evidence. The counter does not say which inbound a probe came through, so the condition names every inbound; one inbound whose probes never reach Xray is the Mac's to judge, from its own probe results and `last_active`. The other option, the probe interval in `watch.json`, could not tell a stats policy that is off from a probe process that is not running.
- **Engines and the uplink.** `systemctl show -p ActiveState,NRestarts,ActiveEnterTimestampMonotonic` per engine unit (systemd 257 on the London VPS, 2026-10-23: the properties in its own order, the timestamp in microseconds since boot, 0 for a unit never active, exit status 0 even for a unit not installed). Uptime is `/proc/uptime` minus the activation, and Xray's Go heap is `statssys` `Alloc` from the same reading (`None` while the API fails). `EngineRestarted{engine}` is journaled when `NRestarts` grows; an explicit restart sets it back to zero. The uplink is the interface of the default route, and its `/sys/class/net/<if>/statistics/{rx,tx}_bytes` are counted as deltas in the view: a reading in another boot, on another interface, or below the last reading is a reset that counts from zero, and a month counts from its first reading.
- **`Status`** is the view (`watch_at`, gate, conditions, handshake, `accounting_at`, `last_active`, engines, host, transfer) with the holds read under `gate.lock`, the halt marker, and `applied`: the newest kept generation whose record is `Committed`, with its digest. Before the watch's first tick it is the OS's error for the missing view (`Io{ReadState, ENOENT}`), never a made-up status.

### 11.6 Host-profile convergence

Host-profile changes travel in ordinary transactions: they are staged, validated (`sshd -t`, `systemd-analyze verify`, sysctl keys), applied and confirmed. Changes to sshd or nftables are therefore protected by commit-confirm. L5 upgrades a node adopted at profile N to N+1.

*Built 2026-10-23 (M4e)* as §11.2 steps 1–5 and 8 describe: a generation stages the whole profile, so a transaction also repairs a local change to any of its files ("Local changes are overwritten"), and a rollback puts back the previous generation's files. Accounts and directories a later profile adds will be converged by its transactions; profile 2's are `Bootstrap`'s (§8.6).

### 11.7 REALITY target selection

**Where policy runs.** The agent's `TargetCheck{host, xray}` returns raw `TargetFacts` (`crates/agent-proto/src/target.rs`). `render::target_facts` converts the report into the model's `TargetFacts` (`crates/model/src/target.rs`), refusing a report about any host other than the one requested (`TargetFactsForOtherHost`). Every wire outcome has a model counterpart, so nothing is invented to fill a value the agent did not measure. `mooring-model::target::qualify(facts, attestation)`, on the Mac, then evaluates the rules and reports every failed rule, not just the first. Failures are listed in a fixed order: the TLS rules, the HTTP rules, the deny list, the resolved address, then the attestation (`crates/model/src/target.rs`, `qualify`).

**Discovery.** The operator runs the pinned RealiTLScanner from the Mac, never from the VPS. The scan is limited to the VPS's /24 and its neighbours, at a low rate.

*Built 2026-10-23:* the engine build carries it as `darwin-arm64/realitlscanner` (§4). It dials by the Mac's default route, so it runs with Wi-Fi off and leaves over the M7, as every contact with the node does: `realitlscanner -addr <a.b.c.0>/24 -thread 2 -timeout 5 -out <file>`, two handshakes at a time, each given up after 5 s. A row is an address that completed TLS 1.3 with h2, with the name on its certificate; the file stays in the operator's local notes (`ops-local/`), since it maps the node's neighbourhood. A name that resolves to exactly that address, on the node's network and not a CDN's, then goes to `node target check`. For lon1 none of the provider's own names qualified (each answers HTTP/1.1 only, redirects `/`, or resolves to two addresses), which is why the scan comes first.

**`TargetCheck` on the VPS collects:**
- the resolved IPv4s (possibly none);
- the TLS outcome against port 443, `TlsProbe`: `ConnectFailed`, `HandshakeFailed`, or `Completed(TlsSession{version, group, chain_bytes, chain_certs, leaf_names, handshake_p95_micros, first_flight_bytes})`. `xray tls ping <host>` supplies the version, the negotiated group (recorded as its IANA code point; none for TLS 1.2 RSA key transport), the chain's length and certificate count, and the leaf's DNS names (Xray v26.9.30 `main/commands/all/tls/ping.go:125-170`). It measures neither latency nor the first flight, and it exits on a failed dial, so the p95 handshake latency over 20 handshakes (`TARGET_HANDSHAKE_SAMPLES`) and the first-flight size are measured separately by the agent's handshake sampler (`TargetTool::HandshakeSampler`, M4);
- `curl --http2 -sS -o /dev/null -w '%{http_code} %{http_version} %{redirect_url}' https://<host>/`, as `HttpProbe`: `Failed` (status `000`) or `Responded{status, version, redirect}`.

A collector that cannot run fails the request with `TargetFactsUnavailable{tool: Resolver | XrayTlsPing | Curl | HandshakeSampler, stderr_tail}`.

**Built 2026-10-23 (M4e part 2): how the agent measures** (`crates/mooring-agent/src/target`).
- **One address.** The name is resolved once, with `getent ahostsv4`, and every probe goes to the same IPv4 (the first of the set): `xray tls ping -ip <address> <host>` (left to itself, Xray resolves the name again and may pick an IPv6 address the node cannot reach), `curl --resolve <host>:443:<address>` and the sampler. A name `getent` cannot resolve (exit status 2, which glibc's `getent` gives for every resolver failure, a resolver that does not answer included) is reported as resolving to nothing, with `ConnectFailed` and `Failed` and nothing probed.
- **Bounded.** Every tool runs under `timeout --kill-after=2 10`; a resolver or an Xray that runs out of time is `TargetFactsUnavailable`, a curl that does is `HttpProbe::Failed`.
- **The Xray** of the request is the stored blob, installed in the engine store (0755) as staging installs it; the next transaction's pruning removes it if no kept generation uses it.
- **`xray tls ping`'s output** is read as the pinned source prints it (v26.9.30 `main/commands/all/tls/ping.go`, read 2026-10-23): only the part with SNI; `Failed to dial tcp` with exit status 1 is `ConnectFailed`, `Handshake failure:` is `HandshakeFailed`; the group is the name Go's `CurveID.String` prints (`X25519`, `CurveP256`, `X25519MLKEM768`, …, or `CurveID(<n>)`), and `RSA Exchange` is no group. Anything else is `TargetFactsUnavailable{XrayTlsPing}`.
- **The handshake sampler** is Rust with no TLS stack: it sends a ClientHello of its own (TLS 1.3 and 1.2, X25519 key share from `/dev/urandom`, the name as SNI, ALPN `h2` and `http/1.1`, no certificate compression), never finishes the handshake, and times from the hello's last byte to the last byte of the server's first flight, which ends when the server is quiet for 300 ms; the flight's size counts every byte, record headers included. An alert, a HelloRetryRequest, silence for 3 s or anything but a ServerHello is `TargetFactsUnavailable{HandshakeSampler}`. The p95 is the nearest rank over 20 handshakes, the flight the largest seen. Without certificate compression a target is measured at its larger size, so the measure errs on the side of refusing it. On 2026-10-23 four public servers (from this Mac, campus network) answered its hello with first flights of 2.8 to 5.5 KB.
- **The hourly check** (`agent target-watch`, `mooring-target-check.service`, every hour from five minutes after boot) resolves the configured target, and finds it degraded when the configured address is not among the results, when the TLS handshake through the current generation's Xray does not complete, or when it does not answer over HTTP/2. It writes `/var/lib/mooring/watch/target.json` (0640: the time, the target it checked, and the verdict); the watch takes a result only about the target its `watch.json` names.

**Rules evaluated in Rust** (`qualify`), each a `TargetRejection`:
- the target accepts a TCP connection on port 443 and completes the TLS handshake: the wire TLS outcome replaces revision 3's "listens on 443" rule, because the agent always probes port 443 and reports no port (`TlsConnectFailed`, `TlsHandshakeFailed`);
- TLS 1.3 and h2 (`NotTls13`; `HttpFailed`, `NotHttp2`);
- no 3xx on `/` (`Redirect`);
- every `serverName` is on the certificate: in v1 the host is the only `serverName`, and it must equal a leaf name exactly, ignoring ASCII case, because REALITY matches server names exactly with no wildcards (`HostNotOnCertificate`);
- the negotiated group is X25519 or X25519MLKEM768 (`UnsupportedKeyExchange`), since a REALITY server cannot complete any other group with a classical or hybrid X25519 client share *(inference from REALITY `e1986a4` `tls.go:215-235`)*. The group is stored with the target (`TargetKeyExchange`), so the operator knows whether hybrid clients get a post-quantum outer session (§4.2);
- the first flight is at most 16 KiB (`FirstFlightTooLarge`; `e1986a4` includes the #33 17 KiB buffer);
- p95 handshake is at most 5 ms (`HandshakeTooSlow`);
- the host resolves to exactly one public IPv4 (`NoAddress`, `AmbiguousAddress`, `NonPublicAddress`), which becomes `TargetSpec.ipv4`;
- the name is not on the compiled-in list (`DeniedName`): any name containing `apple`, `icloud` or `microsoft` or under `.cn`, `.ir` or `.ru`, which Xray v26.9.30 warns about as a REALITY server name (`infra/conf/transport_security.go:163-169`) and which would therefore break the zero-WARN gate, plus 27 widely shared target and CDN domains and their subdomains (`SHARED_TARGET_DOMAINS`);
- the attestation is positive (`SameAsnNotAttested`, `CdnNotExcluded`).

A stored `TargetSpec` re-checks the attestation when decoded, but not the deny list, so a stored target still loads after the list grows.

**Operator attestations.** "Same ASN" and "not a CDN" need data the system does not ship. They are recorded as an explicit `TargetAttestation{same_asn, not_cdn, evidence_url, at}`.

**No automatic fallback.** If no neighbour qualifies, the operator picks another provider or location.

**Changing the target means reissuing user files,** because the SNI is part of each client config.

---

## 12. Secrets and security calibration

| Item | Level | Threat it answers | Where it lives |
|---|---|---|---|
| User VLESS UUID, Hysteria2 password, loopback UUID (per user, per node) | 2 | Unauthorised use of the exit | Data-protection Keychain; VPS configs (0640 root:service); that user's export file until it is imported and deleted (§9.4), then CFM's Keychain vault |
| REALITY private key, salamander password, Hysteria2 key (per node) | 2 | Server impersonation; probe classification | Keychain; VPS configs |
| WireGuard keys (one VPS and one Mac key per node) | 2 | Tunnel impersonation | Keychain; `wgexit.conf` 0600; the Mac key reaches the engine only on stdin |
| SSH operations key | 2 | VPS takeover | `~/Library/Application Support/Mooring/ssh/<node>/ops_ed25519` (0600, excluded from Time Machine); VPS `authorized_keys` with `restrict,command=` |
| SSH bootstrap key and injected host key | 2, short-lived | Spoofing of the first contact | User-data file until adoption. The host key is replaced on the VPS at Bootstrap. |
| Engine and blob sha256 | 1 | Accidental corruption or the wrong artifact | `engines.lock.toml`, `MANIFEST.json` |
| Mac exit deny list | 2 (a security boundary) | A VPS or user reaching the M7 admin page, LAN, CGNAT range or loopback | Mac engine rules (authoritative), Xray rules and the owner guard (defence in depth) |
| VPS owner guard | 2 | User traffic leaving from the VPS IP; reaching VPS-local services | nftables |
| Accounting and status | 0 | — | Plain files |
| M7 admin password (`SecretRef::RouterAdmin`, account `router/admin`; M2a showed a login is needed, §7) | 2: it controls offload, APN, port forwarding and Wi-Fi | Someone turning on offload or a Wi-Fi radio, or forwarding ports, on the exit's router | Until M5, the legacy login keychain (service `com.bill.mooring.dev`, label "Mooring (development)", written by the unsigned development build's `mooringctl router set-password`, which finds an existing item by service and account only, so one made or renamed another way is replaced, not reported missing); M5 moves it to the data-protection keychain. No deployment references it, so the store's secret plans never write or delete it. Sent only in the M7 login `POST` body over the Mac's wired link, after the identity check (§15.6). Never in a URL, an argv, a log or a fixture |
| The deployment's one ntfy topic (`SecretRef::AlertTopic`, account `alert/topic`: `Password` material, 32 random bytes as 43 base64url characters, so 256 bits against F6's 128) and each channel node's two Healthchecks check UUIDs (`NodeDeadManCheck`, `NodeMacAliveCheck`: `Uuid` material) (F6) | 1: a leaked topic lets someone read Level-0 alert text and post spam or forged notices; a leaked check UUID lets someone ping the check and hide an outage. Every channel node and the operator's phone hold the topic, so a compromised node or a lost phone leaks it for the whole deployment, and retiring the node or removing the phone's viewer key does not revoke it. Replacing it takes two configuration changes, because the store replaces no secret the state still references (§7): removing every node's channels, after whose commit the topic and the check items are deleted, then setting them up again with a new topic and the same check UUIDs. Every channel node then needs `node apply`, and the phone one new subscription. M5's `alert rotate-topic` does this (§15.3), after a node that may be compromised is retired (§13.4) and after a phone is lost (§15.9) | — | Keychain; on each channel node, the alert unit's credentials file via `LoadCredential=` (M4, §15.8) |
| Viewer key (F5) | 2 | A stolen phone reading Level-0 status and closing a gate | Private half generated on the phone and never written on the Mac; public half in `viewer_authorized_keys` on each node, 0644 `root:root` (a public key, readable by `mooring-view`, writable only by root) and read by sshd as the unprivileged `mooring-view` (§8.6, §15.9) |

**Keychain.**
- `kSecUseDataProtectionKeychain`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrSynchronizable=false`, access group `<TEAM>.com.bill.mooring.secrets`. These are the same attributes as CFM's `CredentialVaultStorage.swift:133-150`.
- Only the bundled `mooringctl` holds the entitlement. Development lanes use the in-memory `SecretStore`.
- Revision 7's development build, signed only ad hoc (§15.6 rule 10), keeps one item, the M7's admin password, in the legacy login keychain (`LoginKeychain` in `mooringctl`). Its access list names the binary that wrote it, so macOS asks the user to allow access after each rebuild; only the user can answer. M5 reads it there, writes it to the data-protection keychain and deletes it.
- Optional M5 spike: a non-exportable Secure Enclave SSH key via `sc_auth` and `ssh-keychain.dylib`. Adopt it only if a LaunchAgent can use it unattended.

**Backups (revision 8).** The retention periods the agreement states (§11.5, §15.7) hold only if no backup keeps the records longer. The Mac's data directory (`~/Library/Application Support/Mooring/`: `state.json`, the usage store, the journals and the SSH material), its log directory (`~/Library/Logs/Mooring/`, §15.10) and the export folder are therefore excluded from Time Machine. M5's daemon sets the exclusion with `tmutil addexclusion`, a sticky exclusion that needs no root, `doctor` reports it when it is missing, and `user export` warns when its `--out` folder is not excluded (`tmutil isexcluded`). Until then `delivery.md` (section 0) sets it by hand for the export folder. F18's escrow image, if adopted, is the only backup.

**Engine sandbox (M5 spike).**
- `mooring-exit` gets `network.client` only; `mooring-probe` gets `network.client` and `network.server`.
- The spike checks IP_BOUND_IF and interface enumeration under the sandbox.
- If the sandbox turns out to be infeasible, that is recorded as a decision.

**Logs and stderr tails.** Every `stderr_tail` is, deterministically and in this order (`StderrTail::scrubbed`, `crates/agent-proto/src/stderr.rs`):
1. scrubbed by **exact substring** against every secret in the current `SecretSnapshot` or bundle, longest secret first, each occurrence replaced by `<redacted>`;
2. escaped for control characters (`\n`, `\r`, `\t`, otherwise `\u{..}`, and `\` itself doubled), after invalid UTF-8 becomes U+FFFD;
3. bounded to the last whole escaped characters that fit in 4 KiB

before it reaches `status.json`, the UI, `daemon.log` or an SSH reply. Scrubbing runs on the complete output before anything is cut, so a secret is never split by the cut and partly kept. `scrubbed` is `StderrTail`'s only constructor, so agent code cannot wrap raw output without scrubbing it; a received tail is decoded through a private check of the size and control-character rules (the Mac cannot re-check the scrubbing, which needs the secrets). `SecretSnapshot::needles()` yields every secret's text forms, longest first, and a test proves it covers every secret kind. Xray echoes key material in some errors, for example `invalid "privateKey": …` (v26.9.30 `infra/conf/transport_security.go:100-102`).

---

## 13. Provisioning, upgrade, rotation, revocation, retirement and recovery

### 13.1 Provider requirements

**Hard requirements:**
- London (Amsterdam acceptable for the standby);
- a Debian 13 amd64 image;
- cloud-init user-data with `ssh_keys`, or console access to verify the host-key fingerprint;
- a dedicated public IPv4 configured on the interface;
- at least 1 TB of transfer;
- per-second or hourly billing;
- an acceptable-use policy that does not ban authenticated private proxies.

**Candidates:**
- **Primary:** a less popular UK network, such as Mythic Beasts (AS44684). Whether it supports cloud-init is **unknown**: no user-data documentation was found ([beasts.org VPS API quickstart](https://beasts.org/support/api/vps/quickstart), checked 2026-10-08). Use the console-fingerprint path if needed.
- **Standby, on a different ASN:** DigitalOcean LON1, which has billed per second since 2026-01-01 ([DO blog](https://www.digitalocean.com/blog/dropletplans-persecbilling-byoip-natgateway), checked 2026-10-08). DigitalOcean ranges were partially affected in the 2023 GFW measurements, which is one reason it is the standby rather than the primary.
- The final choice goes to whichever shows less peak-hour loss (19:00–23:00 China time) to the users' carriers in M8. **The user rents and pays for these;** Mooring holds no provider token (the operator's own tooling holds one, outside Mooring: D-10).

### 13.2 Provisioning (about 15 minutes hands-on)

1. **`node new lon1 --role primary`.** Generates the node's secrets, the one-time host key and the bootstrap key, and writes `cloud-init-lon1.yaml` (0600). The node is `Planned`, with no address; its `SshPin` is the one-time host key, and the user-data render refuses any other host key (`HostKeyNotPinned`, §8.9). Two active nodes already present make this fail with `TooManyNodes` (§13.4).
2. **The operator creates the VPS** in the provider's console.
3. **`node adopt lon1 --address <ipv4>`.** Over SSH, using the pinned one-time host key and the bootstrap key (unrestricted root for this window only):
   1. upload the agent and run `Bootstrap{expected_agent_sha, bootstrap_pubkey, ops_pubkey}`. This installs packages, users, units, the host profile, and `authorized_keys` with role-restricted lines. It **generates a new ed25519 host key** and removes the other host-key types, then returns `BootstrapDone{host_pubkey}`.
      *Built 2026-10-23 (M4e)*, in this order: the running agent's digest must be `expected_agent_sha` (`AgentShaMismatch`, before anything is done); the packages, unless `dpkg-query` shows them all installed (`apt-get update` and `install`, non-interactive, `Apt{stderr_tail}`); the accounts and the layout (§8.6); the agent installed as `agent/<sha>` and made `current`; the host profile staged in scratch space, validated (the units that run a generation's programs wait for the first transaction), installed and applied as a transaction applies it (§11.2 step 5), sshd's reload aside; every profile unit enabled, and the watch and the reflector started; root's `authorized_keys` rewritten to the two role lines and nothing else (a provider's key goes); the host key replaced; sshd reloaded; and the new key recorded (`/var/lib/mooring/host-key.json`). Another failure is `Bootstrap{step, stderr_tail}`. The order keeps a way back in: the bootstrap key is restricted to its forced command only once the agent it runs is installed, and sshd enforces the drop-in only once both keys are in place, so a retry over the bootstrap key works after any failure. A retry, or a second run, converges again and keeps the recorded host key, so a lost reply does not lose the key. In a Debian 13 VM (arm64, 2026-10-23) a real `Bootstrap` installed everything, the ops key reached the forced command with the new host key pinned (a command line it sent was answered `UnknownRequest`), the bootstrap key could send only `Bootstrap`, a second `Bootstrap` returned the same key, `RevokeBootstrap` locked the bootstrap key out, and after a reboot the watch and the reflector ran while the engines and the tunnel were skipped, with no failed unit. `Hello` reported only the `AllowUsers` drift that the VM's own login needed;
   2. re-pin the host key, then connect with the operations key: `ssh … true` must return the agent's typed `UnknownRequest`, which proves the forced command is active (otherwise `ForcedCommandNotActive`);
   3. reboot. `Hello` asserts Debian 13, a 6.12-series kernel, bbr, fq, the arch, VPS4 on the uplink interface, and the port range. The node's site comes from it (`render::adoption_site`): the address, which must be the single IPv4 `Hello` reports on the uplink (`AddressNotOnUplink`), the uplink interface, the arch and the port range. Debian, kernel, bbr and fq are asserted, not recorded; each `Apply` header carries the values of the `Hello` before it;
   4. `RevokeBootstrap`. The node is then recorded `Adopted` with its site, which stops referencing the bootstrap key, so the store deletes the Mac-side bootstrap key after that state commit (§7); the user-data file is deleted too.
   *Built 2026-10-23 (M5b part 1), for a VPS made by hand* (lon1, 2026-10-22), which has no cloud-init and keeps the host key it booted with: `node new <id> --role primary|standby --host-key <file>` plans the node with every secret above and that host key pinned, and gives every active or suspended user credentials on it; no user-data is written. `node adopt <id> --address <ipv4> --interface <bsd> --root-identity <key> --agent <binary>` uploads the agent with the operator's own root key, runs `Bootstrap` with it (root's `authorized_keys` then holds only the bootstrap and operations lines, so that key stops working), pins the new host key at once in `ssh/<id>/known_hosts` and in the state, checks the operations key's forced command (an empty request answered `UnknownRequest`; otherwise `ForcedCommandNotActive`), runs `Hello` (asserting Debian 13, a 6.12-series kernel, bbr and fq), `RevokeBootstrap`, and records the node `Adopted`. The reboot of step 3 is the operator's, from the provider's console; `Hello` checks the running system. A run that stopped after `Bootstrap` resumes with `--resume`, which starts at the forced command's check.
4. **`node target check lon1 <host>`,** then `node target set` with the attestation. Only a target that passes `qualify` (§11.7) can be stored.
   *Built 2026-10-23 (M5b part 2):* `node target check <id> <host> --interface <bsd> --engines <dir>` uploads the node's Xray if `HaveBlobs` says it lacks it, runs `TargetCheck`, prints the facts and every rule the target fails, judging it unattested and leaving the attestation's two rules out; `node target set … --same-asn --not-cdn --evidence <url>` measures again, qualifies with that attestation and stores the target (a configuration change), saying when it replaces one, since every user's file is then exported again.
5. **`node apply lon1`.** Missing blobs are uploaded, the agent is activated (and confirmed) if newer, and the transaction runs and is confirmed; the Mac records the confirmed generation and digest (`Bookkeeping::Applied`, §7). The daemon adds `wg-lon1`, which restarts `mooring-exit` for 1–2 s. The probes must report `Verified`.
   *Built 2026-10-23 (M5b part 2):* `node apply <id> --interface <bsd> --engines <dir>` renders the bundle from the keychain's secrets, sends `Hello` and the header built on it, uploads every blob `HaveBlobs` reports missing (a managed file from the bundle, an engine from the directory), and runs `Apply`; it reads `TxnStatus` every 2 s until `AwaitingConfirm` (at most 300 s), sends `Confirm`, and records `Applied` at the deployment's generation with the bundle's digest. An `Unchanged` answer is recorded the same way without a transaction. A failed, reverted or late transaction records nothing. The engine directory is the hosted build's `out/` that `cargo xtask engines-verify` accepted; every file is hashed again against the digests compiled into mooringctl, which a test keeps equal to `engines.lock.toml`'s, so a file changed after the check never reaches a node.

   *Built 2026-10-25:* `node upgrade-agent <id> --interface <bsd> --agent <binary>` reads the release binary (as `node adopt` does), sends `Hello`, and stops if the node runs that agent already. Otherwise it uploads the agent if `HaveBlobs` lacks it and sends `ActivateAgent{sha}`. The node installs and self-tests it, makes it the forced command and arms the revert timer the previous agent runs; the reply is `AwaitingConfirm{generation}` with the node's generation unchanged (0 before the first apply). `Confirm{generation}` goes out on a new session, which the new agent serves, and a last `Hello` must name the new agent (`AgentNotSwitched` otherwise). The state records nothing. It was needed before lon1's first configuration: the agent installed at adoption carried the owner-guard check of §11.2 step 6 that looked for account names. `node apply` does not yet activate a newer agent by itself, as this step plans: that needs the agent for each architecture in mooringctl's build, so for now the operator runs `upgrade-agent` with the release binary, as for `node adopt`.
6. **`user export …`.** Every node in the file must have confirmed the current generation, and the user must have accepted the current agreement revision (§9.2, F9). `user add` is a configuration change, so it comes before step 5's `node apply`; `user agree` is a bookkeeping record (§7), so it needs no apply and may come at any time before the export. The file then goes out by the channels of §9.4.

### 13.3 Upgrade and release coupling

1. Rebuild the app, which carries new `Resources/vps`.
2. Run `node apply` on the canary node, then on the others.

The Mac and VPS engines change independently, because the WireGuard wire format is frozen.

**Accepted coupling.** VPS artifacts ship only inside the signed app. A VPS-engine security fix therefore needs an app rebuild, which the `xtask release` lane automates. This is accepted for a single operator with a single Mac.

### 13.4 Rotation (IP blocked)

**The constraint (D-8).** At most two nodes are active (`MAX_ACTIVE_NODES`, §7): the Mac exit carries at most two WireGuard endpoints, and the probe port span is sized for two nodes. A `node new` while two nodes are active (`Planned` through `Retiring`) is refused with `TooManyNodes`, so the order of rotation follows from whether a healthy standby exists.

**Retirement** (`node retire <node>`), used by every procedure below:
1. The node becomes `Retiring`, a configuration change. Its WireGuard endpoint and probes leave the Mac configs, and its address stays denied everywhere.
2. `Shutdown{Retire}` halts the node.
3. A `RetirementShutDown` record moves it to `RetiredPendingProviderDeletion` and drops every user's credentials on it. Only after that state is committed are the node's keychain items, and the users' items for that node, deleted (§7).
4. The operator deletes the VM and confirms → `Retired`, which removes the address from the deny lists (a configuration change).

**With a healthy standby (the normal case).** Precondition: the standby's last `node apply` reported `AppliedVerified`, and its probes are `Verified`. Otherwise follow the procedure for two blocked nodes.
1. Retire the blocked node (lon1) first. It carries no China traffic anyway, and the standby serves the users meanwhile. A `Retiring` node still counts as active, so the next step needs lon1 to have reached `RetiredPendingProviderDeletion` (retirement step 3); deleting its VM can wait. If lon1 is the only channel node, run `alert setup` on the standby before retiring lon1 (below).
2. `node new lon2`, then `alert setup lon2` if alerting is set up, adopt, set the target, apply.
3. Apply the standby as well: its Xray rules list every node address, so its bundle changed, and exports refuse a node that has not confirmed the current generation (`NodeNotApplied{Stale}`).
4. Re-export every user with the new node plus the standby, and deliver the files by the channels of §9.4.

**With a single node and no standby,** the order is reversed: `node new lon2`, `alert setup lon2` if lon1 has channels, adopt, set the target, apply lon2 and re-apply lon1, re-export and deliver every user's file (§9.4), and only then retire lon1. This is the M8 pilot's case (F11): every user is without service until their new file is imported.

**With both nodes blocked,** users have no working node anyway: retire one, provision its replacement (new, `alert setup` if alerting is set up, adopt, target, apply, export), then retire the other and provision its replacement the same way.

Every step that changes the configuration bumps `config_generation`, so `node apply` runs on every node a user holds credentials on before that user's file is exported (§7). **Target: 20 minutes or less hands-on (M9).**

**Alert channels and viewers follow the node (revision 6).** Retirement drops the retired node's alert channels and its two Healthchecks Keychain items (§7). The deployment's one ntfy topic stays while another node has channels, and is deleted after the commit that leaves no channel node; the next `alert setup` then draws a new topic, which the phone must subscribe to. So, while alerting is set up, the replacement or the standby gets its channels with `alert setup <node>` (M5), which stores its Healthchecks checks, **before** the last channel node is retired. A planned node can hold channels (§7), so `alert setup` can follow `node new` at once, and the node's first `node apply` carries them. The node then sends to the same topic, and the phone's ntfy subscription needs no step; the store test `the_alert_topic_is_shared_and_outlives_one_channel_node` follows that order. M5's `node retire` refuses, unless the operator confirms it, to retire the last channel node while another active node has none. The phone's viewer keys need no step either: every node's bundle carries every viewer (§8.6), but the phone needs the new node's address and host-key fingerprint (`viewer new` prints it, §15.9). A node retired because it may be compromised, not merely blocked, leaves the topic with whoever holds its disk: replace the topic after the retirement (`alert rotate-topic`, §12).

### 13.5 Revocation

1. The user moves to `RevokePending`, a configuration change: from then on the user is served on no node and exported nowhere. The nodes still to revoke are not stored separately; they are exactly the nodes in the user's `per_node` (`User::revocation_remaining`).
2. `Apply` runs on each of those nodes.
3. After a node commits, a `RevocationCommitted{user, node}` record removes that node from `per_node`. Only after that state is committed are the user's keychain items for that node deleted (§7).
4. When `per_node` is empty, the same record makes the user `Revoked`. Retiring a node drops the user's credentials there too (`RetirementShutDown`, §13.4).

A failing node stays in `per_node`, and the operator retries it explicitly.

**Runbook for a seized device:** revoke the user, then rotate every node that user held. A leak without a seizure (a lost device, a copy outside the rules, a file handed on) is a `user reissue` instead, applied at once, and a new file for that user alone (`delivery.md`, section 8).

### 13.6 Live changes

User changes re-render the VPS configs and restart the engines. Existing connections drop for a few seconds; restarts are scheduled for 03:00–06:00 China time. `mooring-exit` restarts only if its own rendered digest changed.

Nothing schedules them yet (revision 5): `node apply` is manual, and the daemon never sends `Apply` (§10.5). The plan for M5 is `mooringctl apply --pending`, run at 19:20 UTC (03:20 China time), inside the window and before the VPS's 20:00 UTC unattended-upgrades reboot (§5.2). launchd's calendar intervals are in the Mac's local time, and no fixed London time is both inside the window and before the reboot in BST and in GMT alike, so the job fires every hour at minute 20 and runs only between 19:15 and 19:45 UTC, which leaves its applies time to finish before the reboot; a firing that launchd delivers late, after a sleep, outside that span does nothing, and the console shows the pending apply until the next night. The agreement and the user guide state the window as 3 to 6 a.m. Beijing time. It applies every node whose confirmed generation is older than the deployment's, and carries out the suspensions that users' effective quotas (their own, or the automatic one of F4) and expiry records call for (`daemon-core`'s `policy::evaluate`, §11.5, §15.3). A suspension for quota lasts for the rest of its cycle and keeps counting among the users who share that cycle's budget, so it never changes the others' shares (§15.3). The job records each suspension it carries out with `since` set to the `now` of the evaluation that proposed it, so the instant lies in the cycle its `QuotaExceeded{cycle_start}` names. At the first apply of a new billing cycle the job resumes the users whose suspension for quota has lapsed: those suspended `QuotaExceeded` at an instant (`since`) before the current cycle's start, whatever start the suspension records, exactly the ones `daemon-core`'s `quota_suspension_holds` does not hold, so M5 lists them with that predicate, and a suspension for quota is always either counted or due for resume (§15.3). A suspension for quota made after the run's `now` can only come from a clock that stepped back or a corrupt record; it is `QuotaSuspensionAfterNow` from the predicate, and from `evaluate` whenever an `AutoQuotaPolicy` is recorded (dormant or not), never read as held or lapsed. `evaluate` then fails as a whole, so the run carries out none of its proposals (expiry suspensions and suspensions for a user's own quota included) and no resume that depends on that record, and reports the error until the clock passes that instant or the operator resumes the user; node applies, separate changes, still run. `evaluate` proposes no action for a suspended user, so the resume is the apply job's own step, and until it runs such a user counts for nobody's share. The cap still binds: it counts only active users (§7), so the operator may have admitted a user while another was suspended for quota, and a resume past `capacity.max_active_users` is refused with `TooManyActiveUsers`. The job therefore resumes lapsed users one configuration change each, the earliest suspension (`since`) first and then by `UserId`, only while fewer than `max_active_users` users are active (with no cap, every one). A user the cap holds back stays suspended and shares nothing; the job reports them (its `--json` outcome and the console) and the operator decides, and it is not a failure: no refused resume blocks the run's suspensions or node applies, which are separate changes. `apply --now` does the same at once, for example in an abuse case. The console shows each node's pending apply and how long it has waited (§15.3).

### 13.7 Recovery runbooks

- **`console-recovery.md`.** The provider's rescue boot is used when SSH is lost despite commit-confirm. The steps: mount the disk, restore `authorized_keys` and `/etc/nftables.conf` from `gen-<N-1>`, and reboot.
- **`mac-loss.md`.** Keychain items are `ThisDeviceOnly`, and the operations key is excluded from backups. Losing or replacing the Mac therefore means rotating every node and reissuing every user file. Theft needs the same response in any case. This is the accepted recovery model. An encrypted backup would change it (an `hdiutil` AES-256 image of the state, the Keychain secrets and the SSH material, with the passphrase kept offline). That change to the security posture is the pending operator decision F18 (critique C-13), so until then no backup exists.

---

## 14. Typed error taxonomy

Errors are per-crate `thiserror` enums. Each public error enum has a companion `<Name>Kind` enum with an exhaustive `ALL` list, generated from the same tokens as the kinds (`model`'s single `kinds!` macro, used by every Mac-side crate, and agent-proto's `closed_enum!`), so `ALL` cannot fall out of step. `xtask kinds-coverage` finds every public enum whose name ends in `Kind` and fails if any variant is not named as `<Enum>::<Variant>` by at least one test. xtask's own errors are `pub(crate)` in a binary and have no `Kind`.

The CLI maps errors to `{"error":{"kind","detail"}}` with a stable exit code, fixed by `contract/cli-fixtures`. Revision 7's router commands come before that contract: they print the error and its causes on stderr, `router status --json` prints the unavailable `RouterReading` on stdout, and the exit codes (router row below) move into `contract/cli-fixtures` with the M5 CLI contract. There is no `Other(String)`, no `unwrap` or `expect` outside tests, and no path that defaults to success.

| Domain | Variants | Handled by | Retry | User sees |
|---|---|---|---|---|
| model | One variant per newtype rule (`InvalidAddress{addr,class}`, `InvalidShortId`, `InvalidDnsName`, `InvalidHopInterval`, `InvalidHy2Listener`, `InvalidKeepalive`, `InvalidInterfaceName`, …) and per cross-entity invariant (`PortPlanConflict{conflict}`, `UnknownNode`, `UnknownUser`, `DuplicateId`, `TooManyNodes`, `GenerationAhead`, `GenerationRegressed`, `TargetNotSet`, `NodeNotDeployable`, `NotRevoking`, `RevokePendingWithoutCredentials`, `DuplicateAlias`, `TooManyActiveUsers`, `SimThresholdAbovePlan`, `DeprioritisationNeedsFairUseLine` (revision 5's `DeprioritisationNeedsUnlimitedPlan`, renamed in revision 6), `AlertChannelsOnInactiveNode`, `DigestTimeTooEarly{at,earliest}` (a digest time before 02:00 in Europe/London, §15.8), …; `DuplicateId` names a viewer as `EntityId::Viewer`); revision 6's newtypes: `InvalidBudgetPercent`, `InvalidSimFactor`, `InvalidWallClockTime`; a fresh deployment, or a change that edits the SIM policy, without a recorded plan: `PlanNotRecorded`; user transitions: `UserNotActive`, `UserNotSuspended`, `RevocationAlreadyStarted`; the version-1 lift: `StopPolicyUnchosen`; interface resolution: `InterfaceNotSelected`, `UplinkModeMismatch`, `UplinkEqualsEgress`, `InterfacesForOtherSite`. Target qualification fails separately with `TargetRejected{reasons}`, every failed rule listed (§11.7) | CLI | no | the exact field |
| keys | `Entropy`, `MaterialRejected` (a model constructor refused an all-zero draw: a broken source), `CertValidity{now}`, `CertBuild{step}`, `InvalidSshComment` | CLI | no | fatal |
| store | `StoreError`: `Io{op,path}`, `Lock{path}`, `NotInitialized`, `AlreadyInitialized`, `StateCorrupt{path}`, `DowngradeRefused{found,newest}`, `MigrationFailed{from,to}`, `Encode`, `GenerationConflict{expected,found}`, `RevisionConflict{expected,found}`, `CounterOverflow`, `GenerationEdited`, `AppliedEdited{node}`, `UserStatusEdited{user,from,to}` (a status changed outside the user transitions, or a user who is not revoked removed; §7), `InvalidChange` (a change, or the initial deployment, breaks a model invariant: `Store::init` with an unrecorded plan is `InvalidChange{PlanNotRecorded}` and creates no file, and so is a change that edits the SIM policy and leaves it unrecorded, §7), `SecretRefsChanged`, `SecretPlanMismatch`, `DuplicateSecret`, `SecretWrite{secret_ref}`, `SecretCleanup{committed,failures}`; M5c: `LatchCorrupt{path}` (`run/latch.json` is not a version-1 latch, so the exit stays down rather than read it as none), `UsageDirNotDirectory{path}`; revision 7: `RouterPinCorrupt{path, fault}` (the router identity file is not a version-1 pin: `TooLarge`, `Undecodable`, `UnsupportedVersion`; a missing file is "no pin", never an error). `SecretStoreError`: `SecretMissing{secret_ref}`, `Keychain{op,status}`, and (revision 7) `ItemInvalid{secret_ref}` (a stored item that is not UTF-8 text of its reference's kind; never echoed). `ChangeError<E>`: `Store` or the caller's `Refused(E)` | CLI, daemon | `GenerationConflict`/`RevisionConflict`: the user re-runs | yes |
| export | `UserNotActive`, `AgreementNotAccepted{user, recorded, required}` (F9: no `AgreementRecord` of `AgreementVersion::CURRENT`; `recorded` is the revision accepted, if any), `NothingToExport`, `NodeNotApplied{node, Stage \| Stale}`, `CapabilityUnsupported{line,cap}`, `CertUnparseable`, `CertKeyUnsupported`, `CertNotCurrent`, `CertSanMismatch`, `CertEkuMissing`, `InvalidTag`, `Model`, `Secret`, `Encode` | CLI | no | yes |
| render | `NoAppliedNodes`, `DuplicateCredential{node,kind,first,second}` (two identities on a node, both named, share a VLESS UUID, a loopback UUID or a Hysteria2 password, as the engines key them; §8.1), `AddressNotOnUplink`, `TargetFactsForOtherHost`, `NodeNotPlanned`, `HostKeyNotPinned`, `InvalidHostKey{rule}`, `WireValue{field}` (a drift between the model and wire rules, unreachable by construction), `Model`, `Secret`, `Export`, `Encode` | CLI, daemon | no | yes |
| ssh | `Spawn`, `HostKeyMismatch{node}`, `AuthFailed`, `Transport{stderr_tail}`, `Timeout`, `ProtocolMismatch`, `Decode`, `ResponseTooLarge`, `ForcedCommandNotActive` | CLI, daemon | `Transport`/`Timeout`: user or next poll; `HostKeyMismatch`: **never** | yes; `HostKeyMismatch` as a security alert |
| agent (remote) | `BlobHash{expected,actual}`, `BlobMissing{sha256}`, `BlobTruncated{expected,received}`, `TrailingInput`, `StageValidation{tool,stderr_tail}`, `Apt{stderr_tail}`, `Systemd{unit,op}`, `HealthGate{failed}`, `RolledBack{generation,cause}`, `RollbackFailed{generation,cause}`, `RevertedUnconfirmed{generation}`, `AgentSelfTestFailed{stderr_tail}`, `AgentShaMismatch{expected,actual}`, `Busy{generation}`, `GenerationNotNewer{current}`, `GenerationMismatch{current}`, `NotAwaitingConfirm`, `UnknownTransaction{generation}`, `NodeHalted`, `NotHalted`, `HostFactsChanged{field}`, `HostFactUnavailable{field}`, `PortPlanConflict{recorded,live}`, `TargetFactsUnavailable{tool,stderr_tail}`, `NoUsageRecorded{month}`, `SeriesTooLarge{fitting_bins}`, `SeriesNotRecorded{recorded}`, `GateCloseFailed{stderr_tail}`, `Io{op,errno}`, `RoleNotPermitted{role,request}`, `GateReasonNotPermitted{role,reason}` (revision 6: a `GateSet` reason the role may not set), `GateStopUnconfirmed{waited_secs}` (revision 6: the watch did not confirm a viewer's stop within `VIEWER_STOP_WAIT_SECS`; the gate may still be open, §11.3), `MacReportMissing` (revision 6: no report stored), `UnknownRequest`, `RequestTooLarge` (`NotServedYet{request}` answered the requests of M4's later slices from 2026-10-22 and was removed with `TargetCheck`, the last of them, in M4e). M4e adds `Bootstrap{step, stderr_tail}`, `AccountMissing{account}` and `HostProfileUnsupported{required, supported}`. Not frozen (§11.1). Values that fail their rule on receipt are `ValueError`s; revision 6 adds `NodeName`, `ReportUserId`, `ReportBandNumber{number}` (a band number outside 1..=999), `MacReport{rule: TooManyUsers \| TooManyAlerts \| UsageMismatch}`, `NoticeTitle` and `NoticeBody` | CLI shows; the VPS stays at last-good or stopped | idempotent re-apply | yes |
| daemon: preflight | `EgressInterfaceAbsent{selector}`, `EgressAmbiguous{matches}`, `EgressNoIpv4{bsd}`, `EgressSubnetMismatch`, `UplinkAbsent`, `UplinkEqualsEgress`, `DirectProbeFailed{node,stage}`, `OutsideCarrierPrefixes{ip}`, `SecretsUnavailable`, `AgentNotEnabled{status}`, `ForeignNetworkAttached{findings}` (revision 5, P0-2, §10.2; the check is built in `daemon-core`, the preflight is plan, M5); M5a: `CarrierCheckUnrecorded`; M5c: `NoAppliedNode` (no node has confirmed a configuration, so there is no tunnel to serve), `SimPlanUnrecorded` (a state lifted from version 1, until `sim set-plan`) | daemon | on interface events or the next tick | menu and notification |
| router (revision 7: built in `mooringctl` for `router pin`, `status` and `capture`; the daemon's poll is M5; read only, §15.6) | `RouterUnreachable{cause}` (interface absent, no default route, ambiguous default route, gateway unresolved, socket, bind, connect, send, receive, `Timeout{phase}`, closed before an answer), `RouterAuthFailed{cause}` (`Cooloff`: the M7 reports a password cool-off, so no password is sent; `Refused{status}`: 401 or 403; `LoginRefused{reported}`: the login was answered by a `302` to the M7's login-failed page, alone or followed by `&` and parameters, so nothing more is sent; `reported` keeps the page's `errno` (1 to 4 digits, a number) when given once in that shape, and its `errdetail`, when given once and not empty, as one of the four fields the login form sends (`token`, `err_redirect`, `ok_redirect`, `session.password`, on an exact match) or as "another field" with none of its bytes, and the message names them: for `session.password` it reads the refusal as the stored password being wrong and says to store it again with `mooringctl router set-password`, for another field or a number alone it blames nothing, and with nothing given it is the earlier refusal with that advice (§15.6 rule 9)), `RouterUnsupported{cause}` (`EndpointMissing`: 404; `GatewayLink`: `router pin` found no single unicast Ethernet address, or found the placeholder `02:00:00:00:00:00` (§15.6 rule 4); HTML is never scraped), `RouterMalformed{cause}` (HTTP framing, one of 17 fieldless faults, among them two `Location` headers; an unexpected status; `Redirect{step, status}`, a redirect other than the M7's session set-up, naming the request it answered (the first, the set-up or the retried request) and its status (§15.6 rule 9); a web page; a body over 1 MiB; never the bytes), `Document{error, login}` (the parser refused the `model.json`: a `RouterParseError` naming the leaf path, with the login's answer when one was sent: its status and where its `Location` pointed (the start page, the login-failed page with what it reported, the session set-up, the endpoint, elsewhere, or no `Location`), never its bytes; its kind is the parser's own `reason()`, so a session that is not an administrator's is `AuthFailed`, another model or API version `Unsupported`, anything else `Malformed`, by the one rule the router panel uses), `RouterIdentityMismatch{expected, found}` (another address, or one that cannot identify a device: not unicast, the placeholder `02:00:00:00:00:00`, not six bytes, or two entries; no password is sent). No variant holds a byte of the answer, a header, a cookie, the token or the password, except the login-failed page's `errno` as a number and which of the login form's own four fields its `errdetail` names (any other value is kept as "another field", with none of its bytes). Their kinds are the status's `RouterUnavailableReason` (`NotConfigured` when the pin or the password is missing, then `Unreachable`, `AuthFailed`, `IdentityMismatch`, `Unsupported`, `Malformed`); `mooringctl` exits 3 to 8 in that order, 1 for a failure on the Mac (HOME, keychain, store, kernel tables, an empty neighbour table once the gateway has been reached (for `router pin`, in the reads both before and after a warm-up connection that succeeded), read as the kernel hiding it from the binary (§15.6 rule 10), terminal, confirmation, an existing pin or capture file, the password's rule), 2 for a usage error (clap). A value outside its bounds is `RouterValueError` (`SignalOutOfRange`, `TemperatureOutOfRange`, `BatteryPercentOutOfRange`, `InvalidText{field}`, never echoing the text; revision 7: `TooManySecondaryCarriers`, `SessionExceedsUptime`), and a `model.json` that cannot be read is `daemon-core`'s `RouterParseError`, whose `reason()` is the kind: `NotAdmin` is `AuthFailed`, `Unsupported` is `Unsupported`, every other is `Malformed` | `router status` exits with the code; the daemon → status (M5) | the operator re-runs; the daemon's next poll; `RouterIdentityMismatch`: none until the operator acts | the human error on stderr; with `--json`, the unavailable reading on stdout; the router panel (M5). None of them stops the exit; the carrier check does (§10.2) |
| macsys (revision 7) | `MacsysError`: `InvalidInterfaceName`, `InterfaceAbsent`, `Sysctl{errno}`, `TableChanged` (the table kept growing through three retries), `TableTooLarge` (over 16 MiB), `MalformedRoute{fault}` (`ShortHeader`, `LengthOverrun`, `Version`, `SockaddrOverrun`), `NoDefaultRoute`, `AmbiguousDefaultRoute`, `NeighbourTableEmpty` (the kernel's neighbour dump was empty, 0 bytes; `macsys` states only that, §15.6 rule 10), `NeighbourAbsent`, `NeighbourIncomplete`, `NotEthernet{alen}`, `AmbiguousNeighbour`, `Terminal{call, errno}`; `MacsysErrorKind` is written by hand (no workspace edge, so no `kinds!`) and kinds-coverage scans it | `mooringctl`, which maps the route and neighbour outcomes to the router errors above; `NeighbourTableEmpty`, once the gateway has been reached (by the anonymous `GET` of `status` and `capture`; for `router pin`, only when the reads both before and after its warm-up connection, which succeeded, were empty), to its own local failure `NeighbourTableHidden`, whose message names `cargo xtask mooringctl`; and every other to a local failure | the operator re-runs | as that router error, or as a local failure naming this cause |
| daemon: engine | `EngineSpawn{io}`, `EngineConfigRejected{stderr_tail}`, `EngineStartFailed{stderr_tail}`, `EngineCrashLoop{n,window}`, `StaleEngine{pid}` | daemon | backoff only for post-health crashes | yes |
| daemon: verify | Violations (engine stopped and latched): `EgressMismatch{d1,d2,observed}`, `EgressIsNodeAddress{node}` (+ `Shutdown`), `EgressEqualsUplink`, `OutsideCarrierPrefixes{ip}`. Degraded: `NodeProbeFailed{node,proto,stage}`, `ReachabilitySuspect{node}`, `WatchStale{node}` | daemon | violations: none until Retry, a config change or an interface change | red, with notification |
| daemon: budget and power | `SimWarn{cycle_start}`, `SimCapReached{cycle_start}` (engine stopped until the cycle resets; the bytes and the thresholds are in the status's SIM meter beside it), `OnBattery`, `PowerHelperExited`, `DrainTimedOut`, `DrainFailed{ssh}` | daemon | per rule | yes |
| daemon: console core (`daemon-core`, built) | `ForecastError` (`NoBins`, `NothingElapsed`, `BinOutsideCycle`, `BinsOutOfOrder`, `MissingDay`, `CounterOverflow`, `Model`): a missing day is never read as zero. `UsageError` (`LedgerGap`, `DuplicateLedger`, `MissingLedger{node}`, `LedgerForUnknownNode{node}`, `PeriodBeforeLedger`, `NotCoveredThrough`, `BinStraddlesThrough`, `PrincipalNotAUser`, `UnknownUser`, `CounterOverflow`, `Model`): every node that may have counted traffic needs a ledger. `FigureError` (`ShareAboveWhole`, `SharesNotWhole`, `SplitMismatch`, `DerivedMismatch`): a decoded usage row contradicts its own figures. `AlertError` (`ClockWentBackwards`, `DuplicateCondition`), `PolicyError` (`UsageForOtherCycle`, `UsageAfterNow`, `UsageMissing`, `AutomaticQuotaZero{budget_bytes, sharing}` (revision 6: a share that rounds down to zero is an error, never "no quota"; `sharing` is N, the users sharing the budget), `QuotaSuspensionAfterNow{user, since, now}` (a suspension for quota made after `now`: the Mac's clock stepped back or the record is corrupt, so whether it holds cannot be told), `Model`), `CapacityError`, `RouterValueError` (revision 7 adds `TooManySecondaryCarriers` and `SessionExceedsUptime`), `StatusError` (`UnsupportedVersion`, `UnknownNode`, `UsageMismatch`, `AlertsNotOrdered`); M5c: `MeterError` (`CounterOutOfRange{value}`: a counter read 2^32 or more, so the kernel no longer gives them modulo 2^32 and no delta is taken; `Overflow{date}`, `Calendar`, `Corrupt`: the meter file is not a version-1 meter) and `SnapshotError` (`Activity`, `Quota`, `Cycle`, `RowMissing{user}`, `Status`: the status line could not be assembled); revision 7: `RouterParseError` (`Syntax`, `Truncated`, `NotAnObject`, `KeyRefused`, `Field{leaf, element, fault}`, `Carriers{fault}`, `NotAdmin`, `Unsupported{leaf}`, `SessionExceedsUptime`) with `FieldFaultKind` and `CarrierFaultKind`, naming a leaf's path and never a byte of the answer; revision 6: `NotifyError` (`Text`: a rendered notice broke the notice grammar, a renderer bug; `Model`: a time past the year 9999) and `ReportError` (`Wire`: the projection broke a report rule) | daemon → status (the forecast's and usage's kinds are what the status shows instead of figures) | next poll | the panel that lacks figures says why |
| watch (VPS) | `WgReadFailed` (gate closes), `NftFailed` (unit restarts; gate closed by `ExecStopPost`), `StatsQueryFailed`, `TargetDegraded`, `ExitFlowCapHit{count}`, `StateWrite{io}`, `MacSilent{since}` (handshake older than 600 s, no operator hold), `DiskLow{free}` (under 1 GiB or 10 %), `ClockUnsynced`, `RebootPending{since}`, `AccountingCanaryMissing{inbounds}` (critique C-11; every inbound whose canary is missing, in one condition; its evidence is settled with the watch in M4) | watch → status | next tick | `node status`, menu |

---

## 15. Observability, the operator console and logging

Revision 5 turns this section into the design of the operator console. The operator asked for a console that shows each user's usage and the router's state and lets him act. What needs no decision is designed here. Revision 6 records the operator's decisions of 2026-10-08 on automatic quotas (F4), remote viewing (F5) and the alert channels (F6); retention (F7) was decided in revision 8, by delegation, as its recommended default. Built so far: the protocol-1 frames the console reads from a node (the `StatusV1` additions, `UsageSeries` and `Events`, §11.1), the model records it shows (§7), and, in revision 6, the automatic quota (§15.3), the push notices, digest and dead-man rule (§15.8), and the remote viewer's role, report and keys file (§15.9). Everything else in this section is plan, for M4 (agent), M5 (daemon and CLI) and M7 (app).

### 15.1 Shape

- **The truth stays on the exit Mac.** `mooringctl daemon` merges each node's `StatusV1`, `UsageSeries` and `Events` with the SIM meter, the probes, the read-only router adapter (§15.6) and its own event journal (§15.7).
- **The CLI is the only API.** `Mooring.app` renders `mooringctl status --follow --json`, and calls `mooringctl … --json` for history and actions. It never reads secrets or daemon files (§5.1).
- **No web panel and no new listener**, on the Mac or on a node (§18).
- **The document (revision 9).** Each line of `status --follow --json`, and `status.json`, is a `ConsoleStatus` (`daemon-core::console`): `{"deployed": <MacStatusV1>}` once a deployment exists (which, since 2026-10-23, carries the same `advisories` beside its router panel and refuses any that do not follow from it, `StatusError::AdvisoriesMismatch`), and before that `{"no_deployment": {"version": 1, "at", "router", "advisories"}}`, the router panel alone and the settings the exit needs off that it shows on (`RouterStatus::advisories`, §15.6 rule 8; a document whose advisories do not follow from its panel is refused, `AdvisoriesMismatch`). A Mac without a deployment has no exit, SIM meter, user or node to report, and the document says so rather than carry zeros for a deployment that does not exist. Both carry the router panel, which needs no deployment. The fixtures are `contract/console-fixtures/` (generated by `crates/daemon-core/tests/status/console.rs` and pinned byte for byte); every object in them refuses an unknown key. *Versions:* no daemon is deployed yet, so version 1 of the undeployed document and the control lines change shape in place (revision 9 added `advisories` and the M7's new values); from the first release on, a change of shape raises `UNDEPLOYED_STATUS_VERSION` or `MAC_STATUS_VERSION`, and the control channel gets a first line naming its protocol (M7, with `SMAppService`; built 2026-10-23, §10.1), so that an app updated under a daemon not yet restarted says so instead of failing to read a reply. Until then a development build that changes the documents restarts the agent (`cargo xtask app`, §5.1).
- **Naming.** Revision 4 called the Mac's stream `StatusV1`, which collides with agent-proto's `StatusV1` (`crates/agent-proto/src/status.rs`), a node's status. The Mac's type is **`MacStatusV1`**, defined in `daemon-core` (§6.1). A node's status keeps its name.

### 15.2 `MacStatusV1`

`MacStatusV1` is the `deployed` variant of the console's document (§15.1): `mooringctl status --follow --json` prints it, and `status.json` holds it, once a deployment exists. Revision 4's contents:
- `exit_state` with its reason and `since`;
- `egress{bsd, lladdr, ipv4}` and the uplink;
- per engine: `{pid, restarts, last_exit}`;
- per node: probes (`at`, `verdict`, `latency_ms`), gate state, holds, halted, handshake age, applied generation, watch age;
- `egress_ip` and `verified_at`;
- the SIM figures `{cycle_start, bytes, warn, hard_stop, accuracy: Exact|LowerBound}`;
- per-user bytes;
- power state.

Revision 5 adds (the type is built in `daemon-core`; the daemon that emits it is plan, M5):
- the egress link's speed and state;
- per node:
  - the deployment's current generation beside the applied one, and how long an apply has been pending;
  - the node's own `StatusV1` additions: `accounting_at`, `last_active`, `engines`, `host`, `transfer` and the watch conditions;
- in the SIM figures:
  - the model's `SimThresholds`: the warning, `stop` following the stop policy (§7) in place of `hard_stop`, and the plan's line with its kind (`fair_use` or `allowance`), checked on decode as the policy is;
  - the received and sent bytes;
  - a `SimForecast`: the cycle-to-date daily average, the cycle's bytes projected linearly from it, and the day each threshold was or is projected to be crossed. The average over the whole cycle so far is a deliberate simplification *(inference)*: a burn over the last 7 days would follow a change of use sooner, and is a refinement for M8 data;
- per user, and per node × protocol: bytes for today, the SIM cycle, the calendar month and lifetime, and the last active time; "active now" is `active`, `idle` or `unknown` (a node serving the user has no fresh accounting poll), never a guess. Every node that may have counted traffic must be covered, or usage is shown as unavailable with its reason (`MissingLedger`), never as zeros; a decoded row whose figures contradict each other is refused (`FigureError`);
- router status (§15.6), capacity (§15.3), foreign networks (§10.2) and open alerts (§15.8).

Swift decodes the stream through a Codable mirror, tested against Rust-generated fixtures in `contract/status-fixtures/`: three scenario documents (`serving`, `degraded`, `down`) and `variants.json`, which holds one value of every variant of every enum a status carries, so the mirror has a fixture for each variant. Each is pinned byte for byte, and every object in them refuses an unknown key. `degraded` runs the 20-user fixture without a cap, so 18 users are active, beyond the pilot's cap of 5 (F3): it exercises the app at the scale the model allows, and its SIM is accordingly forecast to pass the warning the next day, with the `SimForecastCrossing` alert open.

### 15.3 What the console shows

Sources: **X** Xray's counters, read by the node's watch; **A** the node's `StatusV1`, `UsageSeries` and `Events`; **D** the Mac daemon (interfaces, probes, latches, SIM meter, power helper, journal); **S** `state.json`; **R** the router adapter (§15.6).

| Screen | Shows | Sources |
|---|---|---|
| Overview | Exit state; each node's gate and verdict; SIM gauge and forecast; the router's data service type, band, LTE and NR signal, and thermal state; capacity now (uplink use, loaded RTT); users active now; open alerts | D, A, R |
| Users | One row per user: label (Mac only); opaque id and optional public alias; status (`Active`, `Suspended{reason, since}`, `RevokePending`, `Revoked`); client line; nodes held; active now and last seen, per protocol and node; up and down for today, the SIM cycle, the calendar month and lifetime; shares of the cycle's served bytes by node and protocol; estimated SIM cost (the cycle's served bytes × the measured SIM factor, §15.4); quota used, limit, state and action, marked as the automatic quota or the user's own override (F4), and the expiry, when set; the agreement revision accepted and its day, flagged when it is not `AgreementVersion::CURRENT`, because `user export` then refuses (F9). "Up" is client → destination (Xray's uplink), "down" destination → client | S, X via A, D |
| User detail | A per node × protocol table; an hourly chart over 7 days, daily over 35 days and monthly over 13 months, the periods F7 keeps on the Mac (§20.2); a rotation tracker (bytes on a newly applied node, which also shows that a re-delivered file was imported); actions | S, A |
| Nodes | Role, stage, address; applied against current generation, and how long an apply has been pending; gate, holds, halted; handshake and watch age; the last in-chain verdict per protocol (time, verdict, latency); engines (active, uptime, Go heap, restarts); watch conditions; the REALITY target and its last hourly check; host health (uptime, load, memory, disk, journal, reboot required, last upgrade, clock sync); the uplink's transfer this month against the provider's allowance; `ReachabilitySuspect`; probe bytes | S, A, D |
| Exit | Exit state, reason and since; violation latches with their evidence (`d1`, `d2`, observed, time); the egress's name, link-layer address and M7-side IPv4, link speed and state; the carrier check (egress public IP, inside `carrier_prefixes` or not, pairing, `verified_at`); `mooring-exit` and `mooring-probe` (pid, restarts, last exit); power (AC or battery, assertions held, last sleep and wake, `DrainTimedOut`); foreign networks (§10.2); pending applies | D, S |
| SIM | The plan (carrier, kind, line or "no line", speed cap, terms URL and date) or "not recorded"; the bill day; cycle bytes received, sent and in total, against the warning, the stop policy and the plan's line; accuracy; daily burn and forecast, with a line for the operator's own use (§10.2); a reconciliation over the cycle (below) | D, S, R |
| Router | §15.6 | R, D |
| Capacity | Egress tx and rx now (1-minute average) and over 24 h; uplink use = tx rate ÷ `UplinkBaseline.p50` (§7), with the observed 7-day p95 tx rate beside it; loaded latency = direct-probe RTT − its 24 h idle p10; who is using it now (per-user rates from the latest deltas, plus an "unattributed" line labelled with the splice caveat); a China-evening heatmap (hourly, Asia/Shanghai) of served bytes and saturated minutes; served bytes this cycle against the served budget (the SIM budget × 1000 ÷ the recorded `SimFactor` in ‰, about 143e9 at the pilot's stop) | D, S, X via A |
| Events | The Mac's journal and the nodes' journals; daily availability; the 72 h `Verified` percentage that M8 accepts on (§15.7) | D, A |

- **Reconciliation** sets the SIM meter's bytes against: Σ users' served bytes × the factor; the probe bytes; the M7's own counter, if §15.6 can read it; and the operator's weekly reading of SMARTY's dashboard or app usage history. SMARTY counts in binary units (1 GB = 1024 MB) per full MB, re-sent packets and flow-control overhead included ([SMARTY-PG] p23), so its figure is converted before comparing; whether it shows the GB used on an Unlimited plan, and how fresh it is, is not stated and is recorded in M2a. The unattributed remainder is WireGuard, keepalive and probe overhead, plus macOS's own traffic.
- **Automatic quotas (decision F4, 2026-10-08; latched per cycle, decided 2026-10-09; built: `daemon-core`'s `policy::automatic_quota`).** While the deployment has an `AutoQuotaPolicy` and at least `from_active_users` (6) users share the cycle's budget, each user's cycle quota is `budget × 1000 × budget_percent ÷ (sim_factor ‰ × 100 × N)` served bytes, rounded down in one step, where the budget is `SimThresholds::budget_bytes()` (the pilot's hard stop, 240e9 since 2026-10-23). N, and the threshold, count the users `Active` now plus the users suspended for quota (`QuotaExceeded`) during the billing cycle being evaluated: their suspension was made (`since`) at or after the cycle's start, UTC midnight of its first day. The instant decides, not the recorded `cycle_start`, which names the cycle as the bill day gave it at the suspension: an edit of the bill day can move the current cycle's start back past a recorded start, or forward past it as SMARTY's late renewal does (§7, `BillDay`), and either way a suspension made since the current start counts and one made before it has lapsed (`quota_suspension_holds`; `a_quota_suspension_counts_after_the_bill_day_moves_the_cycle_start_back`, `a_quota_suspension_counts_after_the_bill_day_moves_the_cycle_start_forward`, `a_forward_edit_of_the_bill_day_keeps_the_share_enforced`). A suspension for quota made after `now`, which only a clock that stepped back or a corrupt record can leave, is `QuotaSuspensionAfterNow`, never read as held until its own cycle ends nor as lapsed (`a_quota_suspension_after_now_is_an_error`). `automatic_quota(&Deployment, now)` takes the cycle `now` is in; `policy::evaluate(&Deployment, &CycleUsage, now)` computes that cycle once and uses it both to check the usage and for the quota. Users suspended for any other reason (`Operator`, `Expired`, `AbuseReview`), revoking and revoked users do not count, nor does a suspension for quota made before the cycle's start, which has lapsed and which the apply job resumes, within the cap, at the first apply of the new cycle (§13.6); `evaluate` proposes nothing for any suspended user. A user with an override does count, and an override does not reduce the shared budget. With the pilot values and N = 6 that is 300e9 × 1000 × 80 ÷ (2100 × 100 × 6) = 19,047,619,047 bytes. The quota warns at 80 % and suspends at 100 % (`SuspendReason::QuotaExceeded{cycle_start}`). A user's own `UserPolicy.quota` wins, larger or smaller (`effective_quota`); a share of zero bytes is `AutomaticQuotaZero{budget_bytes, sharing}`, never "no quota"; `evaluate` applies the effective quota of every active user, and one with a quota but no usage entry is `UsageMissing`.
  - *Latched per cycle.* A suspension for quota changes neither N nor anyone's share within its cycle, so it never switches the quota off: of six users, the first suspended for quota leaves the other five at the N = 6 share, and the next to reach it is suspended in turn (`a_quota_suspension_keeps_every_share_for_the_cycle`). A suspension for quota made in the cycle before does not count (`a_quota_suspension_from_an_earlier_cycle_does_not_count`), nor does any other suspension (`other_suspensions_do_not_count`).
  - *Other departures still lower N* (decided with the latch on 2026-10-09): a suspension at expiry, which `evaluate` itself proposes, by the operator or for an abuse review, and a revocation. Each raises every remaining share at once, and when N was at the threshold it switches the quota off for the rest of the cycle (`other_suspensions_do_not_count` pins the switch-off); only the hard stop then bounds the SIM. So at any moment the shares of the users sharing the budget sum to at most 80 % of the served budget, but a cycle's served bytes can exceed that by what users who left the count for another reason had used before they left, and by what users suspended for quota used beyond their share before the suspension was applied (§13.6). The hard stop bounds the SIM regardless.
  - *Admission still shrinks every share at once* (F4's "÷ N"). Admitting a seventh user mid-cycle lowers the share from 19,047,619,047 to 16,326,530,612 bytes, so a user between the two is suspended at the next evaluation without a warning first (`revoking_users_share_nothing_and_admission_lowers_every_share` pins the share).
  - *Under the pilot cap of 5.* The cap counts only `Active` users (§7), so the automatic quota stays dormant unless users suspended for quota this cycle bring the count to six. While it is dormant only a user's own quota override with the `Suspend` action can suspend anyone for quota, and the count reaches six only if the operator admits or resumes users into the places those suspensions freed: five active and one suspended, or four and two, and so on. The active users then get the share for that N for the rest of the cycle; in the next cycle those suspensions lapse, the quota is dormant again (`five_active_and_one_suspended_for_quota_this_cycle_share_as_six`), and resuming them is bounded by the cap (§13.6). A property test checks the count over every mix of statuses, with suspension instants on both sides of the cycle's start and recorded starts chosen independently of them, with and without the cap (`the_budget_is_shared_by_the_active_and_this_cycles_quota_suspensions`).
- **"Saturated"** means uplink use of at least 85 %, or RTT inflation of at least 200 ms, held for at least 10 minutes. Both thresholds are *(inference)*, calibrated in M8. Saturation looks like a uniformly slow VPN while the probes may stay green *(inference)*, which is why the console tracks RTT inflation and not only throughput.
- **Actions** run through the CLI, from Terminal or the app.
  - Already designed in §13: `exit enable | disable | retry`, `node apply | status`, `user add | export | revoke`, and rotation.
  - New: `user suspend | resume | set-quota | set-expiry | reissue | alias | agree`; `apply --pending | --now` (§13.6); `sim set-plan | set-stop | set-bill-day`; `quota set-factor` (re-records `AutoQuotaPolicy.sim_factor` after M8 measures it, and on any uplink-mode change); `viewer new | list | remove`; `alert setup | test | rotate-topic`; `usage [--by user|node|proto] [--period today|cycle|month|day|hour]`; `top`; `events`; `router pin | set-password | status | capture` (revision 7, §15.6) and `router probe`; `abuse lookup --at <t> --window <d>`, a lower bound (§15.4).
  - `user reissue` draws new credentials for a user and keeps its `UserId` and history.
  - `user agree` records that the user accepted the agreement revision this build ships (`AgreementVersion::CURRENT`), dated the UTC day it is run; it takes neither a revision nor a date, so neither can be mistyped. It is the bookkeeping record `AgreementRecorded` (§7): it keeps the generation, so it makes no node stale; it refuses a revoking or revoked user and a revision lower than the recorded one (`AgreementRegressed`, as after a downgrade), and keeps a record of the same revision as it is (F9, §9.2).
  - `user add` reads the user's label at a terminal prompt, never from an argument, which the shell history would keep (as §15.6 rule 3 does for the router password).
  - `user forget` removes a `Revoked` user at once with every record on the Mac that names it (label, alias, agreement record, usage history, lifetime totals and journal entries), on the user's request, instead of waiting for the 13-month rule (§15.7). The nodes' records of the user expire on their own schedule (§11.5): no request deletes them early. Until the last of them expires (7 days after the end of the month the user was revoked in), a node's `Usage{month}` reply can still name the user's emails, which `aggregate` refuses (`UnknownUser`) and the Mac must not store again: `user forget` keeps the bare opaque id, and nothing else, until then, and the Mac drops entries naming it on receipt; any other unknown id stays an error.
  - `viewer new` imports a public key generated on the phone through `Ed25519Pub::parse_ssh_authorized_key` and prints each active node's host-key fingerprint (`mooring_keys::ssh::SshPublicKey::fingerprint`), so the phone can pin it (§15.9). `alert setup` stores a node's Healthchecks check UUIDs in the Keychain, and the deployment's ntfy topic as well when it sets up the first channel node, and adds the node to `alerting.channels`; the import refuses any check id that is not a version-4 UUID (`InvalidSecret`), never a fallback. `alert test` sends one test notice. `alert rotate-topic` replaces the ntfy topic (§12) in two configuration changes, because the store replaces no secret the state still references (§7): it removes every node's channels, then sets them up again with a new random topic and the check UUIDs it read from the Keychain first. Every channel node then needs `node apply`, and the phone one new subscription; if it stops between the two changes, no node has channels until `alert setup` is run again with the check UUIDs from Healthchecks, where the checks themselves remain. `backup …` still waits for F18.

### 15.4 Freshness and accuracy limits

The console shows these beside the numbers they affect.
- **Cadence.** A node's accounting tick is 60 s (`ACCOUNTING_INTERVAL_SECS`). The Mac polls every 10 minutes (§10.5), or at once on `PollNow`.
- **Splice lag (§11.5).** REALITY+Vision downloads are counted when the connection closes. So (critique C-6):
  - long downloads appear late, and an Xray crash loses the bytes in flight;
  - `last_active`, "active now", the rotation tracker and five-minute bins can miss a user who is streaming over REALITY;
  - `abuse lookup --at T` is a lower bound: it can miss a user who was active at T, or put their bytes in a later bin;
  - quota enforcement can overshoot. Where the stop policy is a hard stop, the SIM meter remains the real-time backstop (§7).

  M10's per-user source addresses would remove the lag *(inference)*.
- **Counters** live in Xray's memory. A restart is detected from `statssys` uptime (§11.5), and a missing counter means no connection since that restart. The accounting canary catches counters that never appear at all (§11.5).
- **The SIM meter** is exact only with the M7's Wi-Fi radio and offloads off (D-4), and it never sees the M7's own traffic (§10.1).
- **Per-user figures** are proxied payload bytes. The SIM factor the console shows is measured (SIM bytes ÷ Σ served bytes, probes included), never assumed. The automatic quotas (§15.3) need a factor before M8 can measure one, so they use the recorded `AutoQuotaPolicy.sim_factor`, §3's estimate of 2100 ‰ until then; the operator re-records it after M8, and on any uplink-mode change (`Separate` is about 1.04×, so a stale 2.1× merely makes the quotas conservative).
- **Time.** Bins are stored by UTC hour. The UK and China are whole-hour offsets from UTC, so "today" converts exactly into Europe/London (the operator) or Asia/Shanghai (the users).

### 15.5 What is deliberately not recorded

Mooring never models, stores or sends any of the following. Anything that leaves the Mac carries opaque ids or aggregates only.
- **Destinations**: domains, IPs, SNI, DNS queries, URLs, and any per-connection or access log.
  - Xray runs with `access:none` and `loglevel:none` (§8.2), and the sing-box instances at `fatal`.
  - Xray's routing-stats stream stays off: its `RoutingContext` carries source IPs, target IPs and the target domain (`app/router/command/command.proto:15-31`).
  - sing-box's Clash API stays off: its `/connections` exposes source IP, destination IP and host (v1.14.2 `experimental/clashapi/connections.go:85-95`).
  - Abuse complaints are answered from time bins only (§15.4).
- **Users' IP addresses**: China IPs, online-IP lists, device fingerprints, request-IP history. `statsUserOnline` stays off (§8.2), for three reasons:
  - safety: a record linking people's IPs and times to a circumvention service could harm them if the Mac or a VPS is seized or compromised *(inference)*;
  - UK GDPR: IP addresses can be personal data (ICO, "What are identifiers and related factors?"), and the household exemption covers only purely personal or household activity (ICO, "A guide to the data protection exemptions", updated 8 Mar 2024), so data minimisation and storage limitation apply (UK GDPR Art. 5(1)(c) and (e));
  - they would be useless: Hysteria2 users arrive from 127.0.0.1, which Xray's online map ignores (§11.5), and Chinese mobile CGNAT makes IP counts a poor proxy for devices *(inference)*.
- **M7 identifiers**: cell ID, IMEI, ICCID, IMSI, phone number, serial number, GPS position, connected clients' link-layer addresses and host names, SSIDs, and WWAN addresses. The router allowlist has no field for any of them (§15.6).
- **SMS text**: never read. The allowlist keeps only an unread count, and the operator reads messages himself in the M7's web UI.
- **Real names**: they exist only on the Mac (§7).
- **Ids in alerts.** Opaque ids and aliases are pseudonymous personal data, because the Mac's labels re-identify them (UK GDPR recital 26). Alert and digest bodies therefore carry aggregates only, never an id or an alias (critique C-12).

What is recorded:
- bytes per opaque user × node × protocol, in time bins;
- last-active times;
- lifecycle events and operator actions.

Retention is decision F7, decided on 2026-10-15 by delegation as its recommended default (§20.2). Users learn of it in the agreement they accept before their first file (F9; `docs/runbooks/user-agreement.md`), so the deletion rules of §11.5 and §15.7 must be built and tested before M8 (M4, M5). "Usage" (用网情况) in the console therefore means bytes and times, never destinations; the operator confirmed on 2026-10-08 that this is what he wants (F16).

### 15.6 Router status (the M7, read only)

**Always available**, with or without an interface on the M7 (source D):
- Ethernet link state and speed;
- the M7 gateway's reachability and RTT;
- direct-probe RTT and loss to each node;
- the carrier's public IP and the carrier check;
- egress rates.

**From the M7 itself** (M2a, 2026-10-13). The MR7450 answers `GET /api/model.json?internalapi=1` (API 2.0). Anonymous, it returns only `session.{userRole, lang, passwordCooloff, secToken, supportedLangList}` and `general.{model, productSKU, InstallID}`, so a login is needed: `POST /Forms/config` with the form fields `token` (the anonymous `session.secToken`), `err_redirect`, `ok_redirect` and `session.password`; the answer's `Location` is judged against the two redirects (rule 9). Logged in, the document has about 651 leaves and carries in plaintext the admin password, the Wi-Fi, guest, auxiliary and cradle passphrases, the IMEI, InstallID, ESN/FSN, ICCID, IMSI, phone number, SMS bodies and senders, cell id, LAC, RAC, physical cell ids and channels, GPS, the clients' addresses and names, the M7's MACs, the WWAN address, the session token and the client's IP. Its clock reads 2016 (`general.currTime`), so no M7 timestamp is used. The allowlist is `NetgearLeaf` (`crates/daemon-core/src/router/netgear/allowlist.rs`, 49 leaves, listed in M2.md): model, API version, firmware and web-app version; data session state, network and data service types (`currentNWserviceType`, `currentPSserviceType`), band (`curBand`), the LTE carriers (`lteBandInfo`: primary, band, downlink bandwidth) and the secondary-carrier count; LTE RSRP, RSRQ, SINR and RSSI and NR RSRP, RSRQ and SINR, where `-32768` means not reported; the network's display name and PLMN, and the SIM's SPN; temperature and thermal state; power state and the battery (charge, state, charging, source, temperature); the WWAN receive and transmit counters (decimal strings); uptime and session time; the Wi-Fi radio, its three access points' status and client count; Wi-Fi and Ethernet offload, UPnP, Analytics and Insight; the unread-SMS count; and, for the login only, `session.userRole`, `session.passwordCooloff` and `session.secToken`. Two of them, the SIM's SPN and the web-app version, may be the empty string as the M7's report of no value: the M7 reported both empty with the SMARTY SIM in the operator's field runs of 2026-10-16 (M2.md; rules 1 and 2). (`session.userRole` may be empty too, as a role that is not an administrator's.) The M2a capture claimed a 5G data service (`5GSUB6`) with every NR reading absent and an LTE primary carrier, so the status keeps the M7's own service types and both sets of readings rather than deriving an access type.

**Rules:**
1. **Allowlist parsing.** On the NETGEAR devices eternalegypt supports, `model.json` carries the admin password (`webd.adminpassword`), the Wi-Fi passphrases, `session.secToken`, and SMS bodies with their senders (`sms.msgs[].text`, `sender`). The source is eternalegypt's `information()`, read 2026-10-08 (critique A-35, C-7). M2a confirmed it on the MR7450, and found more in plaintext (above).
   - `parse_netgear_model_json(&[u8]) -> Result<RouterStatus, RouterParseError>` in `daemon-core` copies only allowlisted leaves into typed fields.
   - Everything else is dropped before anything is logged, stored, or put into status, the journal or a fixture.
   - A raw response is never logged, not even inside an error: a parse error names the field, never the bytes.
   - `redact_netgear_model_json` shares the allowlist (one table, one walker): it keeps exactly the non-secret allowlisted leaves and replaces every other value by a placeholder of its type. An allowlisted value whose shape the walk refuses (an empty or null reading, a number where text belongs, an identifier-shaped text, a carrier list that is not an array) is withheld the same way (an empty string stays `""`) and named by its path in `RedactedModelJson::withheld`, never by its value, so a capture records a state whose leaves change form; the parser refuses the same document. The empty string of the SIM's SPN and of the web-app version is not such a value: their shape admits it (`OrEmpty`), so the redactor keeps it as `""` without naming it, and the parser reads it as none (rule 2). Its result type has no other constructor, so `mooringctl router capture` can write nothing but the redactor's output.
2. **Missing fields are typed errors**, never defaults. With no JSON interface (404) the result is `RouterUnsupported{EndpointMissing}`, and another model or API version is the parser's `Unsupported{leaf}` (reason `Unsupported`); HTML is never scraped. An enum string the M7 has not been seen to report is `Field{leaf, UnknownValue}`; there is no fallback variant. One set is inferred rather than observed: a carrier's downlink bandwidth accepts the E-UTRA channel bandwidths `3MHz`, `5MHz`, `10MHz`, `15MHz` and `20MHz`, spelt as the observed `20MHz` and `10MHz` *(inference: only those two were seen, `10MHz` with the SMARTY SIM on 2026-10-16; 1.4 MHz is left out, its spelling unknown)*; another spelling is still `UnknownValue`, so the inference can make a carrier unreadable but never misread (M2.md). A value the M7 reports as not available is not a missing field: `-32768` is a reading not reported, and the empty string is the SIM's SPN or the web-app version not reported (2026-10-16). The status holds each as `None`, written `null` and shown as "not reported"; the empty string means not reported at those two leaves only (it is also a value of `session.userRole`, a role that is not an administrator's), every other value of theirs keeps the form it had (`Text 1..=32`, digit run ≤ 2, and `Line 1..=64 + LF`, digit run ≤ 6), and an absent key or a `null` is still an error there. *(Revision 9, from the 77 redacted captures of the SMARTY SIM, 2026-10-16 and 17:)* the network service `LteService` (`NetworkService::Lte`) and the data services `4G` (`DataService::Lte`) and `4GPLUS` (`DataService::LtePlus`, the M7's 4G+, kept as its claim: it reported it with no secondary carrier counted) are read, and so is the remote viewer's report (`ReportDataService`). A secondary entry of `wwan.lteBandInfo` with band 0 and the bandwidth `Unknown` together, listed in 2 captures with `wwan.ca.SCCcount` 0, is an unassigned slot *(inference: a secondary-carrier slot holding no carrier)*: it is counted (`LteCarriers::unassigned_slots`), never listed as a carrier, and counts toward the bound of six secondary entries; band 0 with a bandwidth, or `Unknown` with a band, is still refused, and the primary is never one. *(2026-10-22, one capture each:)* the charge source `None` (`ChargeSource::NoSource`) and the power state `Standby` (`PowerState::Standby`) are read. The M7 reported `None` with the battery at 100 % and not charging while it ran on its battery (the operator's statement), where every earlier capture read `QuickCharge`; within two and a half minutes its power state went from `Online` to `Standby`, with its data session still connected. A poll that fails on the Mac (the keychain, the kernel's tables) is `RouterUnavailableReason::LocalFailure` in the daemon's panel (the daemon's own clock readings, outside the poll, stop it instead); a command still reports such a failure as a local error (exit 1).
3. **Read only.** The adapter sends only `GET`, plus one login `POST`, which M2a showed is needed, and only when the anonymous answer is not already an administrator's and reports no password cool-off; never a settings form.
   - Anonymous reads would be preferred, but show only the login fields (M2a).
   - The password goes only in that `POST` body, never in a URL or a log. It is `SecretRef::RouterAdmin` in the Keychain (the legacy login keychain until M5, §12), set with `mooringctl router set-password` (built in revision 7) typed twice at the controlling terminal with echo off, or from stdin with one trailing newline removed; never from argv (critique C-15). It is 1 to 128 bytes of printable ASCII *(inference: the M7's own limits are undocumented)*.
4. **Identity binding (critique C-8).** The client's sockets are bound to the egress interface. The login is sent only when the gateway's link-layer address equals the M7's, as `mooringctl router pin` records it in `~/Library/Application Support/Mooring/router-identity.json` (mode 0600, outside the repository). M2a recorded the address by hand; the command, built in revision 7, was first run against the M7 on 2026-10-14, when its warm-up connection reached the M7 but a plain `cargo` build could not read the neighbour table (rule 10). `pin` reads the kernel's neighbour table (`macsys`, no `arp`); when the table has no address for the gateway yet (no entry, or one still being resolved), or the kernel returns it empty (which may only mean a cold table), it opens one connection to the gateway's port 80, sends nothing, and reads the table again. *(2026-10-23, M7.)* The file's version 2 also records the interface `router pin --interface` named, on which the daemon polls the M7 before a deployment exists (§5.1); a version-1 file is read as a pin without one, and `router pin --interface` records it for the same address without asking again. The check runs after the anonymous `GET` (which reaches the gateway and so fills the ARP cache) and before any secret is sent; the login body can only be built for the `VerifiedIdentity` the check returns. Any other gateway, or an address that cannot identify a device (not unicast, not six bytes, two entries, or the placeholder below), gets `RouterIdentityMismatch` and no password; no address for the gateway is `RouterUnreachable{GatewayUnresolved}`. `02:00:00:00:00:00` is the placeholder Apple's iOS reports in place of a real address: a valid unicast address that every network would match, so it is never pinned (`RouterUnsupported`, exit 7) and never matches a pin, even a pin that holds it; no macOS has been seen to report it. An empty table is read as one the kernel hides from the binary (rule 10) only once the gateway has been reached: by `status` and `capture` at the check, after the anonymous `GET` and before any password is sent, and by `pin` only when its reads both before and after the warm-up connection, which succeeded, returned it empty. A first read that was not empty shows that the binary can read the table, so an empty second read is `RouterUnreachable{GatewayUnresolved}`. If the table still has no address for the gateway after a warm-up connection that failed, the connection's failure is the error; an address the second read finds is treated as one the first read finds, whether or not the connection succeeded (the operator's confirmation is the safeguard); a kernel failure of either read is the error. The hidden table is a local failure (exit 1) whose message names `cargo xtask mooringctl`.
5. **Exactly one endpoint.** M2a chose `/api/model.json?internalapi=1`; `/model.json` is never requested. Trying another at run time would be a silent fallback.
6. **Fixtures** come from the M2a capture through an allowlist redactor (`mooringctl router capture`, which writes only the redactor's output; the first capture was redacted in the operator's browser and re-redacted with `redact_netgear_model_json`, M2.md). The raw capture stays outside the repository. Fixture tests carry a canary in every sensitive leaf, which must never reach status, the journal or a log (§16 L1).
7. **Bounded.** Timeouts are bounded (connect 5 s, each read or write 5 s, 15 s per request, 1 MiB per body), and failures are typed: `RouterUnreachable`, `RouterAuthFailed`, `RouterUnsupported`, `RouterMalformed`, `RouterIdentityMismatch` (§14). The client built in revision 7 (`mooringctl`, std sockets through socket2, no HTTP crate) waits on each read no longer than the request's deadline, reads the head a byte at a time (at most 16 KiB and 64 lines, so no body byte is read before its framing is known), reads `Content-Length`, chunked and close-delimited bodies into one zeroizing 1 MiB buffer that never grows, refuses a declared length past 1 MiB before reading it, keeps cookies in memory for the one command, and never reads the body of the login answer or of a redirect. A read of the endpoint is at most three requests (rule 9), each with these limits. On the device, a 60 s poll for 24 h must not lock out the M7's admin session (M5 acceptance).
8. **Advisory only.** The adapter never stops the exit; the carrier check does (§10.2). It names a cause earlier: offload or a Wi-Fi radio switched on is reported before `OutsideCarrierPrefixes` fires. *(Revision 9.)* Which settings the exit needs off is decided once, in `daemon-core`: `RouterStatus::advisories` lists the Wi-Fi radio, Wi-Fi and Ethernet offload, UPnP (§2) and NETGEAR Insight (a cloud control path, below) when on, never Analytics, which the design asks nothing of. The undeployed document carries the list, `mooringctl`'s summary names it, and the app shows it without a rule of its own; M5's alert machine derives `RouterOffloadActive` and `RouterWifiRadioOn` from it.
9. **Never HTML; one redirect sequence.** The client can request only three targets, all `daemon-core` constants: the JSON endpoint, the M7's session set-up (`SESSION_SETUP_TARGET`, `/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1`) and the login form. It refuses a `text/html` answer to the JSON request: `index.html` carries the IMEI (M2a). Its first `GET` carries no cookie. M2a saw the anonymous JSON answer only after `GET /` had been redirected through `/sess_cd_tmp`, which sets a session cookie. On 2026-10-14 (M2.md) `router capture --anonymous` and `router status` showed that the endpoint is redirected the same way, and failed with `RouterMalformed` (an unexpected status, exit 8), since the client then followed no redirect. Observed that day: the M7 answers a `GET` of the endpoint without a session cookie with `302 Found`, a new `sessionId` cookie and a `Location` of the set-up target on its own address; a `GET` of the set-up target with that cookie with `302 Found`, another `sessionId` and a `Location` back to the endpoint; and the endpoint, with the second cookie, with `200` and the document as `text/plain`. Asked again with the first cookie, the endpoint answers with the first redirect again, so the set-up is required. The client follows exactly that sequence, at most once per read of the endpoint (the anonymous read and the read after the login each): a `302` whose `Location` is exactly `http://<host>` followed by the set-up target, `<host>` written as the `Host` header writes it (the address, and the port unless it is 80), is followed by one `GET` of the set-up target, whose cookies are kept and whose body is never read; that `GET` must be answered by a `302` whose `Location` is exactly `http://<host>` followed by the endpoint; then one more `GET` of the endpoint, which must not be a redirect and is judged as the first (`200`, 401 or 403, 404, any other status). So a read is at most three requests, and the identity check (rule 4) still runs after the anonymous read and before any password is sent. A `Location` is compared byte for byte with those two URLs and the login form's two targets (below) only: it is never requested, and only which of them it matched is kept, with what the login-failed page reports (below). Every other redirect is `RouterMalformed{Redirect{step, status}}` (exit 8), naming the request it answered (the first, the set-up or the retried request) and its status, never a byte of the answer: another 3xx status; a `302` without a `Location` or with one elsewhere (another scheme, host, port, path or encoding, or a relative reference); a set-up answered by anything but the `302` back to the endpoint; a retried request that is redirected again. Two `Location` headers in one answer are an HTTP framing fault. The login answer's redirect is never followed and its body is never read: its status is kept, and its `Location` is judged the same way against the login form's two targets on the M7: the start page (`ok_redirect`) exactly, `http://<host>/index.html`, and the login-failed page (`err_redirect`), exactly `http://<host>/index.html?loginfailed`, alone or followed by `&` and parameters. Of those parameters only `errno` (1 to 4 ASCII digits, read as a number; a value out of that shape is not given) and `errdetail` (when not empty, one of the four fields the login form sends, `token`, `err_redirect`, `ok_redirect` or `session.password`, on an exact byte match, and any other value "another field", of which no byte is kept) are kept, each only when its name is given exactly once; they are split at `&` and at each one's first `=` and never decoded, every other parameter is ignored, and no other byte of the header is kept. The client therefore prints only the form's own field names, which it sends itself: nothing a device echoes back in `errdetail` (the password, the token, a cookie) can be printed. Observed on 2026-10-14 (M2.md): the M7 refused the operator's login with `302`, `Location: http://192.168.1.1/index.html?loginfailed&errno=2&errdetail=session.password`, `Content-type: text/html` and no `Set-Cookie`, and the session read after it was still `Guest`, with no cool-off after four refusals in a row; once the operator had stored the M7's actual admin password, the M7 accepted the login with `302`, `Location: http://192.168.1.1/index.html` (the start page) and a `Set-Cookie` with a new `sessionId`, and the session read after it was `Admin`. A `302` to the login-failed page stops `status` and `capture` at once with `RouterAuthFailed{LoginRefused{reported}}` (exit 5), and nothing more is sent. Its message names what the page reported, "error N on field F", "error N" or "an error on field F": for the field `session.password` it reads that as the stored admin password being wrong *(inference: the M7's own page script ignores both parameters and their meaning is undocumented)* and says to store the password again with `mooringctl router set-password`; for another field, or a number alone, it blames nothing; with nothing given it is the earlier refusal, read as the stored password being wrong, with the same advice *(inference: that page is where the form asks the M7 to send a failed login)*. Any other answer (a `302` to the start page, another status, or a `Location` that is elsewhere, relative or absent) is followed by the next read of the endpoint, whose session decides; when that session is not an administrator's, or the parser refuses that document, the error reports the login answer's status and where its `Location` pointed (the start page, the login-failed page with what it reported, the session set-up, the endpoint, elsewhere, or no `Location`), never its bytes; any other failure of that read (a refused status, a redirect, a framing fault, a time-out) is reported as for any read, without the login answer. Earlier on 2026-10-14 the client, comparing the login-failed page exactly, read that refusal as "elsewhere" and then a session that was not an administrator's (M2.md).
10. **The neighbour table and code signing (measured 2026-10-14, macOS 27.0.1 (26A434)).** On 2026-10-13 the kernel's neighbour table showed no entries to an ad-hoc-signed test binary run from a development shell, nor to `arp` run as that binary's child, while `arp` run from the shell itself, or as the child of a platform binary (`/usr/bin/perl`), listed eleven; the default routes were visible to all of them. That was read as macOS local network privacy *(an inference the 2026-10-14 measurement refuted)*. On 2026-10-14 `mooringctl router pin --interface en9`, a `cargo` build run from Terminal.app, failed with `RouterUnreachable{GatewayUnresolved}` while `arp -n 192.168.1.1` in the same Terminal showed the entry on `en9`; its warm-up connection to the M7 had succeeded, so the network was reachable and only the table read was affected. Measured that day:
   - `sysctl` `NET_RT_FLAGS` with `RTF_LLINFO` returns 0 bytes to such a process: the whole table is hidden, not scrubbed. `NET_RT_FLAGS_PRIV` (10) returns 0 bytes too, and `NET_RT_DUMP` lists the host routes with `RTF_LLINFO` cleared and `sdl_alen` 0.
   - A copy of `/usr/sbin/arp` re-signed ad hoc shows nothing under its default identifier (`arp-copy-<hash>`), and "no entry" when signed `mooringctl` or `mooringctl-020ac5c52e8594c4`; signed `com.bill.mooring.arpprobe` or `com.bill.mooring.mooringctl`, it shows the `en9` entry. The reader's own identifier has to be reverse-DNS (dotted).
   - An ad-hoc-signed process above the reader hides the table from it whatever either identifier is. Apple's `arp`, and the copy signed `com.bill.mooring.arpprobe`, listed 12 lines from the shell and under `/bin/bash`, and none under an ad-hoc-signed copy of `bash` (signed `bashprobe` or `com.bill.mooring.bashprobe`), nor with `/bin/bash` between that copy and the reader. Apple's `arp` showed "no entry" under an ad-hoc-signed `python3`, and the entry under Apple's `perl`. A Developer ID-signed ancestor whose identifier is not reverse-DNS, above the shell these ran from, did not hide it.
   - So the kernel shows the table to a process whose code-signing identifier is reverse-DNS and that no ad-hoc-signed process started, directly or through others *(inference from these cases; the mechanism is undocumented, and public reports likewise describe macOS 27 hiding the ARP table from binaries without a reverse-DNS identifier or bundle id)*. It is not local network privacy: the connection worked, and the terminal's Local Network setting plays no part.
   - Cargo's linker signs every binary ad hoc as `<name>-<hash>` (`mooringctl-020ac5c52e8594c4`) and ignores an embedded `__TEXT,__info_plist` `CFBundleIdentifier` (a C binary linked with one was still signed under its file name), so no build script can fix it. Any later `cargo build` of the package, even one with nothing to compile, replaces the file at cargo's path with a fresh copy of the linker-signed binary in `deps/`, without linking it again (observed on 2026-10-14: a new file each time), so a signature applied there does not last. `cargo xtask mooringctl` therefore builds the package, copies the executable cargo reports to a temporary file, `<target>/signed/mooringctl.<pid>.partial` (cargo does not write `<target>/signed/` while no `[profile.signed]` exists), signs that copy ad hoc as `com.bill.mooring.mooringctl` (`codesign --force --sign - --identifier`), requires `codesign -dv` to report exactly that identifier, and only then renames it over `target/signed/mooringctl`, the path it prints, so no later `cargo build` or `cargo xtask ci` reverts the signature. A step that fails before the rename leaves `target/signed/mooringctl` as it was and removes the temporary file, or reports `PartialNotRemoved` if that removal fails; a run that is killed (Ctrl-C) can leave `target/signed/mooringctl.<pid>.partial` behind, which `cargo xtask clean` removes. The signed copy does not follow later source changes, so the operator runs it as `cargo xtask mooringctl && ./target/signed/mooringctl router …` from the workspace root, in Terminal.app's own shell (xtask has exited by then, so it is not among the copy's ancestors), with no ad-hoc-signed shell or terminal multiplexer in between, and never through `cargo run`: cargo is itself ad hoc signed, and `cargo run` runs the linker-signed binary at cargo's path. It is not a `ci` step: `ci` runs the same steps on every host, ubuntu included, and no test runs `mooringctl` against the kernel.
   - `macsys` states only what the kernel returned: a neighbour dump of no bytes is `NeighbourTableEmpty`, and a dump with bytes but no entry for the gateway, even one none of whose messages is a neighbour entry, is `NeighbourAbsent`. (A Mac with an IPv4 address on an Ethernet or Wi-Fi interface has a permanent entry for that address, as observed on this Mac; nothing relies on it.) `mooringctl` reads an empty table as hidden only once the gateway has been reached, which leaves an entry for it: `status` and `capture` at the identity check, after the anonymous `GET` and before any password is sent, and `router pin` only when its reads both before and after its warm-up connection, which succeeded, returned it empty (the warm-up also rescues a table that was merely cold, and a first read that was not empty shows the table is readable, so an empty second read is `GatewayUnresolved`). It reports it as a local failure (exit 1) whose message names the command, `cargo xtask mooringctl`; the message does not cite this rule. The check is never weakened: an absent entry, an empty table or the placeholder is never a match.
   - The M5 app and its LaunchAgent are signed with a proper bundle identifier and started by launchd, so they should meet the rule *(inference; L6 checks it)*. *(Revision 9.)* The daemon is the process that reads the table, not the app: the app runs only `mooringctl status`, which reads none, so an ad-hoc-signed development app above it hides nothing that matters. A launchd-started agent signed ad hoc as `com.bill.mooring.mooringctl` (with the hardened runtime) is shown the table: on 2026-10-22, once the operator had allowed its keychain read and its local network access (§5.1), its poll passed the identity check and read the M7 (M2.md). On macOS 27.0.1 (26A434) the `macsys` live test against `arp` checks nothing under cargo and nextest, both ad hoc signed, and fails, naming this rule, when its binary alone is re-signed with a reverse-DNS identifier and run from a shell, since its `arp` child then has an ad-hoc-signed parent; on macOS before 27 it compares the two *(inference: the hiding is reported from macOS 27 on)*. A second live test reads the kernel's dump itself and checks how `neighbour_v4` classifies it: `NeighbourTableEmpty` under cargo and nextest on macOS 27.0.1 (§16 L1).

NETGEAR Insight Pro, the cloud management service that lists the MR7450, is not used: it would give a cloud service a control path to the exit's uplink.

### 15.7 Event journal and availability (plan: Mac in M5, nodes in M4)

- **The Mac's journal** appends events: exit transitions and verdicts, gate changes, engine starts and exits, SIM and power changes, router changes, user lifecycle changes, apply results and operator actions. Entries are Level 0, with opaque ids and no destinations. The journal survives `kill -9` of the daemon (M5 acceptance).
- **Each node's journal** holds the watch's condition transitions, gate and hold changes, halts, resumes, commits, engine restarts and boots. The Mac reads it with `Events{since}` (§11.1).
  - *Built 2026-10-22 (M4c).* `/var/lib/mooring/watch/journal.jsonl` (0640), one `AgentEvent` per line. Its only writer is the watch, which journals the differences between what a tick observes and what the journal last recorded: holds recorded or cleared (a hold recorded again, as by a second `GateSet`, is a new recording), a halt, a resume (the marker gone), a commit (the current generation's record committed, once per generation newer than any journaled; a rollback to an older generation commits nothing), a boot (the kernel's boot id changed), conditions raised or cleared, and the gate. So no request handler writes it, an event is stamped with the tick that saw it (at most one tick late), a change undone within one tick is not journaled, and a crash between the journal's append and the view's write repeats that tick's events once. Engine restarts join with the engine figures in M4d.
  - The watch creates the file, and `fsync`s it and its directory, before its first append. An append writes whole lines and `fsync`s them, so a crash leaves at most a last line without its newline: readers ignore it, and the watch cuts it off before its next append. The journal is pruned from its oldest end of the events older than 393 days (the shortest thirteen calendar months) and beyond 16 384 events (down to 12 288), never below its newest event, so a number is never reused. `Events{since}` serves at most `MAX_EVENTS` from `since`, to the ops and viewer roles.
- **Availability** is a daily record of serving, degraded, down and paused seconds. M8 accepts on at least 99 % `Verified` samples over 72 h (§22), and that figure is computed from this record; today nothing durable records those samples.
- Retention is F7 (decided in revision 8): a journal entry that names a user is kept as long as that user's lifetime totals, so at most 13 months after the user is revoked; other entries for 13 months. This is revision 8's reading of F7's default, which the user agreement states.
- **Revoked users** (M5). `UserStatus::Revoked` carries no time today, so M5 records it: `Revoked{since}`, a state-version change whose lift from version 2 sets `since` to the lift's time (which can only delay a deletion, and no real user exists before M8). The apply job removes a user 13 months after `since`, with its label, alias and agreement record, its usage history and lifetime totals, and the journal entries that name it; `user forget` does the same at once on the user's request (§15.3). The agreement states both (clause 4). A revoked user is in no bundle and no export, so its removal is a bookkeeping record (`RevokedUserRemoved{user}`, M5, §7) that keeps the generation and makes no node stale. Any backup kept under F18 must be made again after each deletion, or it keeps what the agreement says is gone.

### 15.8 Alerting (the machine is built; the channels were decided on 2026-10-08, F6)

What exists today: macOS notifications on the exit Mac (§5.1, §10.2). The channels below are decided; their rendering and the dead-man rule are built, and their sending is M4 (agent) and M5 (daemon).

**The machine** (built: `daemon-core`'s `AlertMachine`) runs on the Mac only, as the single debouncer. A node's watch does not run it: `mooring-agent` may depend on `agent-proto` only (§6.1), and the machine's types are the model's. The watch reports its conditions in `StatusV1` (`WatchError`) and journals their transitions (`Events{since}`), and the Mac's machine turns those, with the Mac's own conditions, into notices. The Mac renders each notice to text and a node sends it (below), so the VPS never renders and the machine's debouncing holds for every push notice. Only the dead-man pings are decided on the node.
- It fires on transitions only, deduplicated by (kind, subject). A key is as fine as the facts that can hold at once: an engine's crash loop is about that engine, and several latched violations, degraded reasons or missing canaries are one alert's set, so one observation never holds two conditions with one key.
- Critical alerts repeat every 6 h while active. Warnings are debounced for 15 minutes, a few kinds longer (below). A "resolved" message follows when an alert clears.
- A condition whose source dates its start (a pending reboot, a pending apply, an operator hold, an unreachable node) is held from that start, so a daemon restart does not restart a 24 or 48 h hold.
- Bodies are Level 0 aggregates: a node id and counts, never a label, opaque id, alias, IP address, M7 identifier or SMS text (§15.5).
- Every threshold below is *(inference)* until M8 calibrates it.

**Critical:**
- `MacSilent` (§11.3). It covers the Mac asleep or crashed, the Mac waiting at the FileVault login after a reboot, the M7 without power or signal, and a carrier outage.
- An exit violation, latched (§10.2).
- Router offload active, or the M7's Wi-Fi radio on.
- `SimCapReached`.
- `NodeHalted`, `RollbackFailed` or `GateCloseFailed`.
- `EngineCrashLoop`, on the Mac or a node.
- `HostKeyMismatch`.
- A node gone silent: its agent has failed every poll for 10 minutes, one status-poll interval, from the first failure (`NodeUnreachable`; one lost poll over the lossy uplink is not reported).
- Router thermal level 2 or above, or a router reboot or shutdown.
- `DiskLow` on a node.
- `AccountingCanaryMissing`.

**Warning:**
- `SimWarn`, and a forecast crossing before the end of the cycle (once per cycle).
- The exit `Degraded` for more than 15 minutes.
- `ReachabilitySuspect` and `TargetDegraded`.
- Router: no service; on LTE for more than 30 minutes; thermal level 1 for more than 30 minutes; RSRP below −110 dBm, sustained; firmware changed (re-run the D-4 checklist); unread SMS; the M7's counter and the SIM meter more than 5 % apart over a day.
- Users, as counts only: at 80 % of quota, suspended, expiring within 3 days, expired.
- Capacity saturated for 30 minutes or more in the China evening.
- `ExitFlowCapHit` growing.
- `ClockUnsynced`; `RebootPending` for more than 24 h; an apply pending for more than 48 h.
- An Operator hold active for more than 24 h, because it suppresses `MacSilent` (critique D-4).
- `ForeignNetworkAttached`.

**Channels (decision F6, 2026-10-08).** The operator chose the default that revision 5 recommended:
- **Push through ntfy** (`https://ntfy.sh`), on one random topic for the deployment, random because ntfy's docs say topic names are public. The topic is `SecretRef::AlertTopic` (Keychain account `alert/topic`): `Password` material, 32 random bytes as 43 base64url characters, so 256 bits against F6's minimum of 128. It is assumed to fit ntfy's topic rule `[-_A-Za-z0-9]{1,64}` *(inference from the ntfy server's topic pattern; verified in M4)*. The operator's phone subscribes to it, and every channel node sends to it, so a second node needs no new subscription, and neither does a rotation that gives the replacement or the standby its channels before the last channel node is retired (§13.4). The deployment references it while at least one node has channels: it is written before the state that adds the first channel node and deleted only after the commit that leaves none (§7). A rotation in the other order, or replacing the topic after a compromise or a lost phone (§12, `alert rotate-topic`), therefore needs one new subscription.
- **Healthchecks.io dead-man checks** on the free plan, whose account the operator creates himself: per node, a node check and a `MacAlive` check, each a `Uuid` Keychain item (`NodeDeadManCheck`, `NodeMacAliveCheck`) taken from its ping URL `https://hc-ping.com/<uuid>`. Healthchecks' check codes are assumed to be version-4 UUIDs *(inference from its `Check.code` default)*; `alert setup` refuses any other form (§15.3). Healthchecks alerts by its own e-mail when pings stop, so Mac loss is reported even if ntfy fails (critique D-3). Two nodes use four of the free plan's 20 checks.
- **The dead-man rule** (built: agent-proto's `dead_man_pings`, `crates/agent-proto/src/deadman.rs`). A node decides from its own `StatusV1` alone, so the rule lives where the agent can use it while the Mac is gone. It pings `Node` while the watch is healthy: its latest tick is at most `WATCH_STALE_SECS` (30 s) old and no active condition stops its work (`WgReadFailed`, `NftFailed` or `StateWrite`; an exhaustive match decides every watch condition, and the others are reported by push notices instead). It pings `MacAlive` while the Mac's handshake is at most `HANDSHAKE_MAX_AGE_SECS` (180 s) old, the gate's own freshness rule; an Operator hold does not stop it. A clock that stepped back, or no handshake, pings nothing for that check: silence is what makes Healthchecks alert.
- **A daily digest at 09:00 UK time** (`AlertSettings { digest_at: 09:00, digest_zone: EuropeLondon }`), rendered on the Mac and sent by the node's timer, `OnCalendar=*-*-* 09:00:00 Europe/London` (M4). A digest time must be 02:00 or later (`WallClockZone::earliest_daily_time`; `DigestTimeTooEarly` otherwise): the UK's clocks change at 01:00 UTC, so 01:00 to 01:59 does not occur on the last Sunday of March and occurs twice on the last Sunday of October, and from 00:00 to 00:59 in summer the UTC date, which titles the digest, is still the day before. From 02:00 to 23:59 a time occurs once every day, on the date the digest names, whatever systemd does with a skipped or repeated local time.
- **Level 0 only**: node ids, counts, kinds, byte totals, dates and UTC times, never a label, opaque user id, alias, IP address, M7 identifier or SMS text (§15.5, critique C-12).

**The notices** (built: `daemon-core`'s `notify::alert_message(&AlertNotice)` and `notify::digest_message(&MacStatusV1)`, each returning agent-proto's `NtfyMessage { title, body, priority, tag }` or a typed `NotifyError`).
- **The grammar** (`crates/agent-proto/src/notice.rs`), shared by the Mac that renders and the node that sends: a `NoticeTitle` is 1–128 bytes of ASCII letters, digits, spaces and `, : ; ( ) / % + < > = -`; a `NoticeBody` is 1–2048 bytes of the same plus line feeds, with no line feed or space at either end and no empty line. It has no `.`, `@`, `_`, quote, `#`, `*` or non-ASCII character, so a dotted IPv4 address, a domain name, an e-mail address or a name in another script cannot be written; a renderer that tried would fail with `NotifyError::Text`, never send.
- **An alert notice:** the title `Mooring {critical|warning} {raised|reminder}: {Kind}` or `Mooring resolved: {Kind}`; the body is the alert's key (`NodeHalted on lon1`), a payload line for the kinds that carry more than their key (counts, a projected date, a thermal level, an RSRP in whole dBm rounded down, so never above the reading, free disk, a start time), and `active since {time}` or `cleared at {time}, active since {time}`. Times are UTC minutes (`2026-10-12 08:15 UTC`), because the core has no time-zone database. A critical alert is raised at priority `Max` and reminded at `High` with tag `RotatingLight`; a warning is `Default` with `Warning`; a resolution is `Low` with `WhiteCheckMark` *(the tag names are ntfy emoji short codes, an inference verified in M4)*.
- **The digest** (priority `Low`, tag `BarChart`): the title `Mooring digest {UTC date}`, then one line each for the exit's phase and since when; the SIM bytes used against the hard stop (or, without one, the fair-use line), the warning and the cycle's first day, marked `lower bound` when the meter may miss bytes; the forecast and the first threshold projected to be crossed; users active, suspended and revoking; bytes served this cycle; open alerts by severity and kind; and nodes by count (every node row, retired ones included), how many are behind the current generation and how many are unreachable. Amounts are decimal and rounded down to the largest unit they reach (`42 GB`). It names no user and no node.
- Tests render every alert condition for every notice event through the grammar and pin exact texts. A canary test checks that no notice or digest rendered from the status scenarios holds any of their user ids, aliases, IPv4 or link-layer addresses, the router's carrier name or firmware, a label of any fixture deployment, or a run of five or more digits.

**Transport (open, M4).** The Mac report carries no text by design (§15.9), so the rendered notices need their own ops request (`PutNotices`) and an outbox on the node, which `mooring-alert.service` drains (§5.2). The Mac re-renders the digest with each report push, and the node's 09:00 timer sends the newest. Still open for M4: which node sends the Mac's own notices (sending from both duplicates them), and the fixed Level-0 line a node sends when the Mac's digest is stale, which must not make the VPS render. The unit needs no owner-guard change: the output chain's policy is accept, and the guard constrains only the two engine users (§8.5). Mooring's Rust code has no TLS stack (§6.3), so the node sends with curl, as `TargetCheck` already does (§11.7).

### 15.9 Remote viewing (decision F5, 2026-10-08)

The operator decided on 2026-10-08 to adopt remote viewing as proposed here: a viewer role on each node for the operator's phone, read-only plus an emergency stop.

**Constraints:**
- no inbound connection to the Mac (§1.2, §18);
- no web panel and no new listener (§18);
- never over Janet or eduroam (P0-2, §10.2; F15). A remote client runs on a non-university path: the phone on mobile data with Wi-Fi off, or the research computer tethered to that phone (critique C-1).

**The role** (built: `Role::Viewer`, `crates/agent-proto/src/role.rs`; §11.1):
- The viewer reads `Status`, `Usage`, `UsageSeries`, `Events` and `MacReport`.
- It may close a gate with an Operator hold, as an emergency stop, but never reopen it: `GateSet` is accepted from it only with the Operator reason (`Role::may_close_gate_for`; otherwise `GateReasonNotPermitted`). `ClearHold`, `Apply`, `Shutdown`, `Resume` and every other request stay ops-only, so resuming is done from the Mac.
- **An unprivileged account** (critique C-9). The bootstrap and ops roles are lines in root's `authorized_keys`, so a viewer key there would run the agent as root from a phone. The viewer instead logs in as `mooring-view` (host profile 2, §8.6): its keys are in `viewer_authorized_keys`, root-owned inside the generation directory, and sshd forces `serve-ssh --role viewer` for it. In M4 its handler reads the status, usage and report files and hands `GateSet{Operator}` to the watch through a narrow request file under `gate.lock` (§11.3).
- **The key pair is generated on the phone**, and only its public key is imported, through `Ed25519Pub::parse_ssh_authorized_key` (`crates/model/src/keys.rs`), into a `Viewer` record (§7). No private key is written to a file that must then reach the phone. Phone apps export `ssh-ed25519 <base64> <comment>`, and that parser refuses a comment, so M5 needs an explicit, comment-aware import, never silent stripping *(open, M5)*.
- **`viewer new` prints each active node's host-key fingerprint**, so the phone can pin it (§15.3).
- **A lost or seized phone:** `viewer remove` its key, which every node's next `node apply` drops, and replace the ntfy topic the phone is subscribed to (`alert rotate-topic`, §12).

**The report** (built: agent-proto's `MacReportV1`, `crates/agent-proto/src/report.rs`; the projection `daemon-core`'s `report::project(&MacStatusV1)`). The Mac pushes it to each node with `PutMacReport` on the ops role, and the viewer reads it back with `MacReport` (§11.1).
- **It holds:** the exit's phase and since when; the SIM meter (cycle start and end, received and sent bytes, accuracy, the warning, the hard stop, the plan's line, and the forecast's daily average and projected total); the router's radio (data service type, band, LTE RSRP, RSRQ, SINR and RSSI and NR RSRP, RSRQ and SINR, in tenths) and temperature, or when it was last polled; the uplink's rates and saturation; every user who is not revoked, by user id, with status, cycle bytes and last activity; and the open alerts by kind (`MacAlertKind`, the 39 names of the Mac's alert kinds, mapped by an exhaustive match), severity, node and start.
- **What the grammars refuse, and what keeps the rest out.** The report has no free-text field: every string in it is a closed-enum name, a `ReportUserId` (exactly the model's `UserId` rule, 10 lowercase base32 characters, so an IMEI or ICCID cannot pose as one) or a `NodeName` (exactly the model's `NodeId` rule), and its band number is a `ReportBandNumber`, 1..=999 (exactly the router's `BandNumber` rule, compared value by value in `daemon-core`), so a physical cell id above 999 or a tracking-area code cannot pose as a band. So text with a space, a capital, a `.`, a `@` or a non-ASCII character cannot be decoded into any slot: canary tests put an IPv4 address, a domain, an IMEI, an ICCID, a name with a space, a CJK name and an SMS text into every string slot of a valid report, map keys included, and numbers from 0 and 1000 up into the band slot, and every decode fails. The grammars are not the whole guarantee: a lowercase one-word string (a label such as `phone`, a carrier name written in lowercase) fits a `NodeName` slot, a ten-letter base32 word fits a `ReportUserId` key, and a small number fits a numeric slot. Those are kept out by the projection, which fills every slot from a typed value of the same meaning, never from text, and whose tests plant such canaries (`alicesmith`, `tablet`, `phone`, `laptop`, `phone0`) in the SIM and network names, the firmware and web-app versions and the interface name and find none in the report. Labels never reach a `MacStatusV1`, which has no field for one.
- **Dropped by construction (the redaction list):** latches and violation evidence (addresses); the egress facts (interface name, link-layer address, LAN address); the carrier check (the line's public address); engine processes; power and sleep; foreign networks; the details of a degraded or down exit; the router's SIM and network names, PLMN, firmware and web-app version, counters, carrier list, Wi-Fi and settings, SMS count, power, thermal state, uptime and session time; users' aliases, node sets, quota and expiry states, per-node activity, day, month and lifetime figures and shares; revoked users; and the node rows (a viewer reads a node's own `Status`).
- **Invariants** (`MacReportRule`, checked on construction and on decode): at most 1024 users (`TooManyUsers`) and 256 alerts (`TooManyAlerts`), and every user's cycle bytes present exactly when usage is available (`UsageMismatch`).
- **Not in it yet:** the "last 50 events" of the proposal, which wait for the Mac's journal (M5). `MacReportV1` will change before protocol 1 ships. A node also receives the other node's per-user cycle totals, which F5 accepted. The agreement's clause 4 lists what the report holds per user, so any per-user field or event added to it needs a new agreement revision (F9).

**Open (M5):** whether one JSON request line over SSH works from a phone client, for example an iOS Shortcut that reads JSON, is unverified; a text mode may be wanted.

**Rejected:**
- Tailscale, ZeroTier and reverse SSH tunnels: each creates an inbound path to the Level-3 Mac.
- A Telegram bot: it puts data and a credential on Telegram. Existing panels show the risk: 3x-ui (v3.9.0) keeps clients' IPs in a database table, and its bot sends database and config backups to the admin chat; Marzban's login report sends the attempted password and the client IP to Telegram (`app/telegram/handlers/report.py:196-210`).
- Anything over the campus network.

### 15.10 Logs

- **Xray:** `access:"none"`, `loglevel:"none"`, `dnsLog:false`, `maskAddress:"full"` at run time. `none` turns off both the error and the access log (Xray v26.9.30 `infra/conf/log.go:57-59`). At `warning`, Xray would log failed DoH lookups and resolutions at ERROR with the queried domain (§8.2), and `maskAddress` masks IPs only. Removing `disableFallback` also removes the per-lookup domain warning, and the L4 canary includes domain names. Start-up failures still reach stdout (`main/run.go:84,95`). The L2 and stage-validation copies run forced to `warning` (§11.2 step 3), so configuration warnings still fail validation.
- **All three sing-box instances:** `fatal`. Validation uses warn-level copies (§11.2, L2).
- **journald:** persistent, 200 MB, 14 days.
- **Daemon:** lines in `~/Library/Logs/Mooring/daemon.log`, rotated at 2 × 5 MiB. *Built 2026-10-23 (M7):* the daemon opens the log itself (mode 0600 in a 0700 directory) and points its standard error at it (`macsys::redirect_stderr`), since launchd gives an agent registered with `SMAppService` no log; each line is `<UTC time> mooringctl daemon: <event>`, written when the daemon starts and when an outcome changes, read by the operator as it is (the planned JSON lines were not adopted); once the file holds 5 MiB, the next line starts a new file and the full one becomes `daemon.log.1`, replacing the one before; the daemon's last error, which `main` prints, and a panic's message land in it too. Secret types render as `<redacted>`; destinations are never logged; engine stderr is kept in a 200-line in-memory ring for crash diagnosis and scrubbed as described in §12. It names no user (no opaque id, alias or label); what concerns a user goes to the journal (§15.7), which the agreement's deletions reach. *Corrected 2026-10-24:* with a deployment, an egress that does not resolve is a failed poll of the M7, logged like any other ("router poll failed: the M7 is unreachable: the exit's interfaces do not resolve: …", naming the fault), and a node's first failed poll names the fault too. Until then the router panel turned unreachable without a line, so the log could not say when or why the M7 had gone, and the line of its recovery followed no failure.

**Not included:** metrics servers, dashboards, and automated reachability probing from China. Remote log shipping stays excluded. Beyond each node's own accounting, the only operator data that leaves the Mac is the report of §15.9 and the Level-0 notices of §15.8, which F5 and F6 adopted on 2026-10-08; their sending is M4 and M5.

---

## 16. Test lanes

Every lane runs through `cargo xtask lane <name>`. The gate everywhere is zero errors and zero warnings:
- clippy and `cargo deny`, with warn-level checks promoted to deny;
- Swift via `.treatAllWarnings(as: .error)` (SE-0480, swift-tools 6.2; confirmed in M0) and `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` in Xcode;
- engine validators, with no WARN or ERROR lines on warn-level copies.

Every new invariant test is mutation-checked:
- `cargo mutants --in-diff` runs per change on `model`, `render`, `export`, `daemon-core` and `agent::watch`, and every skip needs a reviewed justification;
- the config-ablation matrix covers rendered data.

| Lane | Where | Content |
|---|---|---|
| **L0 static** | hosted CI (ubuntu, macos) and local | `cargo xtask ci`: fmt, clippy, deny, graph-check, kinds-coverage, deny-skips (the exact-skip check), acceptance (§9.3), nextest, doc tests; plus govulncheck, `xcodebuild`, `xcrun swift test`. The macOS-only crates build everywhere: on another target `macsys` is empty (`#![cfg(target_os = "macos")]`) and `mooringctl` is a stub that says it runs only on macOS and exits 1, their dependencies are macOS-only, so ubuntu runs the same `--workspace` steps |
| **L1 unit/property** | same | newtype bounds (proptest); RFC 7748 X25519 vectors; key encodings; OpenSSH encoder against `/usr/bin/ssh-keygen -y -f` and `-l`, and certificate properties, DER and SPKI against `/usr/bin/openssl` at test time (these tool checks compile only on macOS); render invariants and goldens; export goldens; YAML round-trip (saphyr); acceptance file = shape enumeration × client line, and manifest client lines = enumerated client lines (xtask unit tests; `cargo xtask acceptance` in L0); agent-proto framing, limits, reply-size bounds, frozen-core goldens and protocol-1 goldens; watch gate, holds and drain logic (including a handshake inside the drain window and in the same second); daemon-core state machine with a fake clock, engines, probes and power (wake then sleep within 3 s, Dark Wake transitions, the carrier IP changing between probes, Retry after a violation, latch persistence across restart); SIM arithmetic across counter resets; store CAS, atomicity and migrations; error → UI mapping; *(revision 7)* the MR7450 allowlist parser and redactor (the allowlist is the M2.md table; sentinels; every unknown enum string; a canary in every sensitive leaf never reaching the status, its encodings, the redactor's output or an error; the fixture is a fixed point of the redactor; the status unchanged by any non-allowlisted leaf); the router HTTP client against an in-process loopback stub reached through `lo0` with IP_BOUND_IF (Content-Length, chunked and close-delimited bodies, truncation, oversize refused before reading, a silent and a drip-feeding server, every framing fault, 401/403/404/500 and `text/html`, the M7's session set-up as observed on 2026-10-14 (exactly three requests, the set-up's cookie replacing the first, the `text/plain` document, the redirects' bodies never read; for `capture --anonymous`, and for `status` through the identity check, the login and an authenticated read that goes through the set-up again), every other redirect refused at the request it answered, with exactly the requests made and no login (a `Location` on another host, port, path, scheme or encoding, a relative one, none or two; another 3xx; a set-up not answered by the redirect back; a retried request redirected again), the `Location` judged against the `Host` rendering of the M7 on port 80 (the set-up's two URLs and the start page exactly, the login-failed page exactly, alone or followed by `&` and parameters), a login answered by a `302` to the login-failed page stopping `status` and `capture` with no request after it and the password sent once, both without parameters and as observed on 2026-10-14 (with `errno=2&errdetail=session.password` and no cookie), the error naming the page's `errno` only when given once in its shape and its `errdetail` only as one of the four fields the login form sends, any other value (a near name, an encoded one, or a token, password or cookie echoed there) as "another field", and blaming the password only for `session.password` (empty or repeated values and other parameters never kept or printed), its prefixes (`?loginfailedX`, `?loginfailed2`, `/index.htmlx`, a second `?`, a relative or other-host URL, the start page with a query) judged elsewhere, every other login answer (another status, naming what the login-failed page reported; a `Location` to the start page, elsewhere, relative or absent) left to the session read after it and named in the error, a non-admin session, a cool-off, identity mismatch, the placeholder `02:00:00:00:00:00` (pinned or not), an unresolved gateway and an empty neighbour table after the anonymous `GET` (hidden from the binary) with no password sent; `router pin` reading the table only once when the first read finds an address, else warming an absent or incomplete entry or an empty table with one connection that sends nothing, pinning what the second read finds (after a failed connection too), calling the table hidden only when both reads were empty and that connection succeeded (one empty read is `GatewayUnresolved`), returning the connection's failure when the table still has no address, a kernel failure of either read as the error, and never pinning the placeholder; the exact request bytes, the password, token and cookies only where they belong; the binding itself: an index no interface has cannot be bound, and a socket bound to `en0` never reaches the loopback stub; exit codes 5, 7 and 8 from documents the parser refuses; a capture of a canaried administrator's document that must differ from what was served, and one that withholds refused values); the terminal's bounded line reading and its yes/no answer; `cargo xtask mooringctl`'s build and `codesign` arguments, the executable it reads from cargo's messages, its check of the identifier `codesign -dv` reports, and, with cargo and `codesign` stood in for, the order of its steps (host, build, executable, target directory, copy, sign, check, rename, message), its refusal of relative paths from cargo, a missing executable, a file in place of `<target>/signed`, and failures before the rename that leave `target/signed/mooringctl` as it was and remove the temporary file, or report `PartialNotRemoved` when that removal fails (xtask unit tests); `macsys` route and neighbour parsing from messages built byte by byte, the live tables against `netstat` and `arp` as test oracles (the `arp` comparison checks nothing on macOS 27.0.1 (26A434) under cargo and nextest, both ad hoc signed, §15.6 rule 10), and the live neighbour dump as `neighbour_v4` classifies it (`NeighbourTableEmpty` there); the echo guard on a pseudo-terminal; and with M5 the journal and `daemon.log` (§15.6); the foreign-network check over typed snapshots of interfaces and routes (§10.2), tested here because L6's `bridge100` is the lab egress and is exempt; the alert machine's debounce, repeat and deduplication with a fake clock; the SIM forecast and bill-day cycles |
| **L2 engine-check** | CI, plus a Debian 13 VM locally | `xray run -test` (warn-level copies) and `xray convert pb -debug -type` semantic assertions; `mooring-hy2 check` (warn-level copies); `nft -c -f`; `wg-quick strip`; `cloud-init schema` inside Debian 13; `xray x25519 -i <priv>` equals the Rust public key; `sing-box check` of every sing-box JSON export under upstream and CFM-patched 1.14.1 and 1.14.2 (the `support_x25519mlkem768` shapes only under CFM-patched 1.14.2, §9.3); provenance via `go version -m`; **negative controls that must trip each gate:** a REALITY serverName containing "apple" (Xray warns, v26.9.30 `infra/conf/transport_security.go:163-169`), a deprecated sing-box field, a stale golden, a shape missing from the acceptance file, an undeclared crate edge |
| **L4 netns e2e** | hosted ubuntu amd64; Lima Debian 13 arm64 on this Mac | Namespaces: `cn` (CFM-patched clients fed the exports verbatim, plus Clash JSON twins); `vps` (Xray, Hysteria2, kernel `wgexit`, nft, watch, reflector); `vps2` (a second node, for isolation); `mac` (Linux build of `mooring-exit`/`mooring-probe` driven by the real `daemon-core`; `cell0` egress, plus a `home0` decoy holding the default route); `inet` (routing, a TLS 1.3 + h2 target, echo servers, a DoH stand-in whose test CA reaches Xray only through `SSL_CERT_FILE`); `prober` (active probing); `tc netem` for impairments. Cases are listed below. |
| **L4-ablation** | same | Permanent matrix; each entry names the test that must fail: drop the gate rule; unscope the hop redirect; delete table 77; remove `accept_local`; unbind `exit`; remove the owner guard; remove each deny class in each layer; raise the engine log level to info (the canary must fire) |
| **L5 vm-agent (release)** | hosted CI: QEMU/KVM amd64 (`test -c /dev/kvm` or fail), Debian 13 genericcloud with a NoCloud seed made from the **rendered** user-data, and the exact shipped linux-amd64 artifacts | adopt (including host-key regeneration and proof of the forced command), apply, unchanged re-apply, confirm, rollback, reboot (gate closed until live); failure injection listed below |
| **L5-lab** | this Mac: Lima `vz` arm64 VM with `vzNAT` and the lab agent build (the lab host profile keeps Lima's own SSH user; the release profile is tested only in CI L5) | the same flows on arm64; a host for L6/L7 |
| **L6 host-mac (lab)** | this Mac | Topology: the Mac's egress and uplink are both `bridge100`, the host side of the vzNAT network, which does not hold the default route. The node address and lab "internet" /32s are allowed only through the typed `cfg(feature="lab")` `LabAllowance{vps4, internet: Vec<Ipv4>}`, applied identically in the Xray render, the Mac render, preflight (`carrier_prefixes` = the lab /24) and export. The darwin `mooring-exit` re-asserts every other SPECIAL_V4 class. Checks: selector resolution; IP_BOUND_IF probes; `Verified` verdicts; `kill -9` of the daemon → launchd restart with no orphaned engine and the latch intact; stopping the VM (which removes `bridge100`) → `Down(EgressInterfaceAbsent)` within 4 s; data-protection Keychain read after reboot and login; sandbox spike; **T-deny-mac on darwin** (VM root originates over `wgexit`; a canary listener on the Mac's 127.0.0.1 records zero accepts); handling of the Local Network privacy prompt *(inference that it appears)* |
| **L6-bypass** | this Mac, **user present** (CFM prompts, `sudo tcpdump`) | Wi-Fi `en0` stands in for the physical interface: `curl --interface en0` and bound probes to a public host with CFM's TUN on, in system-proxy mode, and with both off; utun shows zero packets |
| **L7 lab-cfm** | this Mac, **driven by the user**. CFM 0.4, then 0.5, sequentially; the user is warned before every step that opens windows or raises prompts | Import every lab-feature shape by file. Run CFM → VM → `wgexit` → the real daemon → `bridge100`. Record `cfm-acceptance.toml`, including build numbers and the importer digest. This lane does **not** prove the TUN bypass (§10.4). |
| **L8 field** | the real M7, the SMARTY line and a London VPS | measurements, a 72 h soak, peak-hour acceptance by a trusted user in China, and an offload drill (enable M7 Wi-Fi offload → `OutsideCarrierPrefixes` and the engine stops within 30 s) |

L6 and L7 run the signed lab bundle (`xtask release --lab`, signed by the user), never unsigned dev builds, so the entitlement, Keychain and sandbox paths are the shipped ones.

**L4 cases:**

| Test | Assertion |
|---|---|
| T-reality / T-hy2 (TCP and UDP) | Both client versions get through. The echo server sees the `cell0` address, never `home0` or a VPS address. Hysteria2 hopping is proven by at least 2 distinct server destination ports in conntrack over a run longer than 30 s. |
| T-large | 200 MB in each direction, sha256 equal, with the `cell0` path MTU set to 1340 |
| T-deny | Refused through the clients: 192.168.1.1, 127.0.0.1, 10.77.k.2, 10.77.k.1:22, 10.77.k.1:10443, a domain resolving to 10.77.k.1, 100.64.0.1, 224.0.0.1, an IPv6 literal, tcp/25, a domain resolving to 10.x, every node IP (including a two-layer detour chain through the same node) |
| T-deny-mac | From the `vps` namespace as root, originating directly over `wgexit` and bypassing Xray: each SPECIAL_V4 class; 10.77.k.2:<port> with a canary listener on 127.0.0.1 in `mac` (zero accepts); 224.0.0.1; tcp/25; more than `udp_nat_max` UDP flows (bound enforced) |
| T-deny-vps | A test-only render with the Mac deny list removed proves the Xray layer and the owner guard on their own |
| T-no-leak | An exact counter (`meta skuid mooring-xray`, oif eth0, destination = echo servers) stays **0** for the whole suite, including variants with table 77 deleted, `ip link del wgexit` while serving, and Xray started before `wgexit` exists |
| T-fail-closed | Stop `mooring-exit`. Within 3 × keepalive plus one tick, new connections to IP literals fail within the measured bound (about 1.0–1.5 s plus RTT); the cold-cache domain bound is recorded; the leak counter stays 0 |
| T-drain | `GateSet` → flows that send get RST within 1 s. The gate reopens only after a handshake that changes the recorded value. |
| T-reflector | In-chain probes return the `cell0` address. Negative controls: unbound VPS exit → `EgressIsNodeAddress` plus `Shutdown`; Mac egress on `home0` (outside the carrier prefix) → `OutsideCarrierPrefixes`; Mac egress on a second `cell0` pool address (Paired) → `EgressMismatch`; without `accept_local` → `NodeProbeFailed` (mutation check) |
| T-nat | Profiles: (a) SNAT address swap between the direct and in-chain probes → inconclusive, then `Verified` or `CarrierAddressUnstable`, never a violation; (b) conntrack UDP timeout below the keepalive; (c) two-address arbitrary pooling (expected verdict stated for Paired and Unpaired); (d) 200 s of 100% loss, then recovery; (e) a SNAT port remap → traffic resumes within 2 × keepalive |
| T-wg-port | A new WireGuard tuple on 27820 is never redirected to Hysteria2 |
| T-camo / T-reality-fallback / T-hy2-silence | Bytes on port 80 and UDP/443 match the target's, unchanged while the Mac is down. An unauthenticated client or wrong shortId gets the target's real certificate chain. Random UDP, and QUIC without salamander, to 61000-62999 and 27820 get zero bytes back. |
| T-revoke / T-node-isolation / T-retire | Revoked credentials are refused on both protocols; lon1 credentials are refused on `vps2`; a retired node's endpoint is gone from the Mac config |
| T-accounting | Per-user bytes within ±2% |
| T-flow-cap | N+1 flows → fast typed refusal and `ExitFlowCapHit`; other users keep working |
| T-exhaust | 60k distinct source ports to UDP/443 and a SYN flood on 27900 from `prober`; REALITY handshakes keep succeeding and preflight still passes; Xray memory stays below `MemoryMax` |
| T-log-canary | Canary hosts, domains, client IPs, UUIDs and passwords never appear in journald, engine stderr, `status.json`, `daemon.log` or SSH error JSON, and neither journald nor `daemon.log` holds a user id, alias or label. Driven paths include a bad UUID, a bad shortId, a bad Hysteria2 password, a denied destination, a DoH failure, an invalid engine config containing canary secrets, and an agent `StageValidation` containing canary secrets. Also confirms Xray's run-time level `none` (chosen in M1 from the pinned source, §8.2) and checks that Xray at `none` and sing-box at `fatal` still surface start-up errors. |
| T-dns | Zero udp/tcp 53 or 853 packets from the `mac` namespace |
| T-startup-smoke | A 10 s run of every engine at warn level shows no WARN or ERROR lines |
| T-xray-lock | Documents the pin: unmodified Xray v26.9.30 (REALITY `8cdf7bf9`, test-only) rejects a CFM client without the hybrid share; the shipped build (REALITY `e1986a4`) accepts it both with and without `support_x25519mlkem768`, and the hybrid case negotiates X25519MLKEM768 against a target that prefers it |
| T-impair (recorded, not gated) | 5G profile (40 ms, 16 Mbit up, 0.5% loss) and China-leg profile (280 ms, 1–3% loss), using `tc netem` only, never host dummynet. Measures TTFB, page load, bulk rate, loaded latency and Jain fairness across 3 users. A/B tests set the defaults for `block_quic`, `tcp_notsent_lowat` and `bbr_profile`. |

**L5 failure injection.** Each case must produce the named result:

| Injected failure | Expected result |
|---|---|
| Corrupted blob | `BlobHash` |
| Invalid Xray config | `StageValidation` |
| Port 443 taken | `HealthGate` → `RolledBack` |
| Broken previous generation | `RollbackFailed`, with services stopped |
| SSH killed mid-transaction | The transaction completes, and `TxnStatus` reports it |
| No `Confirm` sent | `RevertedUnconfirmed` |
| nft rules that would drop SSH | Revert by timer |
| Transaction unit killed after the swap | Revert by timer; `Apply` is `Busy` until then |
| Reboot while awaiting `Confirm` (nft rules that would drop SSH) | `txn-recover` reverts at boot → `RevertedUnconfirmed`; SSH works again |
| Retry of a generation whose transaction rolled back | Arms its timer again and reaches `AwaitingConfirm` |
| Renamed NIC | `HostFactsChanged` before staging |
| Broken agent binary | `AgentSelfTestFailed`; a broken-but-passing agent is reverted by the timer |
| `wgexit` deleted | `WgReadFailed`, gate closed, no leak |
| Watch killed repeatedly | Gate closed by `ExecStopPost`; the watch keeps restarting |
| `Shutdown`, then reboot | Engines stopped, gate closed, `Apply` → `NodeHalted` |
| Hold, then watch restart and reboot | The hold persists |
| Retry after `EgressViolation` | Reaches `Verified` |
| Disk full | `StateWrite` |
| Clock skewed by 5 minutes | REALITY failures are visible in the probes |
| Target sends a truncated record (PR #36) | `EngineCrashLoop` on the unmodified build; no crash on the e1986a4 variant |
| `RevokePending` with the VM stopped | An explicit retry completes it |
| Host profile N → N+1 | Converges |
| First Apply on a fresh VM | Passes, because the certificate is inline |

---

## 17. Decisions and rejected alternatives

| Topic | Chosen | Rejected, and why |
|---|---|---|
| Tunnel | WireGuard. The Mac dials out with a userspace sing-box endpoint (no privileges). | **Xray VLESS reverse:** mux.cool head-of-line blocking (`common/mux/client.go:347-370`), versions in lockstep (PR #5101), a bearer bridge UUID. **frp:** a third engine, with yamux head-of-line blocking. **QUIC reverse:** none is stable. **Tailscale:** needs a coordination server. |
| Location | London primary; standby on another ASN | **Hong Kong or Japan premium as the only entry:** a long Reno leg over 5G. A China-near relay is M10. |
| VPS steering | SO_BINDTODEVICE, `oif` rule into table 77, `accept_local`, owner guard and nft gate | **SO_MARK/fwmark:** gives CAP_NET_ADMIN to Xray. **Route `unreachable`:** bypassed by bound sockets. **Trusting Xray to fail on ENODEV:** it does not (v26.9.30 `system_dialer.go:79-80,136-137`). |
| Mac processes | `mooring-exit` and `mooring-probe` as separate processes | **Probes inside the exit engine:** a probe config error or a QUIC/uTLS panic would take down the exit, and the exit would need extra tags and `network.server`. |
| Hysteria2 server | sing-box 1.14.2, handing each user to Xray over loopback | **Xray's Hysteria2 inbound:** a first release, fixed only in prereleases, never replies "auto". **An independent hy2 exit:** duplicates the routing policy. |
| Xray version | v26.9.30 with REALITY replaced by `e1986a4` (user decision) | **v26.3.27 stable:** carries the PR #36 whole-process panic. **Unmodified v26.9.x:** REALITY `8cdf7bf9` rejects classical-only CFM clients. |
| Builds | Everything from source, one Go 1.27.x, upstream flags, provenance checked, govulncheck | **Official Xray binary:** built with Go 1.26.1. **Upstream VPS tarballs:** a second supply path. |
| Rendering and keys | One renderer on the Mac; the VPS receives bytes (its SSH host key excepted) | **Key generation and rendering on the VPS:** two renderers, no gain. |
| Credentials | Per user and per node | **Shared across nodes:** one compromised provider could use them on the other. |
| Egress check | Mandatory carrier prefixes, plus Paired brackets, plus a self-hosted reflector | **Paired only:** passes when the M7 offloads to home Wi-Fi. **Cloudflare trace:** an undocumented third-party dependency. |
| Reflector exposure | Open, with a per-source limit | **Restricting to the carrier's prefixes:** offload would become an ambiguous probe failure. |
| Gate | Single owner (`mooring-watch`), persisted holds, a halted marker honoured by systemd | **Three writers and in-memory holds:** reopen races, and the kill switch would be undone by a reboot. |
| Transactions | Commit-confirm for every Apply and every agent activation | **Health checks run only on the VPS:** they cannot detect that the operator has been locked out. |
| Ports | Fixed ports below the ephemeral range, hop ranges above it, a model invariant | **47820/47900:** inside 32768-60999; bind conflicts. |
| Hop range | 61000-62999, with 63000-64999 reserved for a second listener | **61000-65000:** leaves no room for a gecko listener. |
| Camouflage | Forward TCP/80 and UDP/443 to the target IP, with per-source limits and a short-idle policy | **Unbounded:** UDP sessions can be exhausted. **Omitted:** port behaviour would differ from the target's. |
| DNS on the VPS | Cloudflare DoH through the exit, both addresses queried in parallel, serve-stale | **`disableFallback`:** one server only, plus a domain WARNING per lookup. **Plain UDP:** tamperable. |
| Export | sing-box JSON by default; Clash block YAML; shapes keyed by client line; delivered only as a file (§9.4) | **URIs:** CFM's released Hysteria2 URI importer accepts no pin and refuses `insecure`; upstream's `pinSHA256` answers that once CFM ships it, but a URI still travels as text through chats, QR images or a subscription (§9.1, §9.4). **QR codes, HTML pages, subscriptions:** §9.4. **Groups, rules, dns:** parsed strictly by CFM; mainland China traffic goes direct through CFM's own switch instead (F10). |
| Contract gate | Shape enumeration × importer digest, plus acceptance records, plus a real-CFM lab | **Runtime shape checks:** a path that can never fire. **Copying or overlaying CFM's converter:** duplication. |
| Power | NetworkClientActive plus PreventUserIdleSystemSleep in a helper owned by the daemon | **PreventSystemSleep:** deprecated and unsupported (SDK). **An assertion held by the UI:** lost when the app quits. |
| Sleep drain | Stop the engine, then drain, then compare the handshake value for change | **Drain first:** a rekey in the gap reopens the gate. |
| Logs | Non-emitting levels, a canary gate, exact-substring scrubbing of stderr tails | **Regex redactor:** complex and incomplete. |
| SSH keys | ed25519-dalek 3 plus a small OpenSSH encoder tested against ssh-keygen | **ssh-key 0.6.7:** a duplicate RustCrypto generation. |
| Lab | A typed `LabAllowance` behind cfg, a separate bundle id and state directory, release verifier checks | **Ad-hoc relaxations:** the release deny list would go untested on darwin. |
| Provider API | None in Mooring v1; the operator's tooling holds one key outside Mooring (D-10) | A token that could create and destroy servers. |
| Shaping | Deferred until data justifies it (M10) | cake/IFB in v1 would add complexity before evidence. |
| Uplink | `SameAsExit` by default; `Separate` explicit | **Automatic switching:** a runtime fallback. |
| M7 attachment (revision 5) | Plugged-In mode, data over the 2.5GbE port through a USB-C Ethernet adapter (§2) | **USB tethering:** the only USB-C port powers the M7 in Plugged-In mode, and computer ports supply less current. **Battery-powered and always plugged in:** the manual advises against it. |
| Console (revision 5) | The CLI's JSON as the only API; `MacStatusV1` rendered by the app; nothing but opaque ids and aggregates leaves the Mac (§15) | **A web panel or public admin API:** a new listener and a new fingerprint (§18). **IP-based "online" lists (`statsUserOnline`):** personal data, blind to Hysteria2 over loopback. |
| Router status (revision 5) | Read only; an allowlist parser over one endpoint chosen in M2a; login bound to the M7's link-layer address (§15.6) | **HTML scraping:** brittle and untyped. **Trying a second path at run time:** a silent fallback. **Insight Pro:** a cloud control path to the uplink. **Logging raw responses:** they can carry the admin password, Wi-Fi keys and SMS bodies. |
| Quotas and expiry (revision 5) | Records; enforcement by reversible suspension (§7, §11.5) | **Revocation (revision 4):** new credentials into China for every quota event, and a broken history. |
| SIM stop on a plan without a line (revision 6) | A mandatory, explicitly recorded hard stop, with no model ceiling (§7) | **A ceiling constant:** SMARTY publishes no volume, so any number would be invented; revision 5's ceiling was EE's line. |
| Alert sending (revision 6) | The Mac renders every notice into agent-proto's Level-0 grammar; the node only sends it, and decides its dead-man pings with agent-proto's `dead_man_pings` (§15.8) | **The rule or the renderer in `daemon-core`, run by the node:** it would need a `mooring-agent` → `daemon-core` edge, which §6.1 forbids, and the VPS would render. **One ntfy topic per node (as first built in revision 6):** the phone would subscribe once per node and again after every rotation, which F6's single topic does not ask for; it would confine a node's leak to its own topic and retire it with the node, but the topic is Level 1, and the one topic is replaced in two changes after a compromise (§12). |
| Remote viewer (revision 6) | An unprivileged `mooring-view` account with its own keys file and `Match` block, and a request-level rule for `GateSet` (§8.6, §11.1) | **A viewer line in root's `authorized_keys`:** a phone key would run the agent as root. **A kind-only role table:** it cannot limit `GateSet` to the Operator hold. |
| Active nodes and rotation | At most 2 active nodes; with a healthy standby, rotation retires the blocked node first (§13.4, D-8) | **A third active node during rotation:** the Mac exit would need a third WireGuard endpoint and a wider probe port span. |
| CFM acceptance check | In `xtask` (`cargo xtask acceptance`, a `ci` step) with the `toml` crate and xtask → `mooring-export`, `mooring-model` edges; the release gate `require_accepted` is `cargo xtask release-acceptance`, run by release verification (D-9). Cost: every xtask command compiles the two product crates first, so `rm -rf target` replaces `cargo xtask clean` while they do not build (§6.1) | **The two hand-written TOML-subset readers M1 first built** (the acceptance reader in `mooring-export`, the `deny.toml` reader in xtask): duplicated parsing, one of them in the public API of a crate the shipped binary links (review finding F16). |

---

## 18. Non-goals (v1)

- Inbound connections to the Mac; Hysteria Realm; China-facing servers on the Mac.
- Subscription URLs, QR codes, URIs, HTML pages or any delivery form but a file (§9.4), a web panel, a public admin API, provider-API automation.
- Clients other than CFM on macOS (F10). Mooring writes no client rules: mainland China traffic goes direct through CFM's own switch, which the user guide turns on.
- IPv6 entry or exit.
- Automatic switching between tunnels, uplinks, exits, carriers or egress-check modes. This stays a non-goal in revision 5.
- Per-user rate limits in the engines; live API user changes; multiple Macs or exits. Revision 5 restatement: if per-user fairness is ever needed, it lives in the VPS kernel (M10: per-user source addresses and cake on `wgexit`), never in the engines.
- Writing the M7's settings. Mooring reads the M7's status and never writes its settings (§15.6). Offload, Wi-Fi, Ethernet, UPnP and firmware are the operator's manual checklist (M2a, D-4).
- A second carrier beside SMARTY. The MR7450 has one nano-SIM slot and no eSIM (manual 202-12721-02, "Install or replace a SIM card"); NETGEAR has said eSIM may come to the M7 Pro but has not confirmed it. Even dual-SIM hotspots run one modem, so only one SIM is active at a time. If M2/M8 data show the SMARTY line is inadequate at the exit site, first compare carriers by swapping the SIM in the same M7 (EE needs a credit check the operator currently fails, F12). A second cellular device with a typed, measured switching policy is a later decision, not v1 (each carrier would need its own `carrier_prefixes`, SIM meter and exit-IP change handling).
  - Revision 5: the operator asked to use the better of two carriers. Choosing by measurement is already allowed: swap the SIM in the same M7 at the real spot and compare 24 h `fieldkit uplink` runs, p10 during the China evening. Revision 6: SMARTY, on Three's network, became the line (F1), so the comparison of F12 is superseded; EE could be compared only later, by a SIM swap. O2 is unsuitable: its unlimited SIMs must be used in devices that do not need to be plugged in, which rules out Plugged-In mode (§19).
  - A second carrier or a second exit running at the same time is planned as a **static P2 design, gated on M8 data**. It would need a second M7: NETGEAR's UK page lists the MR7450 at £749.99 (undated, read 2026-10-08). Each exit would have its own `SimPlan`, `EgressCheck` and meter, with users pinned to an exit by hand. Automatic switching stays a non-goal.
- In-house protocol implementations, C++, or Xray prerelease features (XHTTP, VLESS encryption, `finalRules`).
- Modifying CFM. Extracting its importer, changing its ML-KEM client handling, the mainland China direct switch (F10) and Hysteria2 URI pins are separate CFM tasks (the last two committed as `d828f92` on CFM's branch `feat/mainland-direct-routing` on 2026-10-16, in no release yet).
- Running without a logged-in session; changing system power, firewall or network settings.
- Inspecting traffic or logging destinations; automated reachability probing from China. Revision 5 makes the console's side explicit (§15.5). Mooring never models, stores or sends:
  - destinations, or any per-connection or access log;
  - users' IP addresses;
  - M7 identifiers: cell ID, IMEI, ICCID, phone number and the rest;
  - SMS text.

  Passive China-reachability counters (counts only, no IPs) are a P1 option, not probing.

---

## 19. Risks and unknowns

| Risk or unknown | Impact | Mitigation, or where it is resolved |
|---|---|---|
| Carrier terms: UK consumer SIMs are personal and non-commercial, and all exit traffic is attributed to the SIM holder | Throttling, suspension, legal exposure | A few trusted users; tcp/25 and BitTorrent blocked; SIM hard stop. **D-1: accepted by the user on 2026-10-08 for a pilot of at most 5 active users, with F20 pending.** §19.1 and the next three rows record SMARTY's terms in detail |
| **SMARTY volume terms** (§19.1): no published volume, no fair-use line and no speed restriction ([SMARTY-PG] p11; help 1155178), but no use of content of excessive size, quantity or frequency, after which SMARTY will contact the customer (TC 5.5(d)); a Data Only plan is not a permanent long-term alternative to home broadband (TC 5.15); continuing excessive use may be suspended (TC 8.1(b)), and use inconsistent with ordinary consumer use may end the line at once (TC 9.4(d)) | Contact from SMARTY, then restriction, suspension or termination of the line, with charges forfeited (TC 9.2). There is no deprioritisation step to fall back on. Forum posts claim cut-offs near 100 GB; no SMARTY page says so *(unverified)* | The 300e9 hard stop (F2), mandatory because the plan has no line (§7); the 5-user cap (F3, D-1); one tethered client, the Mac; no money; the SIM forecast and the weekly reconciliation against SMARTY's usage view (§15.3). If SMARTY contacts the operator about volume, the operator decides whether to lower the stop |
| **SMARTY personal-use terms** (§19.1): personal, non-commercial use with no resale or commercial exploitation (TC 5.4(b)); the agreement is personal to the customer, who stays responsible for the SIM's use even when others use the device (TC 2.2); Data Only plans are for SIM-enabled tablets, laptops and portable mobile Wi-Fi devices, and regularly tethering more than 8 devices is given as unlikely to be legitimate personal use (TC 5.15) | Suspension (TC 8.1(b)) or immediate termination (TC 9.4(d)), with charges forfeited (TC 9.2). SMARTY can see hundreds of GB with near-symmetric up and down volume, and a constant UDP flow to one VPS *(inference)* | A dedicated line on a rolling monthly plan with no minimum term, never the operator's own number (F1). No money, gifts or cost-sharing from users (F3). No advertising. At most 5 active users (F3). The M7 is a portable mobile Wi-Fi device with one client, the Mac. D-1 accepts the rest explicitly. This covers contract terms only and is not legal advice |
| **Plan fit** (§19.1): a speed-capped plan, a capped allowance, a carrier whose terms exclude the M7, or terms changed later | A speed cap silently caps the whole service. A capped plan's slowdown looks like a carrier outage. SMARTY may change its terms or prices on 30 days' notice (TC 3.1–3.3) | The plan record, with its speed cap and terms and their date (§7). F1 chose SMARTY Unlimited Data Only, with no speed cap ([SMARTY-PG] p11). A notice of change means re-reading the terms and recording the plan again. O2 is unsuitable |
| **SMARTY billing** (§19.1): a failed auto-renewal taken later moves the cycle start ([SMARTY-PG] p3); a Renewal Date on the 29th–31st falls earlier in a shorter month, and whether it returns is not stated (TC 5.21) | Mooring's cycle and SMARTY's diverge, so the forecast, the stop and the quotas reset on another day than SMARTY's | Activate the SIM on a day up to the 28th (M2a); keep the payment card funded; after a moved renewal the operator records the new bill day (`sim set-bill-day`, M5); the weekly reconciliation (§15.3) |
| **SMARTY's renewal time of day and time zone are not stated** | Each cycle boundary may be skewed by up to a day *(inference)* | Cycles start at UTC midnight *(inference)*; the first renewals are checked against SMARTY's usage history |
| **No volume ceiling in the model.** Without a line, the model accepts any explicit hard stop, `u64::MAX` included (§7) | A mistyped stop removes the volume guard | The stop is mandatory and recorded only by `exit init` and an explicit `sim set-stop` (M5), which refuses a stop above `PILOT_SIM_HARD_STOP_BYTES` without an explicit confirmation (an M5 acceptance item with its own test, §22) |
| **Operator's exposure under PRC law** (§20.1) | Personal legal exposure for an operator who may travel to China | Recorded under D-1. Not legal advice |
| **Durham Student IT Regulations v2.5**: regulation 5.1 (devices that route traffic or offer services to others on the University network) and regulation 2.3 (unsanctioned commercial activity) (§10.2) | Disciplinary exposure; Janet records linking the VPS to a Durham address *(inference)* | P0-2: from M2b, no Durham network on the exit Mac while any exit or test tunnel runs, and no operator traffic over Janet (§10.2). Not legal advice |
| **VPS terms and transfer.** DigitalOcean's AUP (updated 20 Mar 2026) bans "open proxies" and activity intended to withhold or cloak identity. Each served byte enters and leaves the VPS, so the pilot's about 143 GB served per cycle (§3) means about 300 GB of transfer, with the tunnel's overhead, about half of it outbound *(inference)*. DigitalOcean's $6 1 GiB Droplet includes 1,000 GiB of transfer (pricing page, read 2026-10-08), and inbound is free (bandwidth docs, last verified 14 Sep 2026). Mythic Beasts' VPS 1 has 500 GB and VPS 2 1 TB | Account termination; overage charges | Ask both providers in writing before renting, and size transfer from these figures (F13, D-2) |
| **M7 unattended operation** (manual 202-12721-02; §2, §10.3). Firmware updates need a tap, restart the device, and may restore default settings (pp. 26, 47). Thermal levels 1–3 cut bands, then stop 5G, then shut the device down; the ambient range is 0–35 °C (p. 74). A SIM PIN, if set, is asked at every power-on (p. 62). After a cut with the battery out, it powered on by itself (M2a); a firmware update ran over the air after the operator started it from the device's Settings (2026-10-09), as the manual describes | An update can switch the Wi-Fi radio or offload back on. Heat cuts 5G, or the device. A PIN or a missed power-on keeps the exit down | Firmware by hand only, then the D-4 checklist again. The router adapter flags a firmware change (§15.6), and the carrier check stops the exit on offload (§10.2). Plugged-In mode, ventilation and the M2a thermal run. SIM PIN: F17. A UPS on the M7 (F8), and the M2a power-cut drill |
| **This Mac unattended** (§10.3): no `autorestart` or `acwake` capability; FileVault needs a physical login after any restart; Background Security Improvements may install by themselves from macOS 26.1; `sleep 0` and `displaysleep 0` today | The exit stays down after a restart until someone logs in | A UPS, the lid open, Charge Limit 80 %. The alerting machine and the `MacAlive` dead-man check (§15.8; F6) make the outage visible. An absence runbook. Battery and display-lock settings: F19 |
| **The M7's status document can carry secrets.** On other NETGEAR hotspots `model.json` returns the admin password, Wi-Fi keys and SMS bodies (§15.6) | A log, a status file or a fixture leaks the router's admin password or users' SMS | Allowlist parsing, never logging raw bytes, canary tests, allowlist-redacted fixtures, and a login bound to the M7's link-layer address (§15.6) |
| **Accounting accuracy.** Vision splice counts REALITY downloads at connection close (§11.5) | Live rates, `last_active`, five-minute bins and abuse lookups lag or under-count, and quota enforcement can overshoot | Labelled in the console (§15.4). The SIM hard stop as the real-time backstop. The accounting canary. M10's per-user source addresses |
| **Lane conflict.** L5-lab and L6 run a Lima VM on this Mac, while D-7 moves every VM lane off it. L6 and L7 need the user-signed lab bundle | M5's lab acceptance cannot run here as written | Pure `daemon-core` tests on this Mac (§16 L1). Resolve D-7 against L5-lab and L6 before M5's lab lanes (critique, section D) |
| **UK law not researched**: whether a closed-group relay is a "public electronic communications service", and whether the ICO data-protection fee applies once the household exemption is lost | Unknown | Open. Nothing in this design implies either question is settled |
| WireGuard (UDP) unusable on the line | No tunnel | The M2b gate. A redesign is the user's decision, never a runtime fallback. |
| The carrier's pooling or prefix behaviour (Three's core; Vodafone's radio under VodafoneThree sharing) | False stops | M2b fixes the pairing and the prefixes. A new carrier prefix stops the exit until the operator adds it with RIPE evidence. |
| The carrier's CGNAT port ceiling | Flow failures | M2b estimate; `FlowCap` |
| Uplink capacity, variability and modem thermal throttling | About 5 Mbps on bad days | `Separate` mode; M10. M2a measures placement, the antenna and a 1 h thermal run (§22) |
| Kernel behaviour: the `oif` rule with bound sockets, the on-link branch, `accept_local`, unprivileged SO_BINDTODEVICE, owner-guard and `ct count` semantics | Leak, slow failure, broken probes | L4 on two architectures, L4-ablation, L5. The owner guard makes leak prevention independent of the steering inferences. |
| Narrow guard residual: a flow to the target IP:80/443 while `wgexit` is gone | A small VPS-IP leak | `BindsTo`; measured by the T-no-leak variants |
| Interface-bound sockets not bypassing CFM's TUN | A loop, or capture | L6-bypass and M2; in production the carrier check stops the exit |
| Xray v26.9.30 is a prerelease, and the REALITY replace departs from upstream; Hysteria2 shares Xray's failure domain | Untested upstream changes; a crash takes down both protocols on a node | Upstream package tests and T-xray-lock in M0/L2, target rules, `MemoryMax`, the standby |
| GFW blocks the VPS IP or ASN | Entry lost; in the one-node M8 pilot, for every user until a new node is adopted and every user has imported a new file (F11) | Standby on another ASN from M9; the single-node rotation order (§13.4); delivery by file (§9.4); rotation drill |
| **The pilot needs a CFM release that does not exist yet** (F10): CFM's mainland China direct switch is committed as `d828f92` on its topic branch `feat/mainland-direct-routing` (2026-10-16) but is in no release | Without it an outbound-only file sends every flow to the node, which denies `geoip:cn` and `geosite:cn` (§8.2): mainland sites fail | M8 waits for that release; M6 checks the switch on it; `contract/cfm-manifest.toml` is re-pinned to the release (§9.3) |
| **The switch's first start can time out** (F10; the first start with each profile and each engine owner downloads the switch's three datasets through the node, synchronously, inside the engine start. Measured on 2026-10-15 with CFM's pinned sing-box (`docs/measurements/cfm-first-start.md`): about 150 ms unthrottled, 3.4 s at 50 KB/s and 8.6 s at 20 KB/s per download, while a stalled download has no bound of its own. CFM commit `d828f92` on its branch `feat/mainland-direct-routing` (2026-10-16, in no release yet) interrupts any start still running 11 s after its ProxyAgent or tunnel extension received it, and the Host now waits 18 s for a System Proxy start, up from 5 s, which had let a start over about 10 s leave CFM's network Authority quarantined) | A download still running at 11 s fails that start with "The engine did not finish starting in time" (in TUN, when macOS is slow to launch the tunnel extension, as on its first start after installation, with CFM's generic readiness timeout instead), and CFM rolls the start back cleanly, unless libbox then cannot close the interrupted engine: CFM reports "Global cleanup could not be proven." and connects again only after the Mac restarts; datasets that finished are cached, so the next attempt downloads only the rest, but a dataset that cannot download within 11 s through that node never does | The user guide tells users to connect again at once, to try another node or turn the switch off if it keeps failing, and to restart the Mac when CFM reports that global cleanup could not be proven (`user-onboarding.md`, steps 4 and 8); M6 times the first start through the M7's line and records it; shipping the datasets with the app stays a separate CFM option |
| **CFM's mainland China direct routes mainland destinations around the node** (F10; the switch's trade-offs as CFM documents them) | A resource on a mainland address that a proxied page references is fetched directly, so its host sees the user's own address and the time, and usually which page is open (the page's origin and analytics URLs); the switch's datasets (SagerNet sing-geosite and sing-geoip) decide which traffic leaves the tunnel | The user guide says so and tells users to turn on TUN mode and then Global mode for browsing that must never leave the proxy, because System Proxy alone leaves apps that ignore it, and a browser's WebRTC, on the direct path (`user-onboarding.md`, step 4); the nodes still deny `geosite:cn` names and `geoip:cn` addresses (§8.2), so mainland traffic the switch misses is mostly refused rather than relayed; a name outside `geosite:cn` that resolves to a mainland address is still relayed, because the nodes route `AsIs` and match `geoip:cn` only on addresses |
| **An export leaks in delivery**: a screenshot, a pasted text, a written passphrase, a copy kept after import, a lost USB stick | Its holder can use that user's credentials on that node and identify the node to block it (§1.2) | File-only delivery under §9.4; a passphrase that only travels by voice; deletion after import; on a suspected leak, `user reissue` applied at once and a new file for that user alone (`delivery.md`, section 8); on a seizure, revoke the user and rotate every node it held (§13.5) |
| **The agreement promises retention limits** (F7, F9) | A deletion rule promised in the agreement but not built would make the agreement untrue | Build and test the deletion rules of §11.5, §15.7 and F7 before M8 (M4, M5); a later change of the text is a new revision, which every user accepts again before their next file (`AgreementVersion::CURRENT`, §9.2) |
| The reflector is a visible service on the REALITY IP | A small fingerprint | Per-source limit; revisit with M8 data |
| Purego darwin sing-box; sandbox; Secure Enclave key | Build or runtime surprises | M0 and M5 spikes, with recorded decisions |
| Clamshell sleep; NetworkClientActive behaviour on macOS 27; FileVault reboot needs a login | Exit down | M2/M7 behavioural tests; documented |
| The Mac is a single point of failure for every node | Outage | Accepted; visible state |
| China-leg peak loss to London | Slow peak hours | M8 measurement; M10 relay |
| `.internal` SNI accepted by CFM and by Chrome-QUIC parroting | Hysteria2 import or connect fails | L2, L4 and L7 |
| `xray api` flags; BitTorrent sniffing without a matching `destOverride` | An accounting or policy gap | M3/M4 tests |
| Mythic Beasts cloud-init; geodata licences; whether hosted runners have `/dev/kvm` | Provisioning path; notices; L5 vehicle | Checked at purchase, in M0, and in M4 (a typed failure if KVM is missing) |
| Lima vzNAT and the Local Network privacy prompt for a LaunchAgent | Lab friction | L6 checklist |
| **The neighbour table hidden from `mooringctl`** (revision 7, §15.6 rule 10). On 2026-10-13 an ad-hoc-signed binary, and `arp` run as its child, saw no neighbour entries, which was read as local network privacy *(refuted on 2026-10-14)*. Measured on 2026-10-14 on macOS 27.0.1 (26A434): the kernel returned an empty table to processes whose code-signing identifier is not reverse-DNS, and to processes an ad-hoc-signed process had started *(that it does so to every such process is an inference from the measured cases)*; cargo signs every build ad hoc as `<name>-<hash>`. The rule is undocumented and may change with a macOS update *(inference)* | A plain `cargo` build of `mooringctl` cannot read the M7's link-layer address: `router pin` cannot pin, and `status` and `capture` stop at the identity check before any password is sent. Before the fix it was misreported as `RouterUnreachable{GatewayUnresolved}` | `cargo xtask mooringctl` signs a copy of the build ad hoc as `com.bill.mooring.mooringctl` at `target/signed/mooringctl`, which no later build reverts, and checks the identifier; the copy does not follow later source changes, so it is run as `cargo xtask mooringctl && ./target/signed/mooringctl router …` from Terminal.app's own shell, with no ad-hoc-signed shell or terminal multiplexer in between. An empty table once the gateway has been reached (for `router pin`, in both reads around a warm-up connection that succeeded) is the local `NeighbourTableHidden`, which names the command; never a weaker check. The M5 app and LaunchAgent carry a proper bundle identifier and are started by launchd (L6 checks the table is visible to them) |
| One maintainer | Stalls | Everything driven by `xtask`; runbooks; no hidden VPS state |
| Rendered `nftables.conf`, `wgexit.conf` and cloud-init syntax, and Xray's semantic reading of `xray.json`, are covered only by goldens and Rust-side read-back until L2 runs | A config a tool or engine rejects, or reads differently | L2 on the research computer (`nft -c`, `wg-quick strip`, `cloud-init schema`, `xray convert pb`) before the M3 lanes depend on them |
| An app upgrade (§13.3) with no configuration change re-applies a node at its current generation with a new bundle digest. The agent answers that with `GenerationNotNewer` when it already runs that generation (it stays at its older generation only after an `Unchanged` reply, §11.2), while the model records a new digest at an equal generation (§7) | An engine or host-profile upgrade cannot reach a node without a configuration change | Settle the rule when the agent's transactions (M4) and `node apply` (M5) are built |

### 19.1 Carrier and plan facts (revision 6; read 2026-10-08)

The sources' URLs are in §21, item 12. SMARTY is the decided line (F1). EE's facts follow as history, kept for the record: EE declined the operator's Data SIM order at its credit check on 2026-10-08, so EE is not the line.

#### 1pMobile (the line since 2026-10-23, F1)

Source, read on 2026-10-23: **[1PM-TC]**, 1pMobile Terms and Conditions, updated 24 July 2026, <https://www.1pmobile.com/terms-and-conditions>. The price, the absence of a credit check, tethering and the network come from a carrier comparison on 2026-10-16/17 *(not re-read on 2026-10-23)*.

- **Who.** Telecommunications Management Limited trading as 1pMobile, for the pay-as-you-go service; Utility Warehouse Limited, for the Data Boosts (opening paragraph). On EE's network when read; the terms let it use and change networks without notice (The Services).
- **Plan.** The Unlimited Data Boost, £25, "charged on a 30-day rolling basis" (Definitions). A Boost that is not paid reverts the line to pay-as-you-go. So billing cycles are 30 days from the day the Boost was bought (`CycleRule::FixedDays`, §7); the M7's day-of-month billing counter cannot follow them.
- **Volume.** "Where unlimited data is included in the price plan you have chosen, we consider 30-day rolling data usage above 500GB to be non-personal use" (Fair Usage Policy). Past it the carrier may charge more, move the line to a capped tariff, deprioritise it, throttle it (128 kbps is the terms' example), or suspend the SIM. The window is rolling, so per-cycle stops are bounded across cycles (F2, §7).
- **Personal use.** "private, personal and legitimate purposes" only, no business use unless agreed, and no resale (Fair Usage Policy). This is the same consideration as SMARTY's TC 5.4(b) and D-1.

#### SMARTY (the first line, F1 until 2026-10-17)

Sources, all read on 2026-10-08: **[SMARTY-TC]**, SMARTY Terms and Conditions V33, 30 July 2026; **[SMARTY-PG]**, SMARTY Price Guide V42, 25 August 2026; and SMARTY help-centre articles, cited by article id with the page date where it was recorded.

**The order.** SMARTY Unlimited Data Only, £20 a month, rolling monthly with no minimum term, a physical SIM. Ordered on 2026-10-08, due about 12–13 October 2026, and not yet activated. SMARTY's plan page (undated) lists no credit check.

**Operator and network.**
- Hutchison 3G UK Limited trading as SMARTY (TC 1.1), on Three's network.
- Since August 2025 SMARTY customers are moved onto combined Three and Vodafone coverage (VodafoneThree network sharing), automatically and with the same SIM (help 10235435, 5 May 2026).
- 5G at no extra cost (help 5877334; PG p3): 5G on 3.5 GHz (n78); 4G on 700, 800, 1400, 1800 and 2100 MHz (B28, B20, B32, B3, B1) (help 4670061, 9 Dec 2025). Whether its 5G is standalone or non-standalone is not stated.
- APN `mob.asm.net`, IPv4, with no username or password (help 1155220, 18 Mar 2026).
- Three's national 5G upload median is 20.2 Mbps against EE's 16 Mbps (Opensignal via ISPreview, 29 Jan 2026). This was not re-verified.

**Volume.**
- No numeric fair-use line in the UK and no data-speed restriction on the Unlimited plans (PG p11; help 1155178, "no shaping or throttling", 27 Apr 2023). An Unlimited SMARTY plan therefore has no fair-use line and no deprioritisation step (`PlanKind::Unlimited`, §7).
- The limits are qualitative:
  - TC 5.5(d): no content of excessive size, quantity or frequency; SMARTY will contact the customer if use is excessive;
  - TC 5.15: Data Only plans are for SIM-enabled tablets, laptops and portable mobile Wi-Fi devices, and are not a permanent long-term alternative to home broadband; regularly tethering more than 8 devices is given as an example of use unlikely to be legitimate personal use;
  - TC 8.1(b): suspension for continuing excessive use;
  - TC 9.4(d): immediate termination, among other cases, for use not consistent with the ordinary use of a consumer;
  - TC 9.2: charges remaining on the account are forfeited when SMARTY ends the agreement for the customer's conduct.
- So past the operator's own budget the risk is contact, then restriction, suspension or termination of the line, not deprioritisation. SMARTY publishes no volume. Forum posts claim cut-offs near 100 GB; no SMARTY page says so *(unverified)*.

**Personal use.**
- TC 5.4(b): personal, non-commercial use only, with no resale or commercial exploitation.
- TC 2.2: the agreement is personal to the customer, who cannot pass it to anyone else and stays responsible for the SIM's use, even when others use the device.
- TC 3.1–3.3: SMARTY may change its terms or prices on 30 days' notice.

**Billing.**
- Paid upfront each month. The renewal cycle starts at SIM activation and renews on the same day each month, the Renewal Date (TC 5.20, 5.21; help 952716, 4227332).
- If paid on the 29th–31st, the Renewal Date falls earlier in a shorter month (TC 5.21). Whether it returns to the 29th–31st in a longer month is not stated.
- A failed auto-renewal that is retried and taken later moves the cycle start to the day payment was taken (PG p3).
- The time of day and the time zone of the renewal are not stated anywhere.
- To cancel, auto-renew is turned off at least 24 h before the Renewal Date (TC 9.1).
- Operator practice that follows: activate the SIM on a day up to the 28th, so the bill day never clamps; keep the payment card funded, because a failed renewal moves the bill day, which the operator then records again (`BillDay`, §7).

**Usage counting** (PG p23): binary units (1 kB = 1024 bytes, 1 MB = 1024 kB, 1 GB = 1024 MB), counting re-sent packets and flow-control overhead, charged per full MB. Usage is shown in the dashboard and the app with a usage history; whether an Unlimited plan shows the GB used, and how fresh the figure is, is not stated (M2a records it).

#### Other carriers

- No UK consumer carrier permits this use. O2 and Vodafone restrict use to private or personal purposes, and SMARTY to personal, non-commercial use.
- **O2 is unsuitable.** Its unlimited SIMs may be used only in devices that do not need to be plugged in to work (O2 Unlimited Tariff Terms 3.3, undated), which rules out Plugged-In mode.

#### EE (history: EE declined the order at its credit check on 2026-10-08; not the line)

Revision 5 recorded these facts while EE was the candidate line. EE's Data SIM order was declined at EE's credit check on 2026-10-08 (a thin UK credit file), so none of them applies to the line. They stay for the record, and for a later comparison by SIM swap (F12, superseded).

**Fair use.**
- Every current EE unlimited guide treats use above 600 GB a month as non-personal use. EE may then deprioritise the line at busy times, or move it to a business plan. Sources: the EE SIM Only Pay Monthly Plan Terms and Price Guide (from 7 Aug 2025, updated 5 Mar 2026), p. 2, and the EE Data SIM guide (from 29 Aug 2024, updated 25 Mar 2026).
- EE defines 1 KB = 1024 bytes, 1 MB = 1024 KB and 1 GB = 1024 MB. It counts upstream and downstream together, including flow-control and re-sent packets (SIM-only guide, "What do you mean by data usage?").
  - So 600 GB is 644,245,094,400 bytes, assuming EE measures fair use in those units *(inference)*. Revision 5 held it as `EE_FAIR_USE_600_GIB` and as the unrecorded-plan ceiling; revision 6 removed both, and tests that need a fair-use line keep the value as `TEST_FAIR_USE_BYTES` (§7).
- Deprioritisation moves the line's QCI from 8 to 9, only on congested cells, until the end of the bill cycle (EE Traffic Management KFI, April 2022). EE told the ASA it affects about 4 % of sites, with no extra charge and no suspension (ASA ruling on EE Ltd, 21 May 2025).
- The "12 or more regularly tethered devices" clause appears in the 2021 Unlimited terms and the 7 Aug 2025 handset terms. It is absent from the current SIM-only, Data SIM and WiFi terms and from the 20 Aug 2026 handset terms. Mooring would not trip it anyway: the M7 has one client, the Mac.

**Personal use and the network terms.**
- Unlimited plans are for personal, non-commercial use, and may not be used to sell access to EE's network (plan guides, p. 1).
- The EE Mobile Pay Monthly Network Terms v11 (16 Jan 2026) add:
  - 4.7.11: no device that routes or re-routes voice, data or other services on, from or to the network;
  - 4.7.12: no fraudulent or unlawful purpose, and no direct financial gain, revenue share or benefit in kind;
  - 4.7.13: no selling, or providing commercial services, to third parties without EE's express prior written consent;
  - 6.2: EE may suspend, disconnect or terminate without warning on a breach of any point in 4.7 (6.2.3), or of any other agreement with EE or its group companies (6.2.1);
  - 6.3: after such a termination, everything owed is payable, including any cancellation charge.

**EE plans.**
- **EE SIM-only, 30-day Essentials Unlimited:** £38 list, 100 Mbps cap, +£2.50 each 31 March (SIM-only guide). Its terms speak of use "from your phone".
- **EE Data SIM, 30-day Essentials Unlimited:** £35, +£1.50 each 31 March. Its terms speak of a "device".
- **The EE Student Discount** (v2, 21 Apr 2026): 20 % off SIM-only plans; a single-use code per person and per account; online only. Its terms say SIM-only prices rise £1.50 each 31 March, against the guide's £2.50. The order confirmation decides.
- **Excluded:** No Frills (10 Mbps cap) and PAYG (25 Mbps cap, phone only).
- **5G standalone** needs All Rounder or Full Works, and EE's 5G+ device list names no NETGEAR hotspot (EE help page, updated 24 Apr 2026).

---

## 20. Decisions needed from the user

| ID | Decision | Recommendation |
|---|---|---|
| D-1 | Accept the carrier-terms and attribution exposure of serving third parties through a consumer SIM, now SMARTY's (F1). Revision 5 added the facts behind it (§19.1) and the operator's exposure under PRC law (§20.1). This is not legal advice | **Accepted 2026-10-08 by the user, at a reduced scale: carrier terms accepted for a pilot of at most 5 active users; F20 pending.** The user accepted the carrier-terms exposure after being shown SMARTY's clauses (§19.1, §20.1) and chose to start with 3–5 users, with no money, cost-sharing or gifts. F20 (the PRC-law exposure) was not asked and stays pending; it is part of D-1, so M8 still waits for it |
| D-2 | Rent the VPS(es): an hourly London VPS for M2, then a primary and a standby | Primary on a less popular UK network (Mythic Beasts if its console path works); standby on DigitalOcean LON1 |
| D-3 | **Resolved 2026-10-08 by the user:** Xray v26.9.30 built with `replace github.com/xtls/reality => e1986a4` (§4.2). | Done; gated by L2/L4 |
| D-4 | Keep the M7's Wi-Fi offload and Ethernet offload off (and its Wi-Fi radio off, for an exact SIM meter) | Yes |
| D-5 | Whether to schedule the separate CFM tasks: importer extraction, shipping the ML-KEM opt-in, and releasing the mainland China direct switch with Hysteria2 URI pins (committed as `d828f92` on CFM's branch `feat/mainland-direct-routing` on 2026-10-16, in no release yet) | The first two are independent of Mooring v1; the third is what M8 waits for (F10), and M6 re-pins the CFM manifest to its release |
| D-6 | Signing identity and provisioning profile for the app. The user performs the signing. | Use the user's Apple team; no notarization unless the app is distributed |
| D-7 | **Resolved 2026-10-08 by the user:** this Mac becomes the dedicated exit server, so it must not accumulate build caches. Rust work (M0/M1 pure crates) runs here in the single repository `target/`, which `cargo xtask clean` removes at the end of every milestone. Go engine builds, govulncheck and every VM lane (Lima/QEMU) run on the research computer or in hosted CI. The exit Mac only runs signed release artifacts. **2026-10-23, the user's choice:** hosted CI in a private GitHub repository, `billlza/mooring` (`main` pushed with its history; the user accepted that it holds lon1's address in M4a's tests, which the code no longer has); `.github/workflows/ci.yml` runs `cargo xtask ci` and the agent's musl lints on `ubuntu-24.04`, with cargo-nextest and cargo-deny pinned and every action pinned by commit. A Lima VM was run on this Mac once that day, for M4e's first part, against this decision; it was deleted with Lima's caches. | Done |
| D-8 | **Decided 2026-10-08 for the M1 close-out (review finding F24), recorded as the operator's decision; the repository keeps no record of the user's own wording, so the user confirms it with the M1 commit:** `MAX_ACTIVE_NODES` stays 2, because the Mac exit carries at most two WireGuard endpoints and the probe port span is sized for two nodes. Rotation with a healthy standby therefore retires the blocked node before `node new` (§13.4). | Implemented in M1. **Confirmed 2026-10-08:** the user approved the M1 commit 4a95ee0, which this entry named as the confirmation |
| D-9 | **Decided 2026-10-08 for the M1 close-out (review finding F16), recorded as the operator's decision; the user confirms it with the M1 commit, as for D-8:** CFM acceptance checking lives in `xtask` (`cargo xtask acceptance`, a `ci` step), reading `contract/cfm-acceptance.toml` and `contract/cfm-manifest.toml` with the `toml` crate (xtask-only; `deny-skips` reads `deny.toml` with it too) and the shapes and SHA-256 values through xtask → `mooring-export` and `mooring-model` edges; the release gate `require_accepted` is `cargo xtask release-acceptance`, which release verification runs (§6.1, §6.3, §9.3). Accepted cost: every xtask command compiles those crates first (§6.1). | Implemented in M1. **Confirmed 2026-10-08:** the user approved the M1 commit 4a95ee0, which this entry named as the confirmation |
| D-10 | **Decided 2026-10-21 by the user:** the operator holds one provider API key for operator tooling, outside Mooring. It was created on 2026-10-18 at the D-2 primary provider with the provider's only VPS scope, which can create, manage and delete servers (there is no read-only scope), and with no DNS or domain scope. It is kept in the operator's login keychain; the operator's scripts, which are not in this repository, pass it to the provider's token endpoint on stdin, never in arguments, files or output. They read server state at will, and every call that creates, resizes or deletes a server, or otherwise costs money or destroys data, is asked of the operator first. No Mooring crate, binary or state reads, stores or depends on it: Mooring still provisions through the console path of §13.2, and §17's "Provider API: none" holds for Mooring itself. Threat: the key can create and destroy servers. Whoever can read it already runs code as the operator on the Mac, which holds root SSH to every node (§1, "Same-user processes on the Mac"), so it adds the provider account's billing and server deletion to what that attacker already has. Revoking it is deleting it in the provider's control panel and deleting the keychain item. | Done, outside Mooring's code |

### 20.1 D-1 in detail (revision 6; not legal advice)

D-1 asks the operator to accept two exposures. Revision 5 recorded what each rests on; revision 6 re-points the carrier terms to SMARTY, the decided line. On 2026-10-08 the user accepted the carrier-terms exposure for a pilot of at most 5 active users; the PRC-law exposure (F20) was not asked and stays pending.

**The carrier terms** (SMARTY, §19.1, read 2026-10-08):
- Personal, non-commercial use only, with no resale or commercial exploitation (TC 5.4(b)); the agreement is personal to the customer, who stays responsible for the SIM's use (TC 2.2).
- Data Only plans are for tablets, laptops and portable mobile Wi-Fi devices, not a permanent long-term alternative to home broadband, and regularly tethering more than 8 devices is given as unlikely to be legitimate personal use (TC 5.15).
- No content of excessive size, quantity or frequency; SMARTY will contact the customer about excessive use (TC 5.5(d)). There is no fair-use line and no deprioritisation step.
- Suspension for continuing excessive use (TC 8.1(b)); immediate termination for use not consistent with the ordinary use of a consumer (TC 9.4(d)); charges forfeited when SMARTY ends the agreement for the customer's conduct (TC 9.2).
- Terms and prices may change on 30 days' notice (TC 3.1–3.3).
- EE's terms, which revision 5 recorded here, are history in §19.1. O2 is unsuitable, because its unlimited SIMs are for devices that need no plug.

**The operator's exposure under PRC law:**
- The PRC Interim Provisions Governing the International Networking of Computer Information Networks (State Council Order 195, amended 20 May 1997; www.cac.gov.cn, read 2026-10-08):
  - Art. 6 requires international connections to use the channels the state provides;
  - Art. 14 allows a warning and a fine of up to 15,000 yuan for a breach.
- Providers of paid circumvention services have been prosecuted in China: in Shanghai Baoshan in 2018, a 3-year suspended sentence; in Hangzhou in 2019, an arrest in a case involving 29,000 users. The design-gaps review cited these, and they were not re-verified here.
- Payment, scale and visibility aggravate the exposure *(inference)*. An operator who may travel to China carries it personally.

**The constraints that follow:**
- no payment, cost-sharing or gifts (F3);
- no advertising;
- a cap on active users (F3: at most 5);
- no administration from inside China with identifiable accounts.

F20 asks the operator to accept the PRC exposure as part of D-1. It was not asked on 2026-10-08 and is still pending.

### 20.2 Operator decisions from the console review (revision 5; F1–F6, F12, F15 and F16 decided in revision 6; F7 and F9–F11 in revision 8)

The console review of 2026-10-08 raised twenty decisions, F1–F20. They are not the M1 review findings F16 and F24 cited in D-8 and D-9. On 2026-10-08 the operator decided F1–F6, F12 (superseded), F15 and F16; their right-hand column gives the decision, in the operator's terms, and where the code records it. Two points that the review of 2026-10-09 found open inside F4 and F6, whom N counts and whether the ntfy topic is one or one per node, were decided on 2026-10-09 by the recommended default, following F4/F6 as stated; the F4 and F6 rows mark them as such, and they are not the operator's own words. The onboarding review of 2026-10-15 asked how a user adds Mooring to CFM (a YAML or HTML file, or a QR code) and found the gaps §9.1 and §9.4 record. That day the operator delegated F9, F10 and F11 to the recommended best-practice default, and delegated F7 with them, because the agreement (F9) states retention to users; their rows mark them as decided by delegation, and their text is that default, not the operator's own words. The rest are pending: F8, F13, F14, F17, F18, F19 and F20, with D-2, D-4, D-5 and D-6 above. For those the right-hand column is a recommended default, not a decision. Nothing built presumes a pending one: where the code touches one, it is either absent (F18), or a record whose default is "not recorded" or "off" (expiry, §7). The others are operating choices outside the code.

| ID | Decision | Decision taken (decided), or recommended default (pending) |
|---|---|---|
| F1 | Line and plan (cost). Needs D-1 first | **Decided 2026-10-08: SMARTY Unlimited Data Only**, £20 a month, rolling monthly, a physical SIM. Ordered on 2026-10-08, due about 12–13 October 2026, not yet activated. EE's Data SIM order was declined at EE's credit check on 2026-10-08 (a thin UK credit file), so EE is not the line. O2 stays unsuitable (§19.1). Recorded as `Carrier::Smarty`, `PlanKind::Unlimited`, no speed cap, terms [SMARTY-PG] (§7). Revision 5's recommendation was an EE Data SIM (§19.1, history). **Reopened 2026-10-17:** after the uplink run at the window (M2.md, steps 4–10: China-evening p50 2.53 Mbps and p10 1.17 Mbps, no sample at 15 Mbps), the operator decided to leave SMARTY and change the line, without the antenna A/B first. The next line is measured the same way at the same spot and then recorded here; until then the design's statements about SMARTY describe the line being left. **2026-10-23: 1pMobile's Unlimited Data Boost** (on EE's network when read; £25 per 30 days, PAYG with no credit check; §19.1) is the line the operator ordered, and the code records it (`Carrier::OnePMobile`, `SimPlan::one_p_mobile_unlimited()`, 30-day cycles, §7). Its M2 measurement at the same spot runs when the SIM arrives |
| F2 | Stop policy (user-visible) | **Decided 2026-10-08: a hard stop at 300 GB of SIM bytes, with a warning at 240 GB** (decimal: 300,000,000,000 and 240,000,000,000; `PILOT_SIM_HARD_STOP_BYTES`, `PILOT_SIM_WARN_BYTES`). Users lose service for the rest of the cycle at the hard stop. That is about 140 GB served, since each served byte crosses the SIM about twice (§3: about 143e9 at 2.1×). `AcceptDeprioritisation` cannot apply, because the plan has no fair-use line (§7). **Revised for 1pMobile, 2026-10-23 (proposed; the operator confirms before `exit init`):** a hard stop at 240 GB with a warning at 200 GB. 1pMobile counts 30-day rolling usage above 500 GB as non-personal (§19.1), and a per-cycle stop of 300 GB lets one 30-day window hold two cycles' stops, up to 600 GB; the model refuses any stop whose two cycles reach the line (§7, `SimStopAboveRollingLine`), and 240 GB keeps both at 480 GB with a 4% margin for the carrier counting more bytes than the Mac. About 114 GB served per cycle at 2.1× |
| F3 | Admission and payment (user-visible) | **Decided 2026-10-08: at most 5 active users** for now (`PILOT_MAX_ACTIVE_USERS`, `CapacityPolicy::PILOT`). The user first said 10, then narrowed it to 3–5 after reading SMARTY's terms. No money, cost-sharing or gifts |
| F4 | Per-user quotas (user-visible) | **Decided 2026-10-08: automatic quotas from 6 active users.** Each user's cycle quota is 0.8 × the served budget ÷ N, with a warning at 80 % and a reversible suspension (`SuspendReason::QuotaExceeded`) at 100 %; per-user overrides are allowed (`AutoQuotaPolicy::PILOT`, §15.3). At the pilot's stop the served budget is about 142.9e9 bytes, so 6 users would get 19,047,619,047 bytes each. **What N counts: decided 2026-10-09 by the recommended default, following F4/F6 as stated (latched per cycle).** Read literally, N and the 6-user threshold would count only the users active now, so at exactly 6 the first suspension for quota would turn the quotas off for everyone else for the rest of the cycle, and one heavy user could then run the SIM into the 300e9 hard stop that F4 exists to prevent. N and the threshold therefore count the users active now plus those suspended for quota in the current cycle: a suspension for quota never changes anyone's share within the cycle, admitting a user still lowers every share (F4's ÷ N), and other suspensions, revoked users and suspensions for quota from an earlier cycle (resumed by the apply job at the new cycle, within the cap, §13.6) do not count (§15.3). Whether a suspension for quota counts is decided by when it was made, not by the cycle start it records: one made during the current cycle counts and one made before its start has lapsed, so an edit of the bill day in either direction, a late SMARTY renewal moving the start forward included, never drops a suspension made in the current cycle; one made after now is an error, never read as either (review fixes of 2026-10-09). The other departures still lower N mid-cycle: at exactly the threshold an expiry, which `evaluate` itself proposes, an operator or abuse-review suspension or a revocation switches the quotas off for the rest of the cycle, and only the hard stop then bounds the SIM (§15.3). Under the cap of 5 the quotas stay dormant unless suspensions for quota this cycle bring the count to six; while they are dormant only a user's own quota can cause one |
| F5 | Remote viewing through a viewer role on the VPS, with an emergency stop from a phone | **Decided 2026-10-08: yes**, per §15.9: a viewer role on the VPS for the operator's phone, read-only plus an emergency stop (`GateSet` with the Operator hold only); `ClearHold`, `Apply`, `Shutdown` and `Resume` stay ops-only, so resuming is done from the Mac; an unprivileged `mooring-view` account (critique C-9); the key generated on the phone and only its public key imported; `viewer new` prints the node's host-key fingerprint; never over Janet or eduroam |
| F6 | Alert channels (third parties see Level-0 text; cost £0) | **Decided 2026-10-08: yes**, per §15.8's default: ntfy with a random topic of at least 128 bits, the Healthchecks.io free plan with a node check and a `MacAlive` check per node (the operator creates the account himself), and a daily digest at 09:00 UK time. Aggregates only, Level 0: node ids and counts, never a label, opaque user id, alias, IP address, M7 identifier or SMS text. Revision 5's alternative, Pushover ($4.99 once per platform), was not taken. **One topic for the deployment: decided 2026-10-09 by the recommended default, following F4/F6 as stated.** Revision 6 had first built one topic per channel node, which made the phone subscribe once per node and again after every rotation. F6 names one topic, so the code now keeps one deployment-level topic (`SecretRef::AlertTopic`), required while at least one node has channels; the Healthchecks checks stay per node, because a dead-man check watches one node (§7, §15.8). The phone's one subscription survives a rotation when the replacement or the standby gets its channels before the last channel node is retired (§13.4); replacing the topic after a compromise or a lost phone takes two configuration changes and one new subscription (§12) |
| F7 | Retention, per host (user-visible through the notice) | **Decided 2026-10-15 by delegation** (as F9, whose agreement states it): five-minute bins for 7 days, hourly for 35 days, daily and monthly totals for 13 months, lifetime totals until 13 months after a user is revoked, all on the Mac; a revoked user's label, alias and agreement record go at the same time, or at once on the user's request (`user forget`, §15.7). A node keeps each usage bin for 48 hours and each monthly usage file until 7 days after its month; the Mac pulls the bins every poll and each month's file (`Usage{month}`), and after a longer gap fills it from that file (§11.5). A node drops a user's `last_active` once the user leaves its applied configuration |
| F8 | Hardware (cost; prices not researched) | A USB-C 2.5GbE adapter (needed for Plugged-In mode, §2). A UPS for the M7, which is essential because Plugged-In mode has no battery, and for the Mac. A high-gain antenna only if the survey shows fewer than 2 bars. Pending; on 2026-10-08 the user said he is buying a USB-C Ethernet adapter, and the UPS is undecided |
| F9 | Agreement before export, and the delivery rules (user-visible) | **Decided 2026-10-15 by delegation:** the operator delegated F9 to the recommended best-practice default; this is that default, not the operator's own words. `user export` requires the user's `AgreementRecord` of the revision the build ships (`AgreementVersion::CURRENT`, revision 1) and refuses others with `AgreementNotAccepted` (§9.2, §14); `user agree` records it (M5). The agreement, in Simplified Chinese (`docs/runbooks/user-agreement.md`), covers: no payment or resale; no sharing the file; no unlawful use or P2P; what the operator sees and how long it is kept (F7); what to do when blocked. The user accepts it aloud on an end-to-end encrypted call. Delivery is by file only, in person by AirDrop or in an AES-256 disk image whose passphrase is spoken over that call; nothing about the service over WeChat, QQ or iMessage to a mainland-China Apple ID (§9.4) |
| F10 | Client scope for v1 (user-visible) | **Decided 2026-10-15 by delegation** (as F9): macOS CFM only, on a 0.5-line release with CFM's mainland China direct routing switch, which the user guide (`docs/runbooks/user-onboarding.md`) tells users to turn on. This replaces the earlier line that Chinese sites must go direct in CFM's rules: CFM has no rule-editing UI, and an outbound-only file sends every flow to the node, which denies `geoip:cn` and `geosite:cn` (§8.2). The switch is committed as `d828f92` on CFM's topic branch `feat/mainland-direct-routing` (2026-10-16) and is in no release; the pilot waits for its release (M8), and M6 checks it. Until M6 decides on `ClientLine::Cfm04`, F10 is kept by procedure: a user recorded on the 0.4 line still exports (`delivery.md`, section 1) |
| F11 | Config update channel (user-visible) | **Decided 2026-10-15 by delegation** (as F9): no subscription URL; files are re-delivered by the channels of §9.4. In the M8 pilot there is one node, so a blocked node means a rotation and a new file for every user (§13.4, single node). Every user holds both nodes only from M9, when the standby arrives (which itself means a new file for every user); a blocked node's users then switch to the other node's outbounds until the rotation's files arrive |
| F12 | Carrier comparison (cost) | **Superseded 2026-10-08:** SMARTY, on Three's network, is the line (F1). EE could be compared only later, by a SIM swap in the same M7, and needs a credit check the operator currently fails. Revision 5's default compared SMARTY against EE's measured uplink. Never O2. **Reopened 2026-10-17 with F1:** the next line is compared by a SIM swap in the same M7 at the same spot, with the same uplink run (M2.md) |
| F13 | VPS rental (D-2; cost) | As D-2, with transfer sized from §19 and the proxy question asked of both providers in writing |
| F14 | Beyond one line (cost and user-visible; after M8) | Cap users rather than add a second exit, a split exit or a relocation |
| F15 | Whether operator traffic (a viewer session, push alerts) may ever cross Janet or eduroam | **Decided 2026-10-08: no** operator traffic over Janet or eduroam (§10.2, §15.9) |
| F16 | Confirm that the console shows bytes and times only, never destinations (§15.5) | **Decided 2026-10-08: yes**, bytes and times only |
| F17 | SIM PIN on the M7 | Off, with the M7 in a physically secured place, because a PIN asked at every power-on defeats unattended recovery (§10.3) |
| F18 | Backup escrow (changes §13.7's accepted model) | An `hdiutil` AES-256 image of the state, the Keychain secrets and the SSH material, with the passphrase kept offline, never in iCloud and never in a chat app, made again after each deletion the agreement promises (§15.7). Until decided, no backup exists |
| F19 | Serving on battery, and the Mac's sleep and display-lock settings | Keep §10.3's behaviour on battery. Set display sleep to about 10 minutes with a password required immediately, so the screen locks; Mooring's assertions keep the system awake |
| F20 | Accept the PRC-law exposure as part of D-1 | The operator's own call. Nothing in this design can reduce it below the constraints listed under D-1. Pending: not asked on 2026-10-08, when D-1 was accepted for the carrier terms |

---

## 21. Evidence index (read-only)

1. **sing-box v1.14.2 (af6e64c, clean):**
   - `release/LDFLAGS`; `release/DEFAULT_BUILD_TAGS*`
   - `option/wireguard.go:9-23` (endpoint embeds `DialerOptions`; `udp_nat_max`)
   - `transport/wireguard/device.go:44-52` and `device_stack.go:84-88` (gVisor stack NAT bound)
   - `option/tls.go:22-29,118-120`; `common/tls/std_server.go:405-420` (TLS files read at construction)
   - `cmd/sing-box/cmd_check.go:29-44` (`box.New` and `Close`, no `Start`); `cmd_run.go:48-54` (stdin)
   - `route/rule/rule_default.go:15-19`; `option/rule.go:141-161`; `option/hysteria2.go:17-29`; `option/direct.go:12-14`
   - `protocol/wireguard/endpoint.go:226-246`; `common/tls/std_client.go:137-145,278-295` (SPKI-only pin check over `x509.MarshalPKIXPublicKey`)
   - `option/tls.go:252-256` (`OutboundRealityOptions` has no `support_x25519mlkem768`)
   - sing-quic `v0.7.1-0.20260924092235-6a3a24d65b99` (`go.mod:53`): `hysteria/hop.go:55-57` (hop interval of at least 5 s)
2. **Xray v26.9.30 `b26a91de`** (re-read in M1; `docs/engines.md` maps every rendered key):
   - `infra/conf/log.go:57-59` (`none` turns off both logs); `main/run.go:84,95` (start-up failures on stdout)
   - `infra/conf/transport_security.go:100-102` (`invalid "privateKey"` echoes the key), `:163-169` (REALITY server-name warning)
   - `infra/conf/xray.go:362-368` (freedom `targetStrategy`/`domainStrategy` deprecation warnings); `infra/conf/transport_sockopt.go:50,96-121`; `transport/internet/dialer.go:251-262`
   - `proxy/freedom/freedom.go:55-58,210-211,293-302`; `common/retry/retry.go:23-62`
   - `transport/internet/system_dialer.go:79-80,136-137` (socket-option errors logged at Info, then the dial proceeds)
   - `app/dns/dns.go:321-344`; `app/dns/nameserver_doh.go:155,199,207,215`
   - `infra/conf/serial/loader.go:47-55`; `infra/conf/xray.go:25`; `infra/conf/dokodemo.go:10-31`; `infra/conf/policy.go:12-14`
   - `main/commands/all/tls/ping.go:125-170` (what `xray tls ping` reports); `app/dispatcher/default.go:164-208` (per-user counter names)
   - Not re-read, from the design review at v26.3.27: `app/proxyman/inbound/worker.go:289-317,402-412`; `main/commands/all/convert/protobuf.go:17-54`; `common/mux/client.go:347-370`
3. **REALITY:** `git log` 9234c77 → 393f8de (#33) → e1986a4 (#36), all dated 2026-09-08 except 9234c77 (2026-03-22); `git diff --stat 9234c77 e1986a4` changes 2 files.
4. **Linux v6.12:** `fib_frontend.c:344-452` (`__fib_validate_source` and `fib_validate_source`; `accept_local` at 381 and 430); `fib_trie.c:1427-1438,1619`; `route.c:2301,2768`.
5. **macOS 27 SDK:** `IOKit/pwr_mgt/IOPMLib.h:274-291,344-380,1014-1023`; `caffeinate(8)`.
6. **NETGEAR MR7450 user manual** 202-12721-02 (June 2025), pp. 32-33: Wi-Fi and Ethernet offloading, including dynamic switching on outages.
7. **CFM (read-only):**
   - `scripts/dependency_pins.env` at `ac981c3` (the 0.4 line): `:40-41` Go 1.27.1, `:45-46` govulncheck, `:47-64` sing-box 1.14.1 with its patch pairs and digests, `:68` the libbox tags, `:72-73` the SOCKS lifecycle patch; at `f5b425d`: `:37-38` Go 1.27.2 and its darwin-arm64 sha256, `:42-43` govulncheck, `:44-61` sing-box 1.14.2 with its patch pairs and digests, `:65` the libbox tags, `:69-70` the SOCKS lifecycle patch; and `native/macos/patches/sing-box-v1.14.2-security-dependencies.patch:714-727` (x/crypto v0.54.0 → v0.57.0, x/net v0.57.0 → v0.60.0)
   - 0.5 at `502adf9` (tag `v0.5.0`), which contains `f340fae` (2026-10-08, rejects REALITY without uTLS) and `e6c9e05` (commits `support_x25519mlkem768`: `subscription_import/sing_box.rs:252-263,795-817`; `subscription_import/clash/tls.rs:76-78`)
   - 0.4 `subscription_import/sing_box.rs:30-180,131-152,531-541` (0.5 `:131-158,558-568`); `clash/tls.rs:144-146` (0.5 `:252-253`); `HostBridge.swift:1603-1608`
   - 0.5 `crates/cfw-singbox-config/src/profile_validation.rs:17-18,624-660` (hop interval 5..=3600); CFM patch `common/tls/pinning.go:30-64` (pin verifier)
   - `docs/cfm-contract.md` cites every importer rule the exports meet, at both revisions
8. **crates.io sparse index** (2026-10-08): ssh-key 0.6.7 (sha2 ^0.10, ed25519-dalek ^2); x25519-dalek 3.0.0 and ed25519-dalek 3.0.0 (curve25519-dalek ^5, rand_core ^0.10, sha2 ^0.11); getrandom 0.4.3; uuid 1.27.0 (getrandom ^0.4); rcgen 0.14.10; ring 0.17.14 (getrandom ^0.2); socket2 0.6.5; tokio 1.53.2; security-framework 3.7.0.
9. **Providers:** [DigitalOcean per-second billing](https://www.digitalocean.com/blog/dropletplans-persecbilling-byoip-natgateway) and [user-data immutability](https://docs.digitalocean.com/products/droplets/how-to/provide-user-data/); [Mythic Beasts VPS API quickstart](https://beasts.org/support/api/vps/quickstart). All checked 2026-10-08.
10. **This Mac (2026-10-08):**
    - macOS 27.0 (26A428), MacBookPro18,2, Xcode 27.0, Swift 6.4, rustc 1.98.1, OpenSSH_10.3p1, Lima 2.1.2, Parallels `prlctl` present.
    - No Go on PATH. No QEMU. No `cargo-mutants`.
    - No M7 interface attached: the default route is Wi-Fi `en0`.
    - Revision 5: `pmset -g cap` lists `displaysleep`, `disksleep`, `sleep`, `womp`, `standby`, `powernap`, `ttyskeepawake`, `hibernatemode`, `hibernatefile`, `tcpkeepalive`, `lowpowermode` and `highpowermode`, with no `autorestart` and no `acwake`. `pmset -g custom` shows `sleep 0` and `displaysleep 0` on both AC and battery (§10.3).
11. **Xray v26.9.30 `b26a91de`, re-read for revision 5:**
    - `proxy/proxy.go:273-275` (uplink splice commented out), `:737-739` (splice on linux and android only), `:761-783` (spliced bytes counted when `ReadFrom` returns)
    - `proxy/vless/inbound/inbound.go:554-556` (XRV sets `CanSpliceCopy = 2`), `:591-592` (empty flow sets 3); `proxy/freedom/freedom.go:260`
    - `app/dispatcher/default.go:161-180` (user counters registered at dispatch); `app/stats/online_map.go:9-12,35-38` (loopback ignored); `app/stats/command/command.go:186-206` (`statssys`: uptime, Go `Alloc`/`Sys`)
    - `app/router/command/command.proto:15-31` (`RoutingContext`: source IPs, target IPs, target domain)
    - sing-box v1.14.2 `experimental/clashapi/connections.go:85-95` (`/connections`: source IP, destination IP, host)
12. **Console-review sources (revision 5; SMARTY's added in revision 6).** All were read on 2026-10-08 unless another date is given. Text extracts are in the session scratchpad, not in the repository.
    - **SMARTY (the decided line, §19.1):**
      - [SMARTY-TC]: [SMARTY Terms and Conditions V33](https://sundaecdn.blob.core.windows.net/files/SMARTY-Terms-And-Conditions.pdf), 30 Jul 2026: 1.1 (Hutchison 3G UK Limited trading as SMARTY), 2.2, 3.1–3.3, 5.4(b), 5.5(d), 5.15, 5.20, 5.21, 8.1(b), 9.1, 9.2, 9.4(d).
      - [SMARTY-PG]: [SMARTY Price Guide V42](https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf), 25 Aug 2026: p3 (5G included; a late renewal payment moves the cycle), p11 (no fair-use line, no speed restriction), p23 (binary units, re-sent packets, per full MB). The `SimPlan` record cites it as its terms (§7).
      - Help-centre articles at `http://help.smarty.co.uk/en/articles/<id>`, with the page date where recorded: 10235435 (VodafoneThree network sharing; 5 May 2026), 1155178 (no shaping or throttling; 27 Apr 2023), 5877334 (5G), 952716 and 4227332 (renewal and billing), 4670061 (5G and 4G bands; 9 Dec 2025), 1155220 (APN; 18 Mar 2026).
      - The [plan page](https://smarty.co.uk/plans/unlimited), undated: £20 on a one-month rolling plan, with no credit check.
      - Unverified forum claims of cut-offs near 100 GB appear on no SMARTY page and are not cited as fact.
    - **EE (history; EE is not the line, §19.1):**
      - [SIM Only Pay Monthly Plan Terms and Price Guide](https://ee.co.uk/content/dam/help/terms-and-conditions/price-plans/mobile/pay-monthly-price-plans/ee-simo-plan-tncs-from-7-august-2025.pdf), from 7 Aug 2025, updated 5 Mar 2026: p. 1 personal use and no selling of access; p. 2 the 600 GB clause; "What do you mean by data usage?" (units, both directions); 30-day Essentials £38; +£2.50 each 31 March.
      - [Data SIM guide](https://ee.co.uk/content/dam/help/terms-and-conditions/price-plans/mobile/ee-data-sim-plans-tncs-29082024.pdf), from 29 Aug 2024, updated 25 Mar 2026: 30-day Essentials £35; +£1.50 each 31 March.
      - [Mobile Pay Monthly Network Terms v11](https://ee.co.uk/content/dam/help/terms-and-conditions/mobile/pay-monthly/network/ee-mobile-paym-network-terms-160126-a.pdf), 16 Jan 2026: 4.7.11–4.7.13, 6.2, 6.3.
      - [Traffic Management KFI](https://ee.co.uk/content/dam/help/terms-and-conditions/broadband/network-traffic-management/traffic-management-key-facts-indicator-april-2022-final-version.pdf), April 2022: QCI 8 → 9 on congested cells, until the end of the billing cycle.
      - [Student Discount v2](https://ee.co.uk/content/dam/help/terms-and-conditions/offers-promotions/ee-student-discount/EE%20Student%20Discount%20Terms%20and%20Conditions%20-%20from%2021%20April%202026.pdf), 21 Apr 2026.
      - The "12 or more tethered devices" clause, in the [Unlimited T&Cs](https://ee.co.uk/content/dam/ee-help/Termsandconditions/Unlimited%20Terms%20and%20Conditions.pdf) (18 Jan 2021) and the [handset terms of 7 Aug 2025](https://ee.co.uk/content/dam/help/terms-and-conditions/price-plans/mobile/ee-pay-monthly-plan-t-and-cs-from-7-august-2025.pdf); absent from the [handset terms of 20 Aug 2026](https://ee.co.uk/content/dam/help/terms-and-conditions/price-plans/mobile/pay-monthly-price-plans/EE%20pay%20monthly%20plan%20T_Cs%20-%20from%2020%20August%202026.pdf).
      - [5G standalone help page](https://ee.co.uk/help/mobile/manage-use/using-phone-features/5G-standalone), updated 24 Apr 2026.
    - **ASA:** [ruling on EE Ltd](https://www.asa.org.uk/rulings/ee-ltd-a24-1253564-ee-ltd.html), 21 May 2025.
    - **Other carriers:**
      - [O2 Unlimited Tariff Terms](https://www.o2.co.uk/termsandconditions/mobile/unlimited-tariff-terms), undated: 3.2–3.5.
      - [Vodafone Consumer AUP](https://binaries.vodafone.co.uk/gbnnsauqav4t/73kvRsdntiDauH0KUyhwu3/ac6a07014b341bc907436c49c7d47561/acceptable-use-policy-april-2025.pdf), 8 Apr 2025.
      - Opensignal via [ISPreview](https://www.ispreview.co.uk/index.php/2026/01/ee-wins-big-in-opensignal-study-of-best-4g-and-5g-uk-mobile-networks.html), 29 Jan 2026. Re-fetching returned HTTP 429.
    - **NETGEAR:**
      - Nighthawk M7 Pro/Ultra user manual 202-12721-02 (June 2025), cited by printed page: 9 (ports), 12–14 (charging, Plugged-In mode), 15 (power on), 22 (USB tethering powers it on; Ethernet off by default), 26 and 47 (firmware updates), 47–48 (Ethernet port), 62 (SIM PIN), 65 (data-usage reset date), 74 (thermal levels, 0–35 °C), 76 (external antenna).
      - [MR7450 UK page](https://www.netgear.com/uk/mobile-wifi/hotspots/mr7450/), undated.
      - [eternalegypt](https://github.com/amelchio/eternalegypt/blob/master/eternalegypt/eternalegypt.py), `information()`: the `model.json` leaves it reads and the four it drops.
    - **Durham University:** [Student IT Regulations v2.5](https://dur.ac.uk/media/durham-university/professional-services/cis/Student-IT-Regulations-2.5---approved.pdf) (publication date "xxx"): regulations 1.1, 2.3 and 5.1.
    - **PRC:** [Interim Provisions Governing the International Networking of Computer Information Networks](https://www.cac.gov.cn/1996-02/02/c_126468621.htm), State Council Order 195, amended 20 May 1997: Art. 6, Art. 14.
    - **Apple and macOS:**
      - [Apple support 102338](https://support.apple.com/en-gb/102338), 9 Apr 2026 (Charge Limit).
      - [Apple HT208352](https://support.apple.com/HT208352), 15 Apr 2025 (iCloud in mainland China operated by GCBD).
      - [eclecticlight.co](https://eclecticlight.co/2025/11/06/how-tahoe-26-1-has-enabled-automatic-security-updates/), 6 Nov 2025 (Background Security Improvements).
    - **UK data protection:**
      - [ICO, identifiers](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/personal-information-what-is-it/what-is-personal-data/what-are-identifiers-and-related-factors/).
      - [ICO, exemptions](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/exemptions/a-guide-to-the-data-protection-exemptions/), updated 8 Mar 2024.
      - UK GDPR [Art. 5](https://www.legislation.gov.uk/eur/2016/679/article/5) and [recital 26](https://www.legislation.gov.uk/eur/2016/679/introduction).
    - **Providers:**
      - DigitalOcean: [AUP](https://www.digitalocean.com/legal/acceptable-use-policy), 20 Mar 2026; [Droplet pricing](https://www.digitalocean.com/pricing/droplets); [bandwidth billing](https://docs.digitalocean.com/platform/billing/bandwidth/), last verified 14 Sep 2026.
      - [Mythic Beasts VPS pricing](https://www.mythic-beasts.com/order/vps).
    - **Alerting:**
      - [ntfy docs](https://docs.ntfy.sh/): "topic names are public".
      - [Healthchecks.io pricing](https://healthchecks.io/pricing/): Hobbyist, $0, 20 checks.
      - [Pushover pricing](https://pushover.net/pricing).
    - **Existing panels:** [3x-ui](https://github.com/MHSanaei/3x-ui) v3.9.0 (released 2026-10-03); [Marzban](https://github.com/Gozargah/Marzban) `app/telegram/handlers/report.py:196-210`.
13. **M2a capture, 2026-10-13:** the redacted MR7450 `model.json` (outside the repository, SHA-256 `5f9e62c4…7709464`), re-redacted into `contract/router-fixtures/mr7450-ntgx75-10.04.43.01.json`; `docs/measurements/M2.md`.

---

## 22. Implementation plan

Every milestone ends with zero errors and zero warnings in each lane it touches, every new invariant test mutation-checked, and the results recorded in the PR. "Today on this Mac" means it needs neither the M7 nor a VPS. Downloads of pinned toolchains and sources, and installing tools (`cargo-mutants`, the musl targets), still need the user's approval at the time.

| # | Milestone | Needs |
|---|---|---|
| M0 | Repository, toolchains, pinned engines | Rust skeleton on this Mac (bounded `target/`; done); engine builds on the research computer (D-7; open) |
| M1 | Pure core | This Mac (bounded `target/`, cleaned at the end): **complete and committed (4a95ee0, 2026-10-08)**; the revision-5 console foundations and the revision-6 code built on it are pending the operator's commit; L2 engine checks on the research computer (open) |
| M2a | Field spike, part 1: the M7 alone | The M7; the SMARTY SIM (F1) for every radio, placement, antenna, band, thermal-under-load and byte step, once it arrives (about 12–13 October) and is activated, with only the SIM-less steps before then (the operator has no other SIM for the M7); a USB-C 2.5GbE adapter; the user present; no VPS. From 2026-10-09 |
| M2b | Field spike, part 2 | An hourly London VPS (D-2), the SMARTY line (F1), the user present |
| M3 | Netns e2e | Research computer (Lima) and hosted CI (D-7) |
| M4 | VPS agent and VM lanes | Hosted CI (KVM) and the research computer (D-7) |
| M5 | Mac daemon and lab lanes | This Mac today; L6-bypass needs the user |
| M6 | Real CFM in the lab | This Mac today, driven by the user |
| M7 | Swift app, power helper, release lane | This Mac today; signing by the user |
| M8 | First London VPS and pilot | The M7, the SMARTY line, a VPS, a trusted user in China, D-1 with F20, and CFM's 0.5.x release with the mainland China direct switch (F10) |
| M9 | Operations | Two VPSs |
| M10 | Shaping and placement (optional) | Field data from M8 |

M2 (M2a and M2b) can run in parallel with M3–M7 as soon as the hardware is attached. Its recorded values (keepalive, `EgressCheck`, `InterfaceSelector`, `FlowCap`, `UplinkBaseline`, and the router endpoint and identity) are inputs to M5 and M8, not blockers for M3–M7, which use lab values.

### M0 — Repository, toolchains, pinned engines (Rust here; engines on the research computer, D-7)

**Deliverables:**
- The repository skeleton from §6: GPL-3.0-or-later `LICENSE`, `rust-toolchain.toml` (1.98.1), workspace lints, and a `deny.toml` with `multiple-versions = "deny"` and justified skips.
- Empty crates with the declared edges.
- `xtask` with `ci`, `graph-check`, `kinds-coverage`, `engines {build,verify,upstream-tests,audit}`, `govulncheck` and a `release-verify` skeleton.
- `engines.lock.toml` covering:
  - the Go tarball sha256;
  - Xray v26.9.30 with the REALITY replace to e1986a4;
  - sing-box v1.14.2;
  - geodata;
  - RealiTLScanner.
- Engine builds: `mooring-exit`, `mooring-probe` (darwin-arm64), `mooring-hy2` and `xray` (linux-amd64 and arm64).
- The musl `mooring-agent` stub.
- XcodeGen `apple/project.yml` and the `MooringKit` package.
- The REALITY ancestry check, recorded.

**Status 2026-10-23 (engines built on hosted CI, D-7):** `.github/workflows/engines.yml` builds every engine from `engines.lock.toml`'s pins: go1.27.3 (GO-2026-6809), Xray v26.9.30 with the REALITY replace to e1986a4 and x/net v0.61.0, and sing-box v1.14.2 with x/crypto v0.58.0, x/net v0.61.0 and grpc v1.84.0 (go directive 1.26.0), each bump answering a reachable govulncheck finding or an advisory the pinned version carries (the lock says which). Run 39915405073 built everything twice from clean caches, byte for byte the same, and passed the build-information gate, upstream's package tests and govulncheck on all six outputs; the output digests it printed are pinned, and run 39918017282 rebuilt and verified against them. `xtask engines-{pins,prepare,build,verify,metadata,govulncheck}` replace the planned `engines {build,verify,upstream-tests,audit}`; upstream's tests are run by the workflow. RealiTLScanner v0.2.3 joined the build the same day (`darwin-arm64/realitlscanner`, §11.7): run 39938908454 built it twice, byte for byte the same, with its build information as its recipe says (it stamps no version) and govulncheck passing; its digest is pinned, and run 39941124325 verified every output against the lock. Still open from the list below: the recorded REALITY ancestry check.

**Status at revision 4.**
- *Done on this Mac:* the skeleton, `LICENSE`, `rust-toolchain.toml` (1.98.1), workspace lints, `deny.toml` with justified skips, the crates with their declared edges (now implemented, M1), `xtask ci`, `graph-check`, `kinds-coverage`, `deny-skips` and `clean`, and the input pins of `engines.lock.toml`: the Go 1.27.1 tarball digests (1.27.2 since revision 8, §4), Xray v26.9.30 with the REALITY replace to e1986a4, and sing-box v1.14.2 with its role tags.
- *Open, on the research computer or later:* the engine builds and their output digests (empty in `engines.lock.toml`), the geodata zip digest, RealiTLScanner, `xtask engines {build,verify,upstream-tests,audit}`, `govulncheck`, the `release-verify` skeleton, the musl `mooring-agent` stub, XcodeGen `apple/project.yml` and `MooringKit`, and the recorded REALITY ancestry check.

**Verification:**
```
cargo xtask ci        # fmt --all --check; clippy --workspace --all-targets --locked -D warnings;
                      # cargo deny --all-features --locked check -D warnings; graph-check; kinds-coverage; deny-skips;
                      # acceptance (D-9); cargo nextest run --workspace --locked; cargo test --workspace --doc --locked
cargo xtask engines build --clean && cargo xtask engines build --clean && cargo xtask engines verify
                      # byte-identical unsigned outputs = engines.lock.toml; `go version -m` shows go1.27.x, CGO_ENABLED=0,
                      # -trimpath, tags incl. badlinkname,tfogo_checklinkname0, ldflags incl. -checklinkname=0
cargo xtask engines upstream-tests   # go test: xray ./proxy/vless/... ./transport/internet/reality/...;
                                     # sing-box ./protocol/hysteria2/... ./protocol/wireguard/...
cargo xtask govulncheck              # pinned govulncheck per role tag set; zero reachable findings or a reviewed bump
git -C <reality checkout> merge-base --is-ancestor e1986a4 8cdf7bf9   # records D-3 premise
cargo build -p mooring-agent --release --target x86_64-unknown-linux-musl   # and aarch64; links with rust-lld
xcodegen generate --spec apple/project.yml
xcodebuild -project apple/Mooring.xcodeproj -scheme Mooring -configuration Debug CODE_SIGNING_ALLOWED=NO build
xcrun swift build --package-path apple/Packages/MooringKit && xcrun swift test --package-path apple/Packages/MooringKit
```

### M1 — Pure core: model, keys, export, render, agent-proto types, store (this Mac, bounded target/)

**Status (revision 6): complete and committed as 4a95ee0 on 2026-10-08.** The user approved that commit, which also confirmed D-8 and D-9 (§20). Revision 4 recorded M1 as pending the commit. `cargo xtask clean` (D-7) runs once the work built on M1 is committed.

**Delivered:**
- **`model`:** every type in §7, with the revision-4 changes recorded there; the `SPECIAL_V4`, `PortPlan`, `EgressCheck` and cross-entity invariants; `Bookkeeping`; `target::qualify`; verdict precedence.
- **`keys`:** X25519 (stored clamped, as `xray x25519` and `wg genkey` print keys), ed25519 plus the OpenSSH encoder, credentials (UUIDs, short ids, passwords, user ids), and the P-256 certificate. The pins are derived by `export`, not stored.
- **`export`:** both emitters, selected by `ClientProfile`; shape enumeration (10 `(shape, client line)` entries); certificate pin derivation and runtime checks; the probe outbounds.
- **`render`:** `xray.json`, `hy2.json`, `wgexit.conf`, `nftables.conf`, `watch.json`, cloud-init, and the Mac exit and prober configs; the model ↔ wire conversions. The host profile is data in `agent-proto` (§8.6).
- **`agent-proto`:** wire types and framing, roles, the host profile, the VPS contract names, `StderrTail`, and frozen-core goldens of the requests and their replies.
- **`store`:** locks, CAS, atomic writes, the ordered secret writes, the migration-chain scaffold, the in-memory `SecretStore`, and the V1 golden files.
- **`mooring-fixtures`:** four deterministic fixture deployments, a test-only crate (§6.1).
- **`xtask`:** `ci`, `graph-check`, `kinds-coverage`, `deny-skips`, `acceptance` and `release-acceptance` (D-9), and `clean`.
- **Goldens** for 1, 3 and 20 users across 1 and 2 nodes, plus the cloud-init, export and agent-proto frozen-core goldens.
- **Docs:** `docs/cfm-contract.md`, `docs/engines.md`, `contract/cfm-manifest.toml` and `contract/cfm-acceptance.toml` (every entry pending until M6).

**Verification run on this Mac:**
```
cargo xtask ci          # every step listed under M0 above: zero errors, zero warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```
- Both passed with zero errors and zero warnings at the M1 gate. The D-9 change (the `acceptance` step and the acceptance reader moving to `xtask`) landed after that run, so the gate is run again before the operator's commit.
- The `ci` tests include the RFC 7748 and RFC 8032 vectors, the OpenSSH encoder against `/usr/bin/ssh-keygen -y`, `-l` and `-F` (OpenSSH_10.3p1), the certificate's properties, DER and SPKI against `/usr/bin/openssl` (LibreSSL 3.3.6 here), and the insta goldens with their directory-equality checks.
- Every new invariant test was mutation-checked by hand: the production code was broken, the test was seen to fail, and the code was restored. `cargo-mutants` is not installed on this Mac, so the planned `cargo mutants --in-diff -p mooring-model -p mooring-render -p mooring-export` has not run.

**Moved to later milestones, or still open:**
- The Keychain `SecretStore` implementation: M5. It must keep the trait's semantics: `put` is an upsert (`SecItemAdd`, then `SecItemUpdate` on a duplicate), deleting an absent item is `SecretMissing`, and `doctor` will need a `list` the trait does not have yet.
- `xtask engines {build,verify,upstream-tests,audit}`, `govulncheck` and `cfm-client`: M0, on the research computer (D-7). `xtask lane <name>`: with the lanes it runs. `xtask release-verify`, which runs `release-acceptance`: M7.
- **L2 has not run.** It needs the research computer:
  ```
  cargo xtask lane l2   # in a Debian 13 VM: xray run -test / xray convert pb -debug -type assertions; mooring-hy2 check
                        # (warn-level copies); nft -c -f; wg-quick strip; cloud-init schema --config-file; xray x25519 -i;
                        # sing-box check of exports under upstream + CFM-patched 1.14.1/1.14.2 (xtask cfm-client --manifest);
                        # all negative controls trip
  ```
  Until it runs, the rendered syntax of `nftables.conf`, `wgexit.conf` and cloud-init, and Xray's semantic reading of `xray.json`, remain *(inference)*.
- graph-check's `x86_64-unknown-linux-gnu` build of the pure crates: with the Linux e2e lane (M3, research computer or hosted CI); this Mac has no such target (§6.1).
- The `lab` feature and `NodeAddress::Lab`: M5.
- The macOS-gated `ssh-keygen` and `openssl` cross-checks have run only on macOS. A Linux run of equivalent checks is unverified.

**Format note.** The V1 `state.json` shape changed during M1, before any release (certificate-only `Hy2Server`, unit `RevokePending`, required `hard_stop_bytes` and `target` keys, no serialised `Uuid`), without a version bump. A `state.json` written by an earlier development build does not decode. From the operator's commit on, the V1 golden files pin the format. Version 2 is in the same position: it has been neither committed nor released, so revision 6 extended it in place and regenerated its goldens rather than adding a version 3; the V2 goldens pin the format from its commit on. **One exception, 2026-10-23 (M5a):** the switch to 1pMobile replaced the SIM policy's `bill_day` with `cycle` (`CycleRule`) and gave `unlimited_fair_use` its required `window`. Version 2 was committed by then but never written outside the tests: `exit init` did not exist, so no deployment held a state, on this Mac or anywhere else. It was therefore extended in place once more, with both V2 goldens regenerated (the V1 goldens are byte-identical). From the first `exit init` on, any change needs a version 3 and a migration step.

**Console foundations (revision 5, 2026-10-08).** These were built on top of M1 on this Mac. They are not in 4a95ee0 and are pending the operator's commit. All of it is pure Rust and was decision-neutral when built.
- **`model` and `store`:**
  - state version 2 (§7), with a real V1 → V2 migration, the new goldens `state-v2.json` and `state-v2-every-variant.json`, and the V1 goldens unchanged;
  - `CalendarDate`, `BillDay`, `SimPlan`, `StopPolicy`, `SimThresholds` with the unrecorded-plan ceiling, `EE_FAIR_USE_600_GIB`, `UplinkBaseline` (revision 6 removed the ceiling and `EE_FAIR_USE_600_GIB` with EE);
  - `UserStatus::Suspended`, `UserPolicy`, `PublicAlias` (drawn by `mooring-keys`; no text constructor), `AgreementRecord`, `CapacityPolicy`, `NonEmptySet`;
  - the frozen version-1 types (`crates/model/src/v1.rs`), checked with the version-1 cross-entity rules only;
  - the store's transition guard (`UserStatusEdited`, §7).
- **`render`:** `DuplicateCredential{node, kind, first, second}` (§8.1).
- **`agent-proto`:**
  - `UsageSeries`, `Events` (consecutive numbers per page), the `StatusV1` additions, the new watch conditions (`AccountingCanaryMissing{inbounds}`) and the new agent errors (§11.1, §14);
  - six protocol-1 goldens in `contract/agent-proto-golden/`; every contract file that existed before them is byte-identical.
- **`daemon-core`** (§6.1, §15): `MacStatusV1`, usage aggregation over every node that may have counted traffic and activity from fresh polls only, the SIM forecast, the capacity monitor, the alert machine, quota and expiry evaluation, the router-status types and the foreign-network check; `contract/status-fixtures/` holds the three scenario documents and `variants.json`.
- **Verification run** on this Mac (2026-10-08), after the review fixes of the same day:
  - `cargo xtask ci` passed all 9 steps: fmt; clippy with `-D warnings`; deny (advisories, bans, licenses, sources); graph-check (9 crates match the table); kinds-coverage (all 386 variants of 36 `Kind` enums are named by tests); deny-skips; acceptance (10 shapes recorded, 0 accepted, 10 pending); nextest (716 of 716 passed); doc tests.
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` passed with no warnings.
- **Mutation checks.** Every new invariant test was mutation-checked by hand: 49 mutants for the state work, 48 for the render and protocol work, 116 for `daemon-core`, and 51 for the review fixes. All were stopped, by a failing test or by a compile-time check; the few that survived a first run had their tests strengthened and now fail.
- **Still open:** `fieldkit`, and everything in §15 that is marked plan. The D-7 `cargo xtask clean` still runs once the work is committed.

**Revision 6: the operator's decisions in code (2026-10-08).** Built on this Mac on top of the console foundations, pure Rust, and pending the same commit. No new dependency and no new crate edge.
- **`model`, `store` and `mooring-fixtures`** (§7):
  - `Carrier::Smarty` (EE removed); `PlanKind::{Unlimited, UnlimitedFairUse { fair_use_bytes }, Capped}`, with `line()` now an `Option`; the stop rules without a line, `SimThresholds::budget_bytes()`, and the removal of `UNRECORDED_PLAN_CEILING` and `EE_FAIR_USE_600_GIB`;
  - the pilot constants `PILOT_SIM_WARN_BYTES`, `PILOT_SIM_HARD_STOP_BYTES`, `PILOT_MAX_ACTIVE_USERS`, `CapacityPolicy::PILOT`, `AutoQuotaPolicy::PILOT`, `PILOT_DIGEST_AT` and `AlertSettings::pilot()`;
  - P0-1: `SimPolicy::new` takes a plan, `DeploymentInit`, `Deployment::new` returning `PlanNotRecorded`, and `Store::init(DeploymentInit)`, which validates before touching any file;
  - the F4, F5 and F6 records (`quota.rs`, `viewer.rs`, `alerting.rs`), their invariants, the alert `SecretRef`s (since 2026-10-09 one deployment-level topic and two checks per channel node), and retirement dropping a node's channels;
  - the single V1 lift rule (every explicit stop kept, a missing one refused);
  - the fixtures run the SMARTY plan at the pilot thresholds with no cap, no automatic quotas and no alert channels, and `2-nodes-3-users` has one viewer.
- **`agent-proto` and `render`** (§8.6, §11.1, §15.8, §15.9): `Role::Viewer` with `Role::may_close_gate_for`; `PutMacReport` and `MacReport` with `MacReportV1`, `ReportUserId` and `NodeName`; the notice grammar and `NtfyMessage`; `dead_man_pings` and `WATCH_STALE_SECS`; host profile 2 with `mooring-view` and `sshd_effective_lines`; `ManagedFile::ViewerKeys` and its render.
- **`daemon-core`** (§15.3, §15.8, §15.9): `automatic_quota`, `effective_quota` and `evaluate` over the deployment; `notify::alert_message` and `notify::digest_message`; `report::project`; the conversions to the report's names in `wire.rs`; a forecast test for a plan without a line (warning and hard stop only).
- **Goldens and contract files.** Every golden and contract file that existed before revision 6 is byte-identical except these:
  - the two V2 state goldens in `crates/store/src/tests/golden/`, regenerated (`state-v2.json` SHA-256 `fed6e86b…`, `state-v2-every-variant.json` `8ff37ce9…`); the V1 goldens keep `9d264466…` (`state-v1.json`) and `180d2efa…` (`state-v1-every-variant.json`), unchanged since 4a95ee0;
  - the four status fixtures, regenerated for the pilot thresholds and the line-less plan; all of them show the router's carrier name as `SMARTY` *(inference until the M2a capture)*, `variants.json` since the review fixes below, and `degraded.json` also holds the SIM forecast alert since then.
  - New: the `put_mac_report` and `mac_report` request and reply goldens in `contract/agent-proto-golden/`, and a `vps-<node>-viewer_authorized_keys.snap` for every fixture node. The frozen-core goldens and the console frames are byte-identical.
- **Verification run** on this Mac (2026-10-09), after the three parts were built:
  - `cargo xtask ci` passed all 9 steps: fmt; clippy with `-D warnings`; deny (advisories, bans, licenses, sources); graph-check (9 crates match the table); kinds-coverage (all 446 variants of 39 `Kind` enums are named by tests); deny-skips; acceptance (10 shapes recorded, 0 accepted, 10 pending); nextest (802 of 802 passed, up from 716); doc tests.
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` passed with no warnings.
- **Mutation checks.** The new invariant tests were mutation-checked by hand, each file restored and checked by SHA-256: 47 mutants for the model and store work, 35 for the protocol and render work, and 32 for `daemon-core`. All of those were stopped. Two survived a first run: one exposed a random bound test, which became an exhaustive test over its whole domain (`BudgetPercent`, `SimFactor`, `WallClockTime`), and the other was an equivalent mutant. Those runs did not reach every arm of the report projection (`exit_phase` beyond three phases, the radio, saturation and plan-line mappings) nor the digest without a hard stop; the review of 2026-10-09 found that, and the fixes below add a test and a mutant for each.
- **Review fixes (2026-10-09).** Four reviews (architecture, implementation, tests, security) of revision 6 found no P0 or P1 defect; their P2 and P3 findings were fixed as follows, each behaviour defect first reproduced by a failing test:
  - P0-1 after init: `change_config` refuses a change that edits the SIM policy and leaves its plan unrecorded (`InvalidChange{PlanNotRecorded}`, §7), so a recorded plan cannot be un-recorded; `init_refuses_an_unrecorded_plan` now requires the store directory to stay empty, `state.lock` included.
  - The report: `ReportBandNumber` (1..=999, exactly the router's `BandNumber`, compared for every `u16`) replaces the bare `u16` band number, which shrinks `MAX_MAC_REPORT_BYTES` to 178,874; every arm of the projection has an exact test (every exit phase, also in the digest; every radio access, band system and reading slot; every saturation with its time; both plan lines; the router's poll time), and a canary test plants grammar-shaped text (`alicesmith`, `phone`, `phone0`) in the fields the report drops; §15.9 now says what the grammars enforce and what only the projection does.
  - The viewer's stop: `GateStopUnconfirmed{waited_secs}` and `VIEWER_STOP_WAIT_SECS` (15 s) make a stop the watch has not confirmed an error, never a `GateClosed` (§11.3).
  - The digest time must be 02:00 or later in Europe/London (`DigestTimeTooEarly`, §15.8); a weak-signal notice shows RSRP rounded down; the digest without a hard stop is tested.
  - Host profile 2 keeps its `Match` block: OpenSSH's sources and `sshd -T` with 10.3p1 show the block ends with the drop-in and `root` keeps the default keys file (§8.6). §8.6, `ManagedFile::ViewerKeys` and `sshd_effective_lines` now state that sshd reads the keys file as `mooring-view` (0644 `root:root`, directories 0755) and that `AllowUsers` drift is an exact multiset comparison; `docs/engines.md` has a `viewer_authorized_keys` section.
  - Tests: the per-byte id agreement in `wire_rules.rs` now starts each rule from an id it accepts; the degraded scenario raises its SIM forecast alert and documents its 18 uncapped users; `variants.json` and its router builder say `SMARTY`.
  - Held for the operator at that point, and decided on 2026-10-09 (below): F4's meaning of N (§15.3, §20 F4) and F6's single topic against the per-node topics first built (§20 F6, §13.4). Recorded without a code change: the model admits any explicit stop on a plan without a line, guarded by an M5 acceptance item (§7, §22 M5).
  - Golden and contract changes: `contract/status-fixtures/degraded.json` (the forecast alert) and `variants.json` (`EE` → `SMARTY`, two lines); no state, protocol or render golden changed, the V1 and V2 state goldens included.
  - Gates on the final tree: `cargo xtask ci` passed all 9 steps (nextest 816 of 816; kinds-coverage all 449 variants of 39 `Kind` enums), and the doc build passed with no warnings. 41 hand mutants against the new tests (store 4, model 3, protocol and render 7, `daemon-core` 27), each recorded with the tests that must stop it, were all stopped by those tests (one first written did not compile and was rewritten), each file restored and checked by SHA-256.
- **Decisions of 2026-10-09.** The two points held above were decided on 2026-10-09 by the recommended default, following F4/F6 as stated (§20 F4, F6). No state type or encoding changed, and no golden or contract file did; what changed in version 2 is a meaning and a Keychain name: `auto_quota.from_active_users` now counts this cycle's suspensions for quota beside the users active now, and the topic's Keychain account is `alert/topic`, not `node/<n>/alert-topic`. Version 2 is unreleased, so no stored state or Keychain holds the old form.
  - F4, latched per cycle: `policy::automatic_quota(&Deployment, now)` counts N, and the threshold, over the users `Active` now and those suspended `QuotaExceeded{cycle_start}` in the current cycle; `evaluate` reuses the cycle it computes once; `AutomaticQuotaZero` names the users sharing the budget (`sharing`). Reproduced first: the old test, set to expect the N = 6 share after one suspension for quota, failed with `Ok(None)`. It is replaced by `a_quota_suspension_keeps_every_share_for_the_cycle`, `a_quota_suspension_from_an_earlier_cycle_does_not_count`, `other_suspensions_do_not_count` and `five_active_and_one_suspended_for_quota_this_cycle_share_as_six`; the property test `the_budget_is_shared_by_the_active_and_this_cycles_quota_suspensions` replaces `the_pilot_cap_keeps_automatic_quotas_dormant`, and `only_active_users_count` became `revoking_users_share_nothing_and_admission_lowers_every_share` (§15.3).
  - F6, one topic: `SecretRef::AlertTopic` (account `alert/topic`) replaces the per-node `NodeAlertTopic`; `SecretRef::node` returns an `Option`, `None` only for the topic; `SecretEntry::AlertTopic` and `SecretSnapshot::alert_topic()` follow; `required_secrets` lists the topic while `alerting.channels` is not empty. The store's ordered writes needed no change. New tests: `the_alert_topic_is_required_iff_a_channel_node_exists`, `only_the_alert_topic_belongs_to_no_node` and the retirement test (model); `the_alert_topic_is_shared_and_outlives_one_channel_node` and `the_alert_topic_is_deleted_after_the_commit_that_leaves_no_channel_node` (store); `alert_channel_secrets_reach_no_rendered_file` (render).
  - This document: the operator has no EE SIM, so M2a does the SIM-less steps until the SMARTY SIM is active (§22 M2a); §7 names `RuntimeIntent.revision` as the code does.
  - Gates on the final tree: `cargo xtask ci` passed all 9 steps (nextest 823 of 823, up from 816; kinds-coverage all 449 variants of 39 `Kind` enums), and the doc build passed with no warnings. 28 hand mutants against the new and changed tests (`daemon-core` 11, model 14, store 3), each recorded with the tests that must stop it, were all stopped by those tests, each file restored and checked by SHA-256.
- **Review of the decisions (2026-10-09).** Four reviews (architecture, implementation, tests, security) of the decisions above found no P0 or P1 defect; their P2 and P3 findings were fixed as follows:
  - F4 after an edit of the bill day: a suspension for quota counted only while its `cycle_start` equalled the current cycle's start, so an edit that moved that start back left a suspension made inside the current cycle neither counted nor lapsed, and the quota switched itself off again. Reproduced first: `a_quota_suspension_counts_after_the_bill_day_moves_the_cycle_start_back` failed with `Ok(None)`. That first fix compared the recorded start with the current cycle's (`>=`); the independent verification found that it still failed for a forward move, the direction of SMARTY's own late renewal (§7, `BillDay`), and counted a start recorded after now until that date. Reproduced first: `a_quota_suspension_counts_after_the_bill_day_moves_the_cycle_start_forward` (bill day 5 → 8) and `a_forward_edit_of_the_bill_day_keeps_the_share_enforced` (28 → 1) failed with `Ok(None)`, and the evaluation then proposed nothing (`Ok([])`) for a user over the N = 6 share. One private predicate, `quota_suspension_holds`, now decides between held and lapsed on when the suspension was made (`UserStatus::Suspended.since` at or after the current cycle's start), not on the start it records, which stays the record of the cycle exceeded; the evaluation's time and its cycle are computed together (`Moment`), so they cannot disagree. A suspension for quota made after `now` is the new `PolicyError::QuotaSuspensionAfterNow{user, since, now}`, by the rule that already makes usage past `now` `UsageAfterNow`, rather than held until its own cycle ends (`a_quota_suspension_after_now_is_an_error`). The M5 resume is to list lapsed users with the same predicate, and the apply records each suspension at its evaluation's `now` (§7, §13.6, §15.3, §20 F4, M5). The property test varies the instant on both sides of the cycle's start and the recorded start independently of it.
  - `automatic_quota` refusing a time outside the calendar is now tested itself, with and without a policy (`the_automatic_quota_refuses_a_cycle_outside_the_calendar`), not only through `evaluate`.
  - This document: a rotation keeps the ntfy topic only if the replacement or the standby gets its channels before the last channel node is retired, which §13.4's procedures now do, with M5's `node retire` refusing to drop the topic unless confirmed (§13.4, §15.8, §20 F6); replacing the topic takes two configuration changes, M5's `alert rotate-topic`, after a node that may be compromised is retired or a phone is lost (§1.2, §7, §12, §15.3, §15.9); the resume at the cycle boundary stays within the cap, one change per user, earliest suspension first, and never blocks the run (§13.6, M5 acceptance); other departures still lower N and can switch the quota off, and the 80 % bound is stated as it holds (§15.3, §20 F4); the cap wording (§15.3, `policy.rs`) and the state-version wording above.
  - A nextest LEAK: one full CI run of these fixes reported `mooring-store`'s `init_refuses_an_unrecorded_plan` as leaky (passed, its output pipe still open 100 ms after it exited). The test starts no process or thread and writes only to its temporary directory. Alone under nextest it passed 200 runs without a leak; 100 runs of the whole `mooring-store` suite (6,700 test processes) had 9 leaks spread over 8 different tests, in-memory ones included, and 60 runs of the same suite with `--test-threads 1` (4,020) had none. A scratch probe outside the repository, 300 tests that each list their own descriptors, found 153 of 18,000 test processes holding pipe descriptors they never opened, and each of its 51 runs with a leak had such a process. The cause is in the runner on macOS, not in this repository: the Rust standard library there creates a pipe and only then marks it close-on-exec (macOS has no `pipe2`), and `posix_spawn` passes every descriptor not yet so marked, so a test the runner starts from another thread in that window keeps another test's output pipe open after that test exits. No retry, timeout or leak setting was added; the final CI run had no leak.
  - Golden and contract changes: none; the V1 goldens keep `9d264466…` and `180d2efa…`, the V2 goldens `fed6e86b…` and `8ff37ce9…`.
  - Gates on the final tree: `cargo xtask ci` passed all 9 steps (nextest 828 of 828, up from 823, with no leak; kinds-coverage all 450 variants of 39 `Kind` enums, `PolicyErrorKind::QuotaSuspensionAfterNow` the new one), and the doc build passed with no warnings. 7 hand mutants against the first fixes (`daemon-core` 7: the recorded-start predicate 4, the calendar error 2, the test helper 1) and 13 against the instant predicate (`daemon-core` 13: what decides held or lapsed 4, the error after `now` and its scope 6, the bill day of the cycle 1, the cycle a proposed suspension records 1, the error kind 1) were all stopped by the tests recorded for them, each file restored and checked by SHA-256.

### M2 — Field spike (in two parts since revision 5; user present)

Revision 5 splits M2 in two:
- **M2a** needs only the M7, and starts on 2026-10-09.
- **M2b** needs an hourly London VPS (D-2).

Every `fieldkit` measurement needs a VPS sink, so M2a used tools built into macOS and the M7's own web UI. `fieldkit` exists since 2026-10-22 (below).

**Deliverables:**
- `docs/measurements/M2.md` with the raw logs. Raw M7 captures stay outside the repository (§15.6).
- `fieldkit`, a dev-only darwin and linux-musl tool, for M2b. Its VPS-side sink was to be built on the research computer or in CI, because this Mac had only the `aarch64-apple-darwin` target and no musl linker (critique, section D); since 2026-10-22 it is built here with the `x86_64-unknown-linux-musl` target and `rust-lld` (§6.2). Its loopback self-tests run here.

**Recorded decisions:**
- **M2a:**
  - the M7's attachment: the Ethernet adapter's BSD name, and the M7 gateway's link-layer address, which is the router identity of §15.6;
  - the router endpoint (exactly one path, or "no JSON interface") and whether a login is needed;
  - the placement and the antenna, on the SMARTY SIM;
  - the thermal and power-cut results;
  - *(revision 6)* the SMARTY SIM's activation date, which is the bill day (§7); the APN the M7 uses; the bands and radio access types it attaches with; the carrier name it displays; and what SMARTY's usage view shows for an Unlimited plan.
  - **Status (2026-10-13):** steps 1–3 are done except `pmset` and the USB class (M2.md), on a CMLink practice SIM until the SMARTY SIM arrives. The endpoint is chosen, `GET /api/model.json?internalapi=1`, and a login is needed. The gateway's link-layer address was recorded locally, not in the repository; `mooringctl router pin` (built in revision 7, tested only against a loopback stub) is to store it as the router identity in the first live run, from Terminal.app: `router set-password`, `router pin`, `router status`, then `router capture`. Two read-only steps come first (M2.md): `router pin`, answered `y` only if the printed address equals the locally recorded one, which stores the pin that every later command reads, and `router capture --anonymous`, which shows how the M7 answers a cookie-less `GET` before any password is sent (§15.6 rule 9). Before any switch to Plugged-In mode, the battery-removed state is captured: the router status requires the battery's leaves (M2.md). Deviations: the battery stays installed, the adapter is gigabit USB, and Wi-Fi ranks above the USB LAN service while the M7 has no line SIM. Step 3's capture was taken in the operator's logged-in browser with an in-page allowlist redactor; later captures use `mooringctl router capture --interface <bsd> --out <outside the repo>/model.json [--anonymous]`.
  - **2026-10-14:** the first `router pin`, a plain `cargo` build run from Terminal.app, reached the M7 with its warm-up connection but could not read the neighbour table, and was misreported as `GatewayUnresolved`: on macOS 27.0.1 (26A434) the kernel returned an empty table to that binary, whose signing identifier is not reverse-DNS (§15.6 rule 10 records the measurements, the rule inferred from them, and the fix). The live runs are to use the copy that `cargo xtask mooringctl` signs, `target/signed/mooringctl`, run from Terminal.app's own shell. Later that day a `router pin` failed once with `RouterUnreachable{InterfaceAbsent}` while the USB adapter re-attached, and a rerun pinned the address; `router capture --anonymous` and `router status` then failed with exit 8 at their first request: the M7 answers a `GET` of the endpoint without a session cookie with its session set-up redirect (M2.md), which the client now follows, once per read (§15.6 rule 9). With the set-up followed, `router status` passed the identity check and sent the login; the M7 answered it with status 302 and the session read after it was not an administrator's (exit 5). The client did not yet judge that answer's `Location`, so a refused password could not be told from an accepted login; it now stops at a `302` to the login-failed page and otherwise names where the answer pointed (§15.6 rule 9, M2.md). Run again, it judged the answer "elsewhere": a diagnostic that repeated its requests showed that the M7 refuses the login with a `302` to the login-failed page followed by `&errno=2&errdetail=session.password`, sets no cookie, keeps the session `Guest`, and left the cool-off at 0 after four refusals in a row; the client now reads those two parameters on that page and names them (§15.6 rule 9, M2.md). The password the operator had typed was not the M7's admin password; with the right one stored, `router status`, `router status --json`, `router capture --anonymous` and `router capture` all succeeded against the M7 that evening, and both captures were checked for identifiers (none) and against the fixture (the same 627 leaf paths; M2.md).
  - **2026-10-16:** the operator inserted and activated the SMARTY SIM (the operator's statement). In both spot runs of the operator's M2a field runs that day (17:56 and 19:06 UTC, kept outside the repository), `router status --interface en9` refused with "the M7's answer is malformed: router field sim.SPN: not text of its form (the login was answered with status 302 and a Location to the start page)", and `router capture` exited 0 and named both `sim.SPN` and `general.webAppVersion` as withheld: the M7 reported both as the empty string (M2.md). The status named `sim.SPN` alone because the parser stops at the first value whose shape it refuses, in the document's order, where `sim` comes before `general` (derived from the code and the fixture's key order). Both are now read as not reported, and the redactor keeps them without naming them (§15.6 rules 1 and 2). The 22 redacted captures of that day also hold values that the status does not hold yet, so `router status` still exits 8 on this line *(from the code)*: the network service `LteService` and the data services `4G` and `4GPLUS`, which no vocabulary holds (`UnknownValue`), and, in one capture, a second carrier-list element with band 0 and downlink bandwidth `Unknown` while `wwan.ca.SCCcount` was 0 (`OutOfRange`: a band number is 1 to 999). The bands seen, B28, B8 and B3, and their bandwidths, `10MHz` and `20MHz`, are read. Holding the rest waits for a decision on their names in the status and on what a band-0 element means, and for a capture of them in the repository; none is in it yet (M2.md).
- **M2b:**
  - keepalive;
  - `EgressCheck{carrier_prefixes (RIPE inetnum evidence), pairing}`, on the SMARTY line;
  - `InterfaceSelector` variant;
  - `FlowCap`;
  - `UplinkBaseline` (p10, p50);
  - the go/no-go for UDP over the SMARTY line.

**Checklist (both parts):**
- M7 Wi-Fi offload and Ethernet offload off; M7 Wi-Fi radio off (D-4).
- External antenna A/B: the operator owns NETGEAR's MIMO antenna accessory for the M7's two TS-9 ports. The manual warns that with more than 2 bars an external antenna can reduce reception, and that TS-9 connectors are delicate (202-12721-02, "Improve reception with an external antenna"). Run `fieldkit uplink` and record RSRP/RSRQ/SINR, band and network type for the internal antennas and for each antenna placement (window side, aimed at the nearest Three or Vodafone site). Keep whichever measures better; the choice is recorded with the raw logs.
  - Revision 5: M2a runs a first pass with `networkQuality` (step 5 below), and M2b repeats it with `fieldkit uplink`.
  - Revision 6: the line is SMARTY on Three's network, with Vodafone masts shared (VodafoneThree, §19.1), so the nearest site is chosen by the band and RSRP the M7 reports. The A/B runs on the SMARTY SIM only, because the operator has no other SIM for the M7 (M2a, The SIM).

#### M2a — The M7 alone (from 2026-10-09; no VPS)

**Preconditions:**
- **The SIM.** The SMARTY SIM (F1) was ordered on 2026-10-08 and is due about 12–13 October. The operator has no other SIM for the M7: EE declined its order on 2026-10-08, so there never was an EE SIM, and the operator's phone SIM (Lebara, on Vodafone's network, moving to an O2 eSIM) does not go in the M7. Until the SMARTY SIM arrives and is activated, M2a does the SIM-less steps only:
  - Plugged-In mode, the admin password, the Wi-Fi radio, both offloads and UPnP off, and the Ethernet port on (step 1);
  - the Mac's Ethernet interface discovery (step 2);
  - the router endpoint discovery and capture (step 3);
  - the power-cut drill (step 8), whose time until data flows again is timed once the SMARTY SIM is in.

  Every radio, placement, antenna, band, thermal-under-load and byte step (steps 4–7 and 9) waits for the SMARTY SIM, as do the SIM PIN record of step 1 and step 10's check that all traffic flows with Wi-Fi off. Carrier prefixes and the meter's calibration are measured on the SMARTY line in M2b.
- **The SMARTY SIM** (revision 6; facts in §2 and §19.1):
  - **Activate it on a day of the month up to the 28th.** The activation day becomes the Renewal Date, and a Renewal Date on the 29th–31st falls earlier in a shorter month (TC 5.21). Record the activation date as the bill day (`BillDay`, §7), and set the M7's data-usage reset date to the same day (manual p. 65).
  - **Keep the payment card funded.** A failed renewal taken later moves the cycle start ([SMARTY-PG] p3); the operator then records the new bill day.
  - **APN:** `mob.asm.net`, IPv4, with no username or password (help 1155220). Record whether the M7 selects it by itself; set it by hand in the M7's web UI only if it does not (Mooring never writes the M7's settings, §18).
  - **Bands:** 5G n78 (3.5 GHz); 4G B1, B3, B20, B28 and B32 (2100, 1800, 800, 700 and 1400 MHz) (help 4670061). Steps 4 and 6 record which band and radio access type the M7 attaches with, and whether 5G is ever standalone.
  - **VodafoneThree sharing:** since August 2025 SMARTY uses combined Three and Vodafone coverage on the same SIM (help 10235435), so the best spot may attach to a Vodafone mast. Record the band, the radio access type and the signal at each spot, never the cell id (§15.5).
  - **Usage reconciliation:** SMARTY's dashboard and app usage history counts in binary units (1 GB = 1024 MB), per full MB, including re-sent packets and flow-control overhead ([SMARTY-PG] p23). Step 9 compares it, converted, with the Mac's and the M7's counters, and records whether an Unlimited plan shows the GB used and how fresh the figure is.
  - Record the carrier name the M7 displays for the SIM; the status fixtures assume `SMARTY` *(inference)*.
- **Hardware.** A USB-C 2.5GbE adapter (F8).
- **Wi-Fi off on the Mac** for steps 4–9, so that background traffic cannot hop between interfaces (§10.2, critique C-3).

**Steps:**
1. **Set up the M7.** Path: M7 RJ45 → USB-C 2.5GbE adapter → Mac.
   - Plugged-In mode with the official adapter: battery out, cover off (§2).
   - Change the admin password.
   - Turn off the Wi-Fi radio, both offloads, and UPnP (manual p. 70).
   - Enable the Ethernet port. That restarts the M7 (pp. 47–48).
   - Record the firmware version, and whether a SIM PIN is set (F17).
2. **The Mac's side.**
   - Record the interface and the service order.
   - Record the gateway's link-layer address.
   - Record the USB class, for the record only.
   - Record `pmset -g` and `pmset -g cap` (§10.3).
3. **M7 interface discovery** (§15.6).
   - Send an anonymous `GET` of the JSON endpoint, bound to the Ethernet interface. Record only the status code, the content type and the top-level keys, plus whether an anonymous response contains `webd.adminpassword` (critique C-7). M2a did this for `/api/model.json?internalapi=1` and chose it; `/model.json` is never requested (§15.6 rule 5). Later anonymous captures use `mooringctl router capture --anonymous`, which writes only the redactor's output.
   - Then the operator logs in through the web UI himself, typing the password, and saves one capture.
   - The raw responses and the capture stay outside the repository. Fixtures are made from them later, by the allowlist redactor.
   - Choose exactly one endpoint, or record "no JSON interface".
4. **Placement survey** at 3–5 spots: desk, window, a higher floor.
   - At each spot, read the M7's Diagnostics page: band, LTE or NR, RSRP, SINR, temperature (manual p. 56).
   - Then run `networkQuality` bound to the interface. Each run costs a few hundred MB *(inference)*.
5. **Antenna A/B** at the best spot: the internal antennas against the owned NETGEAR antenna (checklist above), with the same `networkQuality` run.
6. **Band setting.** Compare the M7's band region "4G" against "4G + 5G": which radio carries the uplink, and whether the SIM ever attaches in 5G SA. On the SMARTY SIM, record which of n78 and B1/B3/B20/B28/B32 the M7 uses.
7. **Thermal.**
   - Run one hour of upload-only saturation in Plugged-In mode, logging the M7's temperature and the throughput every 5 minutes.
   - Let the M7 cool to ambient. Then repeat with the battery in, to compare (critique C-4).
8. **Power-cut drill** (§10.3, critique C-5).
   - Remove mains from both the M7 and the Mac for at least 60 s.
   - For the M7, record whether it powers on unattended, the time until data flows again, and whether the Ethernet, offload and Wi-Fi settings persist.
   - For the Mac, record what it does on battery and when AC returns. It has no `acwake`.
   - Then reboot the Mac and record the FileVault behaviour.
   - The daemon's own behaviour can be tested only after M5 and M7.
9. **Byte baseline.** Run `netstat -I <bsd> -b` before and after a fixed transfer, and compare with the M7's own data counter and, on the SMARTY SIM, with SMARTY's usage history (binary units, re-sent packets included).
10. **Mac settings.** Lid open; Charge Limit 80 %. Confirm that all traffic flows with Wi-Fi off.

**Commands.** `<bsd>` is the USB-C Ethernet adapter's interface. `<m7>` is the M7's address: the manual's web UI address is `http://192.168.1.1` (p. 55).
```
networksetup -listallhardwareports ; ifconfig <bsd> ; networksetup -listnetworkserviceorder
route -n get default ; arp -n <m7>                    # the M7 gateway's link-layer address: the router identity (§15.6)
ioreg -p IOUSB -l -w0 | grep -iE "bInterfaceClass|Netgear"   # the M7's USB class, for the record only (224 = RNDIS)
pmset -g ; pmset -g cap                               # recorded in M2.md (§10.3)
cargo xtask mooringctl                                # builds mooringctl and signs a copy, target/signed/mooringctl; again after any source change, as `cargo xtask mooringctl && ./target/signed/mooringctl router …` (§15.6 rule 10)
./target/signed/mooringctl router pin --interface <bsd>   # in this order, from the workspace root in Terminal.app's own shell (the first two steps are M2.md's first live run); y only for the address recorded in step 2
./target/signed/mooringctl router capture --interface <bsd> --out <outside the repo>/anonymous.json --anonymous   # no password is read or sent
./target/signed/mooringctl router set-password        # typed twice at the terminal, echo off
./target/signed/mooringctl router status --interface <bsd>   # the password is sent only after the identity check
./target/signed/mooringctl router capture --interface <bsd> --out <outside the repo>/model.json   # logged in; the redactor's output only (§15.6)
networkQuality -I <bsd> -s -M 30 -c <spot>.json       # per spot and per antenna; -c is given a file name, so it cannot take the next flag
networkQuality -I <bsd> -d -M 300 -c up-<n>.json      # upload only, in a loop for 1 h: the thermal run
netstat -I <bsd> -b                                   # before and after a fixed transfer; compare with the M7's counter
```

**Reading the results** *(inference; thresholds from the capacity review)*. M2a's `networkQuality` runs are a first reading; the 24 h `fieldkit uplink` in M2b decides.
- Best-spot p50 ≥ 15 Mbps and p10 ≥ 5 Mbps on the SMARTY SIM: the capacity review's estimate is that v1 could carry about 10 users; the pilot is capped at 5 (F3).
- p50 of 8–15 Mbps: fix the placement or the antenna first.
- p50 < 8 Mbps or p10 < 2 Mbps: the placement and antenna first; changing the carrier would be a new decision, because F12 is superseded (§20.2).
- Loaded RTT rising by more than 200 ms (M2b): bring M10's cake forward before adding users.
- A thermal step-down within the hour: Plugged-In mode and ventilation are mandatory, and the location changes.

#### M2b — With an hourly London VPS (D-2)

From M2b on, the Mac joins no Durham network while any exit or test tunnel runs (P0-2, §10.2).

Measurements added in revision 5, beside the commands below:
- the loaded RTT to the VPS while the uplink is saturated;
- real-path goodput through WireGuard with 1, 4 and 16 flows;
- the China-evening windows: 13:00–17:00 BST until 25 Oct 2026, then 12:00–16:00 GMT;
- the SIM-factor reconciliation;
- a three-client fairness check (Jain index).

M2a recorded the M7 gateway's link-layer address (outside the repository), which the router adapter binds its login to (§15.6), and `mooringctl router pin` (revision 7) records it as `router-identity.json`; `fieldkit env` checks that it is stable across replug and reboot.

**Verification commands** (the Mac is attached to the M7's 2.5GbE port through the USB-C adapter; `<bsd>` is that interface):
```
cargo xtask fieldkit                                  # builds fieldkit and signs a copy, target/signed/fieldkit (env reads the neighbour table)
cargo build -p fieldkit --release --target x86_64-unknown-linux-musl   # the VPS copy; on the VPS: fieldkit serve --listen <vps4> --for 26h
./target/signed/fieldkit env --bind <bsd> > env.json  # NET_RT_IFLIST2 lladdr/gateway lladdr; after replug or reboot: env --bind <bsd> --compare env.json
fieldkit udp-nat-timeout --bind <bsd> --echo <vps4>:27950 --min 10 --max 300
fieldkit nat-behaviour --bind <bsd> --echo <vps4>:27950   # mapping and filtering, with echo port B (27951)
fieldkit pooling --bind <bsd> --reflectors <vpsA>:27900,<vpsB>:27900 --flows 32 --duration 1h
fieldkit public-ips --bind <bsd> --reflector <vps4>:27900 --duration 24h --interval 5m   # then `whois` each IP → prefixes
fieldkit port-ceiling --bind <bsd> --target <vps4>:27960 --max 8192
ping -b <bsd> -D -s 1312 -c 20 <vps4>                 # outer path MTU ≥ 1340 (1312 + 28)
fieldkit uplink --bind <bsd> --sink <vps4>:27970 --echo <vps4>:27950 --duration 24h --interval 15m   # p10/p50/p90, loaded RTT; --flows 1, 4, 16
fieldkit rtt --bind <bsd> --targets <candidate provider IPs>
# WireGuard over the SMARTY line: VPS kernel wg (ListenPort 27820) + mooring-exit from M0 with a test config (no egress rules):
wg show wgexit latest-handshakes                      # on the VPS: handshake < 180 s, stable for 1 h across idle periods
# CFM coexistence (user enables CFM TUN; prompts appear):
nc -b <bsd> <vps4> 27900 ; sudo tcpdump -ni <cfm utun> host <vps4>   # prints the carrier IP; zero packets on utun
pmset -g log | grep -E "Sleep|Wake|DarkWake"          # clamshell on AC, with a NetworkClientActive test assertion held
```
**Stop rule:** if UDP over the SMARTY line fails, stop. A redesign is the user's decision.

**`fieldkit` (built 2026-10-22).** One crate, `crates/fieldkit`, built for macOS (the probes) and Linux musl (`serve`). Every probe binds its sockets to `--bind` (`IP_BOUND_IF` on macOS), writes one JSON line per sample as it is taken and a summary line last, exits 0 when it measured something, whatever it found, and 1 when it could not measure. What the commands and the servers say to each other (`src/wire.rs`):
- UDP echo, ports A and B (27950, 27951): 32-byte requests and 32-byte answers carrying the source the server saw, so the server never sends more than it received; a request asks for an answer now, after a delay of up to ten minutes (`udp-nat-timeout`), or from the other port (`nat-behaviour`'s filtering test). At most 1024 delayed answers wait at once.
- TCP reflector (27900): one line, `MFK1 <ipv4>:<port>`, the source seen.
- TCP port-ceiling target (27960): one byte per connection it holds, so the probe can tell a connection the server holds from one only the kernel's backlog took; it holds at most `--ceiling-max`.
- TCP sink (27970): after `MFK1 SINK <seconds>` it counts the bytes of each second, reports at the end of the window while the probe may still be sending, and drains the rest. The probe stops at the report and aborts the connection (`SO_LINGER` 0): the bytes still in its socket would otherwise keep the line busy after the sample, which on 2026-10-22 delayed the next sample's opening lines past the sink's first 5 s limit (now 30 s).
- `serve --for` is required and at most 48 h; the log is counts, never addresses. The servers answer anyone who reaches their ports, so the ports are opened only for a session (M2.md, "Running fieldkit").
- `udp-nat-timeout` repeats a probe that got no answer before it counts, and reports the largest keepalive §3 admits (half the longest idle time survived, at most 60 s). `nat-behaviour` cannot tell address-dependent filtering from none with one server address. `pooling` records each round's TCP and UDP addresses separately. `uplink` sets the interface's byte counter (macOS, read modulo 2^32 to 1 KiB, see macsys) against the bytes the sink counted.

Not built: the real-path WireGuard goodput (needs `mooring-exit`, M0), the three-client fairness check (`uplink --flows` gives the Jain index of one Mac's flows only) and the CFM coexistence check.

### M3 — Netns e2e (this Mac via Lima, and hosted CI)

**Deliverables:**
- `lanes/netns/*` and the `e2e` harness, driving the real `daemon-core`.
- Every L4 case from §16 and the L4-ablation matrix.
- A/B results for `block_quic`, `tcp_notsent_lowat` and `bbr_profile`.
- Confirmation of the Xray run-time log level (`none`, chosen in M1 from the pinned source, §8.2) by T-log-canary.

**Verification:**
```
limactl start --name mooring-l4 lanes/vm/lima-debian13-arm64-lab.yaml
cargo xtask lane l4 --arch arm64 --runner lima:mooring-l4      # local
cargo xtask lane l4 --arch amd64                               # hosted CI (ubuntu)
cargo xtask lane l4-ablation --arch arm64                      # every ablation fails its named test
```
Order: REALITY and the tunnel first; then `accept_local` and the reflector; then Hysteria2; then the owner guard and the no-leak variants; then camouflage, exhaustion and NAT profiles; then impairment.

### M4 — VPS agent and VM lanes (hosted CI KVM, and this Mac)

**Deliverables:**
- `mooring-agent`:
  - roles;
  - `Bootstrap` with host-key regeneration;
  - transactions with commit-confirm;
  - `ActivateAgent` self-test and revert;
  - single-owner gate, persisted holds, halt and `ExecCondition`;
  - the watch loop, reflector, accounting and `TargetCheck`, including the handshake sampler for p95 latency and first-flight size (`TargetTool::HandshakeSampler`, §11.7);
  - host-profile convergence;
  - stderr scrubbing;
  - *(revision 5)* the console's node side (§11.3, §11.5, §15.7):
    - five-minute, hour and day bins, each deleted 48 hours after it ends, and each monthly `usage/<YYYY-MM>.json` deleted 7 days after its month ends, and `last_active` dropped for an email that leaves the applied configuration (F7, §11.5);
    - `last_active`, host health, and the uplink transfer counters with reset detection;
    - `MacSilent`, suppressed by an Operator hold;
    - the event journal behind `Events{since}`;
    - the accounting canary's evidence;
  - *(revision 6)* the decided F5 and F6 node side (§5.2, §11.3, §15.8, §15.9):
    - host profile 2's convergence, including the `mooring-view` account;
    - the viewer handler, which runs as `mooring-view`, serves only the viewer's reads, and writes the stop-request file under `gate.lock` that the watch turns into an Operator hold, then answers `GateClosed` only after reading the hold back with the gate closed, and `GateStopUnconfirmed` after `VIEWER_STOP_WAIT_SECS` otherwise (§11.3);
    - staging `viewer_authorized_keys` 0644 `root:root` in `/etc/mooring` and `gen-<N>` directories that are 0755 `root:root`, so sshd can read it as `mooring-view` (§8.6);
    - the `sshd_mismatches` comparison, which for `AllowUsers` compares the exact multiset of `allowusers` lines (§8.6);
    - storing and serving the Mac report (`PutMacReport`, `MacReport`);
    - `PutNotices` and the node's outbox;
    - `mooring-alert.service` and its 09:00 Europe/London timer, with the alert secrets delivered as a credentials file;
    - the Healthchecks pings that `dead_man_pings` selects.
- QEMU/KVM CI lane with a NoCloud seed.
- Lima lab VM profile.
- The cross-version agent test with the previous agent fixture.

**Verification:**
```
cargo xtask lane l5 --vm qemu-kvm-amd64     # CI; fails with a typed error if /dev/kvm is absent; every §16 L5 injection
cargo xtask lane l5 --vm lima-arm64-lab     # this Mac
cargo xtask lane l1 -p mooring-agent-proto  # frozen-core wire goldens
```
**Acceptance:**
- An unchanged re-apply restarts nothing.
- Xray runs with `CAP_NET_BIND_SERVICE` only.
- Shutdown survives a reboot.
- *(Revision 5, in the L5 VM lane.)*
  - Stopping the peer's handshakes raises `MacSilent` after 600 s.
  - Filling a tmpfs raises `DiskLow`.
  - Restarting Xray mid-stream keeps the deltas monotonic.
  - A range the agent does not fully hold is refused with `SeriesNotRecorded`.
  - *(Revision 8.)* With a fake clock, a bin is gone 48 hours after it ends and a monthly usage file 7 days after its month ends, whether or not the Mac pulled them, and a range reaching a deleted bin is refused with `SeriesNotRecorded`; after an apply that revokes a user, its emails have no `last_active`.
- *(Revision 6, in the L5 VM lane.)*
  - A node converges to host profile 2 (version 1 was never installed, so only `HostProfile::CURRENT` exists), and `sshd -T -C user=mooring-view,…` shows the viewer's keys file and forced command, while `-C user=root,…` does not.
  - A real SSH login as `mooring-view` with a viewer key succeeds on the staged generation (the keys file and its directories readable by that account under StrictModes, §8.6), and the same key is refused for `root`.
  - A viewer key reads `Status` and `MacReport` and closes the gate with the Operator hold; every other request, and `GateSet` with any other reason, is refused, and the gate stays closed until the ops role clears the hold.
  - With the watch stopped, a viewer's `GateSet{Operator}` is answered `GateStopUnconfirmed` after `VIEWER_STOP_WAIT_SECS`, never `GateClosed`.
  - A drop-in that adds `AllowUsers debian` after Mooring's is reported by `Hello` as `AllowUsers` drift.
  - The alert unit sends a test notice to ntfy and pings both Healthchecks checks; stopping the watch stops the node check's pings, and stopping the peer's handshakes stops the `MacAlive` pings.

**Status 2026-10-23 (M4a to M4d merged; M4e's first part on the topic branch `feat/m4e-bootstrap`).** M4 is built in six slices, each gated and committed on its own: M4a the agent's core; M4b transactions with commit-confirm, `ActivateAgent` and `Resume`; M4c the watch loop, conditions, the event journal and `Events`; M4d accounting, the engines' figures and restarts, the uplink transfer, the series, retention, `Usage`, `UsageSeries` and `Status`; M4e bootstrap, host-profile convergence, sshd, the viewer account, the alert unit and `TargetCheck`, in three parts (bootstrap and the host profile; `TargetCheck`; the alert unit and `PutNotices`); M4f the VM lanes and the cross-version test.
- **Built in M4a** (`crates/mooring-agent`, edges as §6.1): `serve-ssh --role` reads one frame, checks the role (`Request::authorize`) before acting and writes one reply. It serves `Hello` (every host fact read live: the up IPv4 default route in `/proc/net/route`, the one global IPv4 on it from `ip -j`, `/proc/sys`, `/etc/os-release`, `/proc/self/exe`'s digest; sshd drift from `sshd -T` as multisets; `client_ip` from `SSH_CONNECTION`), `HaveBlobs` and `PutBlob` (hashed on arrival and whenever reported present; a damaged blob is removed for re-upload), `GateSet`, `ClearHold`, `Shutdown`, `PutMacReport` and `MacReport`. `reflect`, `halted-check` (exit 1 while halted or while the marker cannot be read), `gate-close` and `self-test` are the unit commands. Tools run only from a closed list at Debian 13 paths (`nft`, `systemctl`, `ip`, `sshd`, `wg`), with a cleared environment.
- **State files added:** `/var/lib/mooring/host-profile.json` (the installed `HostProfileVersion`, written by `Bootstrap` and transactions; an agent without it answers `Hello` with `Io{ReadState, ENOENT}`), `/var/lib/mooring/stop/request.json` (a viewer's stop, `{"at"}`, for the watch; in `gate/` until M4e) and `/var/lib/mooring/mac-report.json`.
- **Shutdown** attempts every step whatever the step before did: on 2026-10-22 on the London VPS (no `mooring` table yet) the gate's close failed, and the engines must still be stopped. The first failure is reported.
- **Built in M4b** (`crates/mooring-agent/src/txn`): `Apply`, `TxnStatus`, `Confirm`, `Rollback`, `ActivateAgent` and `Resume`, and the unit commands `txn <N>`, `txn-revert <N>` and `txn-recover`, as §11.2 and §11.3 describe them, with the layout of §11.2 step 4. The tool list adds `wg-quick`, `systemd-run` and `ss`; a staged engine or a new agent runs by its own path, with the same cleared environment. The host-profile parts of a transaction (its files, `sshd -t`, `systemd-analyze verify`, the sysctl check, `daemon-reload`, `sysctl --system`, the sshd reload) join with host-profile convergence in M4e, which also installs the boot unit that runs `txn-recover`. Checked only against a stand-in node: a transaction on the London VPS would load the golden ruleset there, so the first real transactions run in the M4f VM lane.
- **Built in M4c** (`crates/mooring-agent/src/watch`, `journal.rs`, `wg.rs`): the `watch` unit command and `Events{since}`, as §11.3 and §15.7 describe them. The tool list adds `stat` and `chronyc`. WireGuard is read from `wg show wgexit dump` everywhere (the drain hold too), and the transaction records are 0640 so the watch can journal commits. Bootstrap lays out the permissions this relies on (M4e, §8.6): `/var/lib/mooring/watch` writable by `mooring-watch`, the gate directory writable by it (the holds), the stop request's directory by both (the viewer writes it, the watch removes it; it was the gate directory until M4e, which would have let the viewer remove the holds), the view, the journal, the holds and the records readable by the `mooring` group, and `/run/mooring` for both locks.
- **Built in M4d** (`crates/mooring-agent/src/accounting`, `watch/engines.rs`, `watch/transfer.rs`, `status.rs`): accounting, the series and their retention, the engine figures and restarts, the uplink transfer, `Status`, `Usage` and `UsageSeries`, as §11.5 describes them, and the canary's evidence, which changes two render goldens: the `probe_flows` counter in `nftables.conf` and the `emails` of `watch.json`. Bootstrap also lets `mooring-watch` run `systemctl show`, execute `/etc/mooring/current/engines/xray`, read `/proc/net/route` and `/sys/class/net`, and write `/var/lib/mooring/usage` (its files group-readable by `mooring`, for the viewer's `Usage` and `UsageSeries`) (M4e). Checked only against a stand-in node: the London VPS runs no Xray yet.
- **Built in M4e, part 1** (`crates/mooring-agent/src/bootstrap.rs`, `accounts.rs`, `layout.rs`, `hostfiles.rs`; agent-proto's `profile.rs`): `Bootstrap` and `RevokeBootstrap` (§13.2), host profile 2's accounts, layout, search grant and units (§5.2, §8.6), and host-profile convergence in every transaction (§11.2), with the permissions M4c and M4d asked for. The protocol adds `Bootstrap.bootstrap_pubkey`, `AgentError::{Bootstrap{step}, AccountMissing{account}, HostProfileUnsupported}` and `ApplyStep::{Tmpfiles, Journald}`. The tool list adds `dpkg-query`, `apt-get`, `groupadd`, `useradd`, `usermod`, `ssh-keygen`, `sysctl`, `systemd-tmpfiles` and `systemd-analyze` (their paths checked on Debian 13). `reflect` takes no address. Checked against a stand-in node and, for `Bootstrap`, in a Debian 13 VM (§13.2); the transactions' host steps on a real node wait for M4f's VM lane, which has engines to run.
- **Built in M4e, part 2** (`crates/mooring-agent/src/target`): `TargetCheck{host, xray}` with the handshake sampler, and the hourly target check behind `TargetDegraded` (§11.3, §11.7). `AgentError::NotServedYet`, which answered the requests of the slices still to come, is gone with the last of them. The tool list adds `getent`, `curl` and `timeout`, and a tool's exit status reaches the agent. Checked against a stand-in node and, for the sampler, against public servers; `xray tls ping`'s output against the pinned source only, until the engines are built (no Xray binary exists for this project yet).
- **Checked on the London VPS** (Debian 13, kernel 6.12.113, 2026-10-22, all state removed afterwards): `Hello` read the real facts (and the eight sshd directives the profile would change), the blob round trip, `GateSet` reporting `GateCloseFailed` with nft's own message while keeping the hold, `Shutdown`, `halted-check`, `self-test`, the reflector on the public address, and the usage errors.

### M5 — Mac daemon, CLI, prober and lab lanes (this Mac, today)

**Deliverables:**
- `macsys`: interface resolution and the PF_ROUTE monitor.
- `daemon-core`: the state machine, verdicts with brackets, latches, and the control socket.
- `mooringctl daemon` and the CLI with `--json` and `status --follow`.
- Supervision of both engines, including `check -c stdin`.
- The SIM meter.
- The data-protection Keychain from the bundled helper, as the Keychain `SecretStore` implementation (moved from M1).
- A minimal signed lab bundle (`xtask release --lab`, signed by the user) for the Keychain and sandbox checks; M7 completes the release lane.
- Spikes: the sandbox and the Secure Enclave key, with decisions recorded.
- *(Revision 5)* The console's Mac side (§15):
  - `MacStatusV1`, the Mac usage store, and incremental `UsageSeries` and `Events` pulls;
  - the event and action journals, and availability;
  - the alert machine, rendering its notices and the daily digest for the nodes to send (§15.8), beside the local notifications;
  - the read-only router adapter (after M2a) and the capacity monitor;
  - the SIM forecast, and reconciliation inputs;
  - the `ForeignNetworkAttached` preflight;
  - `PollNow`;
  - `apply --pending` (a launchd calendar job, §13.6) and `apply --now`;
  - the CLI commands of §15.3.
- *(Revision 6)* The decided pilot (§7, §15):
  - `exit init` records the pilot values: the SMARTY plan, `PILOT_SIM_WARN_BYTES` and a hard stop at `PILOT_SIM_HARD_STOP_BYTES`, `CapacityPolicy::PILOT`, `AutoQuotaPolicy::PILOT` and `AlertSettings::pilot()`;
  - `sim set-plan | set-stop | set-bill-day` (with a confirmation for a stop above `PILOT_SIM_HARD_STOP_BYTES`), `quota set-factor`, `viewer new | list | remove` (with a comment-aware import of the phone's key) and `alert setup | test | rotate-topic` (§12);
  - `node retire` refusing, unless the operator confirms it, to retire the last channel node while another active node has none (§13.4);
  - the apply job's suspensions, each recorded at its evaluation's `now`, and its resume of lapsed suspensions for quota, listed with `daemon-core`'s `quota_suspension_holds` (made public for it) and bounded by the cap (§13.6);
  - the daemon refuses to serve while the plan is unrecorded (§10.2);
  - the `PutMacReport` push with each poll (§10.5).
- *(Revision 8)* The decided delivery (§9.2, §9.4; F9–F11):
  - `user agree <uid>`, which records `AgreementRecord { version: AgreementVersion::CURRENT, accepted_on: <the UTC date of now> }` and takes neither a revision nor a date, as the bookkeeping record `AgreementRecorded` (§7), which keeps the generation, refuses a revoking or revoked user and a lower revision (`AgreementRegressed`), and keeps a record of the same revision;
  - `Revoked{since}` (a state-version change, §15.7), the apply job's removal of a user 13 months after `since` and `user forget`, both as the bookkeeping record `RevokedUserRemoved`;
  - the Mac's deletion tiers (five-minute bins after 7 days, hourly after 35 days, daily and monthly after 13 months) and the `Usage{month}` pulls with the gap rebase of §11.5;
  - the Time Machine exclusion of the data and log directories, its `doctor` check, and `user export`'s warning for an `--out` folder that is not excluded (§12);
  - the apply job's launchd schedule: every hour at minute 20, running only between 19:15 and 19:45 UTC (§13.6);
  - `user export`'s CLI error for `mooring-export`'s `AgreementNotAccepted` (built in revision 8);
  - the deletion rules that the agreement promises (F7, §11.5, §15.7).

  Only commands that presume F18 (`backup …`) wait for that decision.

**Status 2026-10-18 (on the topic branch `feat/m5-user-delivery`):** built and tested: `mooringctl user add` (the label read at the terminal; fresh credentials on every node that is not retiring, written before the state; `--client cfm05|cfm04` and `--mlkem`, refused for CFM 0.4 before anything is asked) and `user alias` (a configuration change that never replaces an alias); the bookkeeping record `AgreementRecorded` (§7) and `mooringctl user agree`; `mooringctl user export` with `export_secret_refs`, `read_snapshot` and `SecretSnapshot::material`, its mode-0600 file that is never overwritten, and its warnings for a synced folder and for a folder Time Machine backs up (`tmutil isexcluded`). The development build keeps the secrets in the login keychain until the data-protection keychain lands. Not built yet: `exit init`, without which none of these has a state to work on, and the rest of this list.

**Status 2026-10-22 (revision 9, on the topic branch `feat/router-console`):** built and tested: the router's poll loop in `mooringctl daemon` (every 60 s on `--router-interface`, before a deployment exists), the control socket's `Status` and `Subscribe` (§10.1), `status.json`, `mooringctl status [--follow] [--json]`, and `ConsoleStatus` with its fixtures (§15.1); the M7's SMARTY-line values (§15.6). Run under launchd on this Mac: the agent started, served `status` and `status --follow` to the CLI and the app, and, once the operator had allowed its keychain read and local network access (§5.1), read the M7 (2026-10-22 08:13 UTC; the poll before the local network answer failed with `EHOSTUNREACH`). The 24 h poll acceptance (rule 7) started then. Not yet: its result, and everything else on this list.

**Status 2026-10-23 (M5a, on the topic branch `feat/m5a-exit-init`):** built and tested: 1pMobile's plan and its 30-day cycles in the model (`CycleRule`, `FairUseWindow::Rolling`, `SimStopAboveRollingLine`, §7), the F2 revision it needs (pending the operator's confirmation), the optional carrier check and its bookkeeping record (`CarrierRecorded`), `DeploymentInit::pilot`, and `mooringctl exit init` (the egress from the pinned M7's gateway and the interface's LAN subnet; a summary and a confirmation before anything is written; an existing deployment refused first), `exit record-carrier` and `sim set-anchor`. Not run on this Mac yet: `exit init` stops the router-only daemon (`DeploymentNotServed`), so it waits for the daemon that serves a deployment, and it is asked of the operator first.

**Status 2026-10-23 (M5b, merged):** the node driver: `node new --host-key`, `node adopt`, `node target check | set` and `node apply` over `dial-bound` management SSH (§10.5, §13.2).

**Status 2026-10-23 (M5c, on the topic branch `feat/m5c-exit-runtime`):** built and tested: `daemon-core`'s exit machine, SIM meter and status line, and the deployed daemon (§10.1, §10.2): interface resolution against the exit site, the foreign-network check (IPv4), `mooring-exit` supervised from `engines/` against its pin with the config on stdin (the pinned engine's `check` accepts the rendered fixture config), the direct probe every 30 s with the verdict, the latch file, the gate, halt and hold calls, the SIM meter's thread and file, the hard stop, the power source read from `pmset`, the router poll through the egress, the status published, `exit enable | disable | retry | observe`, and the stale engine. Not yet (M5d): `mooring-probe`, the in-chain probes and `Serving`, the node polls (`Status`, `UsageSeries`, `Events`), `PutMacReport`, pending applies and the alert machine's notices; the PF_ROUTE monitor; IPv6 in the foreign-network snapshot.

**Status 2026-10-23 (M5d, on the topic branch `feat/m5d-in-chain`):** `mooring-probe` supervised beside the exit, the in-chain rounds with their brackets and verdicts, `Serving` and the probe failures that degrade it, the node `Status` polls with `WatchStale` and unreachable nodes in the status. Not yet: `UsageSeries` and `Events` pulls (the usage view stays unavailable, `MissingLedger`), `PutMacReport`, pending applies, the alert machine's notices, the PF_ROUTE monitor, and IPv6 in the foreign-network snapshot.

**Verification:**
```
cargo xtask lane l6                          # Lima vzNAT lab: Verified verdicts; T-deny-mac on darwin; kill -9 → launchd restart,
                                             # no orphan, latch intact; VM stop (bridge gone) → Down(EgressInterfaceAbsent) ≤ 4 s
cargo xtask lane l6-bypass                   # user present: CFM TUN on/system proxy/off; `sudo tcpdump -ni utunN` shows zero
mooringctl doctor --keychain --json          # entitled helper self-check: data-protection items readable after reboot + login
```
**Acceptance:** a data-protection Keychain read works after reboot and login.
- *(Revision 5.)*
  - The foreign-network check refuses every case of §10.2 in its unit and property tests on this Mac, rather than through L6's `bridge100`, which is the lab egress (critique, section D).
  - The journal survives `kill -9`.
  - A quota crossing on a user with a `Suspend` quota suspends them at the next apply window, or at once with `--now`.
  - The router adapter passes a loopback stub server for 200, 401, a slow response and a truncated body (built in revision 7 for `mooringctl`; M5 adds the poll loop).
  - On the device, a 60 s router poll for 24 h causes no admin-session lockout, and turning offload on is reported before `OutsideCarrierPrefixes`.
  - `status --follow` fixtures are regenerated, and the Swift decoding of them passes.
- *(Revision 6.)*
  - `sim set-stop` refuses a hard stop above `PILOT_SIM_HARD_STOP_BYTES` unless the operator confirms that stop explicitly, and a test pins it: 3e12 (a typo for 3e11) is refused without the confirmation, 3e11 is accepted (§7: the model alone admits any explicit stop).
  - With the plan unrecorded (a lifted state), the daemon does not serve, and says why; `sim set-plan` lets it serve.
  - Under the pilot cap, with five users active and one suspended for quota in the cycle before, the first apply of the new cycle resumes nobody, reports the user it held back, and still carries out that run's suspensions and node applies; with a place free it resumes the earliest suspension first, one change per user (§13.6).
  - After `sim set-bill-day` moves the cycle's start forward or back, the next apply keeps a user suspended for quota since the new start suspended and counted, and resumes one suspended before it; a suspension for quota recorded after the run's `now` is reported as `QuotaSuspensionAfterNow`, and while it stands `evaluate` fails as a whole, so none of its proposals (expiry suspensions and suspensions for a user's own quota included) and no resume that depends on that record is carried out, while node applies still run (§13.6).
  - `alert rotate-topic` ends with a new topic, the same check UUIDs and every channel node pending `node apply`; stopped between its two changes, it leaves no channel node and no topic, never a half-replaced one (§12).
- *(Revision 8.)*
  - `user export` of a user without a record of `AgreementVersion::CURRENT` exits with `AgreementNotAccepted` and writes no file; after `user agree`, which leaves the generation and every node's confirmation as they were, the same command writes the file with no `node apply` in between.
  - `user agree` refuses a revoking and a revoked user and a record of a newer revision, and changes nothing each time; its test starts from a user without a record, since every fixture user now carries `AgreementVersion::CURRENT`.
  - With a fake clock, the Mac's five-minute, hourly, daily and monthly records are gone after 7 days, 35 days and 13 months, and a 3-day pull gap within one billing cycle is filled from `Usage{month}` with the cycle totals exact, while one across the cycle's start is reported, never guessed.
  - With a fake clock, a user revoked 13 months ago is removed with its label, alias, agreement record, usage and journal entries, and one revoked a day less is kept; `user forget` removes a revoked user at once and refuses any other.
  - `doctor` reports a data or log directory that Time Machine does not exclude.
  - With the time zone set to Europe/London, the apply job's schedule runs exactly once a day, at 19:20 UTC, on dates in BST and in GMT, and a late firing after 19:45 UTC does nothing.

### M6 — Real CFM in the lab (this Mac, user-driven)

**Deliverables:**
- `contract/cfm-acceptance.toml` entries for every enumerated shape × client line, with importer digests.
- L7 evidence files.
- *(Revision 8)* `contract/cfm-manifest.toml`'s `cfm05` pinned to the CFM 0.5.x release that carries the mainland China direct switch (§9.3), and L7's 0.5 run on that build: every shape imported by file, the switch turned on as `docs/runbooks/user-onboarding.md` says, and a `geoip:cn` destination seen leaving directly while any other goes through the node. The guide's wording is checked against that build.

**Status 2026-10-18:** `cfm05` is pinned to `502adf9`, the commit of CFM 0.5.0 (build 50030, tag `v0.5.0`), and `docs/cfm-contract.md` was re-read at that revision. The guide's CFM steps and wording were checked against 0.5.0's source and zh-Hans catalogue, not yet against the running app. L7 has not run, so every entry is still pending.

**Verification:**
```
cargo xtask lane l7 --cfm 0.4   # user warned before each window or prompt; then:
cargo xtask lane l7 --cfm 0.5
cargo xtask ci                  # shape gate now passes against the recorded importer digests
```

### M7 — Swift app, power helper, SMAppService, release lane (this Mac; signing by the user)

**Deliverables:**
- `Mooring.app`, including the `AgentNotEnabled` flow.
- `mooring-power` with NetworkClientActive and PreventUserIdleSystemSleep.
- `xtask release`, with signing performed by the user (D-6).
- `xtask release-verify`: no `lab` feature or marker; engine provenance; unsigned byte identity; entitlements.
- *(Revision 5)* The console screens of §15.3, rendered from `contract/status-fixtures/`. Every action calls the CLI, and Swift never touches a secret: the router password, if one is needed, is set with `mooringctl router set-password` in Terminal.

**Status 2026-10-22 (revision 9):** the app's first slice is built: `apple/project.yml` (XcodeGen) and `apple/Packages/MooringKit` (swift-tools 6.2, macOS 15, Swift 6, warnings as errors); the overview and the router screen from `mooringctl status --follow --json`, which the app runs from its own bundle and starts again 5 s after it ends, saying why on screen; every other screen of §15.3 says it needs a deployment. Its Codable mirror is tested against `contract/console-fixtures/` and the router variants of `variants.json`, refusing any unknown key or variant, and refuses a `deployed` document whole (`deploymentNotShown`) until it mirrors `MacStatusV1`. The mirror is strict on shape only: every line it reads, `mooringctl` has decoded with the Rust types and encoded again, so the values' own rules (ranges, lengths, which advisories a panel calls for) are not repeated in Swift. It reads the command's output on threads of its own with read(2) (a pipe read blocks; `FileHandle.read(upToCount:)` waits on a pipe for the whole count), splits it on 0x0A bytes only, refuses a line over 1 MiB and ends the command, and shows a refused line as not live; it starts reading at launch, whether or not its window is open, and a released model terminates its command. *Changed 2026-10-25, after the operator saw the window jump every few seconds while the daemon was stopped:* a command started again keeps how the last one ended on screen, now "Retrying…", until it shows a document, ends, or lasts 2 s; only then does the console say it is waiting for the daemon's first status (with the hint about the keychain and local network questions). Before, every retry went back to waiting at once and the failed command came back within a second, so the banner's symbol, colour, headline and height, and the menu's first line, changed twice every 5 s. English and Simplified Chinese (`apple/App/Localizable.xcstrings`). `cargo xtask app` runs MooringKit's tests, builds the app unsigned, requires Xcode's result bundle to report no error or warning and every string the code localizes to have a Chinese translation with the same format specifiers, cleaning first so that no warning hides in a task Xcode skips, checks that the built app carries the local network alert's text in Chinese (`apple/App/InfoPlist.xcstrings`), then signs the bundle ad hoc with the hardened runtime, the signed `mooringctl` inside (§5.1), and restarts a loaded agent on it. `cargo xtask ci` runs MooringKit's tests as its last step on macOS (and says it did not run them elsewhere), so a change to the documents that the mirror does not follow fails `ci`. Not yet: `SMAppService`, the `AgentNotEnabled` flow, `mooring-power`, the release lane and every screen that needs a deployment.

**Status 2026-10-23 (M7, the deployed console):** MooringKit mirrors `MacStatusV1` (`DeployedStatus`): the exit section, the SIM meter, the router panel with its advisories, the capacity, the user and node rows and the open alerts, with every enum of `variants.json` (each simple enum's Swift cases are the fixture's list in order; each enum with fields reads one value of every variant, as many as its cases) and the three scenarios of `contract/status-fixtures/`. As for the router, the mirror is strict on shape: every object refuses an unknown key (a test adds one to every object of each scenario; in a map keyed by ids the key reads as an entry whose value is refused), every key is required, a `null` too (a test removes each key of every record), a variant keeps its form (a unit variant is a string, any other a one-key object), and a document of another version is refused as such (`unsupportedVersion`). A mutant that let a struct variant's unknown key through was caught by 9 of those cases. So that the app shows the settings the exit needs off without a rule of its own after `exit init` too, `MacStatusV1` carries `advisories` beside its router panel, derived by `RouterReading::advisories` as the undeployed document's are and refused when they do not follow from it (`StatusError::AdvisoriesMismatch`; the four deployed fixtures gained `"advisories": []`, the only change to them). The app's screens: the overview (the exit's state and why, the open alerts with the critical first, each node's gate and in-chain verdicts, the SIM gauge, the router), and the exit, SIM, nodes, users (a table by opaque id and alias, the selected user's figures in an inspector) and capacity screens of §15.3, every figure from the document and none computed beyond the SIM gauge's bar, every state worded in English and Simplified Chinese (338 strings, checked by the catalog gate). Usage the daemon cannot report is shown as unavailable with its reason, never as zeros. The events screen says that the journals are not read yet (the `UsageSeries` and `Events` pulls are M5's). The menu bar shows the exit's state once there is a deployment. Checked with Xcode's result bundle (no error, no warning) and, on each screen and scenario, against a stand-in `mooringctl` that replays a fixture. Not yet: `SMAppService`, the `AgentNotEnabled` flow, `mooring-power` and the release lane.

**Status 2026-10-23 (M7, the daemon as a login item):** the app carries the daemon's plist (`Contents/Library/LaunchAgents/com.bill.mooring.daemon.plist`, §5.1) and registers it with `SMAppService` on the operator's **Start the Daemon at Login**, from its menu or from the banner the console shows while the daemon does not run at login; **Stop the Daemon** unregisters it; *(2026-10-24, the operator's decision)* the console window's toolbar has a **Daemon** menu with the menu bar item's daemon controls, because a menu bar manager can hide that item, as one did on this Mac; `.requiresApproval` shows `AgentNotEnabled` with **Open Login Items…**; **Open Mooring at Login** makes the app itself a login item (`SMAppService.mainApp`). The daemon takes no argument: it reads the M7's interface from the router pin (version 2) and writes its own rotated log with standard error pointed at it (§15.10). `xtask app` checks the plist in the bundle against the repository's byte for byte and, since 2026-10-24, is refused while the daemon is registered (§5.1); `agent-install` and `agent-uninstall` are gone. Registration was measured with a throwaway agent (§5.1). *The daemon's own first registration on this Mac, 2026-10-23, once the router's 24 h poll acceptance had passed (no failed poll from 10-22 17:57 to 10-23 17:57 UTC):* the development agent was booted out and its plist removed; `router pin --interface en9` from the new build recorded the interface beside the same address (version 2) without asking again; **Start the Daemon at Login** registered the job, which launchd lists as managed by `com.apple.xpc.ServiceManagement`, with the program identifier `Contents/MacOS/mooringctl` and the parent bundle identifier `com.bill.mooring`; the operator answered the keychain (**Always Allow**) and local network (**Allow**) questions; the first poll, made before the local network answer, failed `host unreachable`, and the next, 60 s later, succeeded; the new `status` read the protocol line; and `launchctl kickstart -k` ended the daemon with SIGTERM and started the same executable again, which read the M7 within a second and asked nothing. Not yet: `mooring-power`, the release lane, and the control channel's protocol line.

**Status 2026-10-23 (M7, the power helper):** `mooring-power` and the sleep drain are built (§5.1, §10.3): the helper holds `NetworkClientActive` and `PreventUserIdleSystemSleep` while the exit is enabled on mains, reports the power source, numbers each sleep and holds it for the daemon (25 s at most), and reports wakes. The daemon drains each sleep within its 4 s budget, each node's ssh session killed with its dialler when the budget runs out (§10.5), keeps the exit `Paused` until the wake, and is degraded (`PowerHelperExited`) while the helper is not running. The protocol is pinned by `contract/power-fixtures/protocol.json` and tested on both sides; the helper's logic is tested over a recorder (MooringPowerTests), the daemon's over a fake helper, the reaping and the session deadline against real processes and `/usr/bin/ssh`. `xtask app` signs the helper as itself and checks its identifier with the other two. Found and fixed on the way: socket2's `connect_timeout` reports a peer that answered and closed before its poll looked as a failure with no error set ("no error set after POLLHUP"), measured 18 times in 3000 loopback connects, so a direct or in-chain probe could fail a round on a reflector that had answered; both probes now read such a connection (`runtime::probe::connect_within`). *(2026-10-24)* fieldkit's `Bind::connect`, which every TCP measurement uses, had the same fault and counted such a connection as failed (a `public_ips` test failed on it in `ci`; a new test saw it in 3 of 3 runs of 1000 connects); it reads such a connection the same way now. The other `connect_timeout` callers (the management SSH dial, the router's HTTP client, the agent's target sampler, which runs on Linux) reach servers that do not close at once, and a server that did would fail them anyway. Not yet: a real sleep with a drain against a node (this Mac does not sleep, `sleep 0`), and the release lane, which follows M5's signed lab bundle and data-protection keychain (`xtask release --lab` and the entitled helper, not built) and needs the operator's signing identity and provisioning profile (D-6).

**Status 2026-10-23 (M7, the control protocol line):** the daemon names its control protocol on the first line of every connection, and the CLI refuses a daemon that names none or another before reading any reply, saying to restart it (§10.1, §15.1). Four mutants (the line left out of a served or a busy connection, the CLI's check skipped or accepting any number) were each stopped by the tests.

**Verification:**
```
cargo xtask release --identity "<user's Apple Development identity>"    # run by the user
cargo xtask release-verify dist/Mooring.app
codesign --verify --strict --deep -vv dist/Mooring.app
codesign -d --entitlements - dist/Mooring.app/Contents/Library/Helpers/MooringAgent.app
pmset -g assertions | grep -E "NetworkClientActive|PreventUserIdleSystemSleep"   # on AC, exit enabled
pmset -g log | grep -E "Sleep|Wake"           # behavioural: on AC, display off, past idle timer → no sleep; Dark Wake recorded
```
**Acceptance:**
- Login → `Serving` (lab) within 60 s with no interaction.
- Quitting the UI keeps the exit running.
- The drain is seen at the VM gate within 2 s.
- Wake → `Serving` within 10 s.
- `.requiresApproval` produces `AgentNotEnabled`.

### M8 — First London VPS and pilot (needs the M7, the SMARTY line, a VPS and a trusted user in China; D-1 with F20; CFM's 0.5.x release with the mainland China direct switch, F10)

**Deliverables:**
- A provisioned primary node: `node new`, `adopt`, `target`, `apply`.
- Exports delivered per `delivery.md` (§9.4), only to users who accepted the current agreement (`user agree`, F9) and run the CFM 0.5.x release with the mainland China direct switch on (`user-onboarding.md`, F10). With one node, a block means a rotation and a new file for every user (F11, §13.4).
- `docs/measurements/M8.md`.

**Verification and acceptance:**
- a 72 h soak with at least 99% `Verified` samples while awake on AC;
- the SIM meter within 3% of SMARTY's usage view, converted from its binary units (with M7 Wi-Fi off);
- per-user totals within 2% of WireGuard-derived totals;
- the offload drill: `OutsideCarrierPrefixes` and the engine stopped within 30 s;
- a trusted user in China succeeds on both protocols at peak on their carrier, and a mainland site loads with the mainland China direct switch on, which only a direct route allows (the nodes deny `geoip:cn`, §8.2);
- the provider choice is recorded;
- *(revision 5)*:
  - the 72 h figure is computed from the availability record (§15.7);
  - the SIM meter is within 3 % of the M7's own counter, read by the router adapter or by hand if M2a found no JSON interface;
  - the exit Mac joins no Durham network (P0-2);
  - pulling the M7's power is reported by the alerting within 15 minutes, and so is stopping the VPS, through the F6 channels (an ntfy notice, or Healthchecks' own e-mail when the node itself is gone);
  - *(revision 6)* the viewer works from the operator's phone off campus, on mobile data (F5, F15), and its emergency stop closes the gate until the Mac clears the hold;
  - *(revision 6)* the daily digest arrives at 09:00 UK time with Level-0 text only.

Commands:
```
mooringctl node status lon1 --json
mooringctl usage --month <YYYY-MM> --json
mooringctl exit status --follow --json
```

### M9 — Operations (needs two VPSs)

**Deliverables:**
- A standby node on a second ASN; from then on every user holds both nodes (F11), which takes a new file for every user.
- Runbooks: `rotate`, `revoke`, `retire`, `incident`, `console-recovery`, `mac-loss` (`delivery` exists since revision 8).
- *(Revision 5)* The runbooks listed in §6. `exit-host`, `power-cut` and `sim-plan` are needed before M8, and are drafted from the M2a results; *(revision 8)* so are `delivery`, `user-onboarding` and `user-agreement` (F9–F11), written in revision 8, whose CFM steps are checked on the 0.5.x build in M6.

**Verification and acceptance:**
- A rotation drill at 20 minutes or less hands-on.
- Revocation and retirement drills, with deletion confirmed by a Keychain listing through the helper's self-check.
- A console-recovery drill on the standby.
- A canary agent upgrade with confirm.

### M10 — Shaping and placement (optional, gated on M8 data)

**Deliverables:**
- cake on `wgexit` egress plus IFB ingress: static first, then autorate.
- Per-user source addresses only if the fairness data needs them.
- A China-near premium relay into London, only if peak TTFB and bulk throughput improve by at least 30%.

**Acceptance:**
- The loaded-latency increase at p95 is at most 30 ms at 85% or more utilisation (L4 `T-impair` and L8).

---

## Appendix A. Candidate architectures

Three drafts were compared; implementation risk is scored so that 10 means the lowest risk. **Mooring** (operability-first, 58/70) was chosen over **Tidegate** (security-first, 47/70) and **Portway** (performance-first, 45/70). Elements taken from the other two:

**From Portway:**
- the leg/sender table and the performance budget;
- QUIC blocking;
- the explicit `oif` route;
- the VPS TCP sysctls;
- the fixed MTU of 1280;
- closing the gate before sleep;
- a shaping milestone gated on data.

**From Tidegate:**
- the threat model;
- the hop range above the ephemeral ports;
- camouflage forwarding;
- typed outbounds;
- per-user, per-node credentials;
- a power helper owned by the daemon;
- the sandbox spike;
- revocation and retirement states;
- proof of the forced command;
- the `ReachabilitySuspect` and `TargetDegraded` signals;
- the data-protection Keychain.

**Defects found in the drafts and fixed here:**
- Portway's hop redirect swallowed its own WireGuard port.
- Condition-less sing-box rules.
- Missing linkname build flags.
- The in-chain probe's martian drop (fixed by `accept_local`).
- Xray's swallowed bind errors (fixed by the owner guard).
- `disableFallback` making DoH single-server.
- Path-based Hysteria2 certificates breaking staging.
- A deprecated sleep assertion.
- Unowned gate state.
