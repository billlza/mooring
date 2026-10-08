<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Mooring design

**Status.** Design, revision 4 (2026-10-08): M1 complete, pending the operator's commit. Revision 3 added the user decisions D-3 (Xray v26.9.30 with REALITY e1986a4) and D-7 (build host). Revision 4 brings the document into line with the M1 code (`crates/`, `xtask/`, `contract/`): where the code is stricter, or where the pinned upstream source contradicted revision 3, the code is authoritative and this text now says what it does. It also records the decisions D-8 (rotation order) and D-9 (where CFM acceptance is checked). The pure Rust core is built and tested on this Mac; no engine has been built, and nothing has been run on a VPS or provisioned. Any statement not confirmed in source code or a primary document is marked *(inference)*, and each one is tied to the test lane or milestone that will prove it. Evidence is cited as `file:line` at a named commit, or as a URL with the date it was checked. Pinned upstream trees used for citations:

| Tree | Commit |
|---|---|
| sing-box v1.14.2 | `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` (clean checkout, no local modifications) |
| Xray-core v26.9.30 (prerelease) | `b26a91de4f3294e26a0ad0a970b81a386a41f789`, built with `xtls/reality` replaced by `e1986a4` (§4.2) |
| XTLS/REALITY | `e1986a4d31ca33c087a72ab4644aef1295693b69` (parent of `8cdf7bf9`, which Xray v26.9.30 pins) |
| Linux | v6.12 `net/ipv4/{route.c,fib_frontend.c,fib_trie.c}` |
| sing-quic (as pinned by sing-box v1.14.2 `go.mod:53`) | `v0.7.1-0.20260924092235-6a3a24d65b99` |
| CFM 0.4 line | `ac981c3` (sing-box 1.14.1) |
| CFM 0.5 line | worktree at `3157ef9` (sing-box 1.14.2), which contains `f340fae` (REALITY requires uTLS) and `e6c9e05` (the committed `support_x25519mlkem768` opt-in). The export contract (`docs/cfm-contract.md`, `contract/cfm-manifest.toml`) is pinned at `3157ef9`. |

**What Mooring is.** Mooring lets a small number of trusted users in mainland China reach the internet through the operator's UK mobile connection. Their traffic exits from a NETGEAR Nighthawk M7 Pro (MR7450) with an EE SIM, attached to the operator's Mac. EE puts consumer IPv4 behind CGNAT and reportedly filters unsolicited inbound IPv6, and the MR7450 has no inbound IPv6 controls. The Mac therefore cannot accept connections from China. Instead, a rented Linux VPS faces China, and the Mac dials out a tunnel to that VPS and acts as the exit.

---

## 0. Decisions at a glance

| Area | Decision |
|---|---|
| Product | **Mooring**. Repository `mooring`, licensed GPL-3.0-or-later, separate from CFM. Bundle id `com.bill.mooring`; lab builds use `com.bill.mooring.lab`. Branch names are neutral (`main`, `feature/<area>`, `fix/<area>`). No tool, generator or attribution markers appear anywhere. Check the name for collisions before creating the repository. |
| Topology | CN user (CFM) → **London VPS**, serving VLESS+REALITY+Vision on TCP/443 and Hysteria2 on UDP 61000 (hopping across 61001-62999) → **kernel WireGuard `wgexit`** → **Mac** running a userspace sing-box WireGuard endpoint. The Mac dials out, and its sockets are bound to the **M7 wired interface** → EE → internet. |
| VPS steering | Xray's only exit outbound is bound to `wgexit` (SO_BINDTODEVICE). Routing uses `ip rule oif wgexit lookup 77` with `default dev wgexit table 77`. `accept_local=1` is set on `wgexit`. An **nft owner guard** (`meta skuid`) rejects any connection either engine originates outside its allowed paths, which makes the steering kernel-enforced. An nft output **gate** fails client connections fast while the Mac is away. |
| Engines | **VPS:** Xray-core **v26.9.30 with REALITY pinned to e1986a4** handles REALITY, routing, DNS and accounting. sing-box **1.14.2** runs the Hysteria2 inbound only, and hands each user to Xray over loopback. **Mac:** sing-box **1.14.2** runs as two processes: `mooring-exit` (WireGuard endpoint and bound egress) and `mooring-probe` (in-chain probe clients). Every engine is built from pinned source with one Go toolchain and upstream's release flags. |
| Tunnel uplink | `SameAsExit` (the M7) is the default. `Separate(home interface)` is an explicit setting. Mooring never switches between them automatically. `Separate` may only name a connection the operator contracts for (their own home broadband). It must never name an institutional network: on 2026-10-08 this Mac's only other uplink was Durham University Wi-Fi (Janet AS786, NAT, no IPv6), whose IT regulations limit use to authorised users and academic purposes. On that network the exit runs `SameAsExit` only. |
| Egress verification | **Mandatory carrier check.** Every observed egress IP must fall inside the EE prefixes recorded in the field spike (M2). In addition, `Paired` mode brackets each in-chain probe between two direct probes. Direct probes run every 30 s and in-chain probes every 300 s. A violation stops the Mac engine (fail closed). |
| Rust | `mooringctl` (CLI, LaunchAgent daemon and bound SSH dialler) is one signed binary with one keychain identity. `mooring-agent` is a static musl binary on the VPS: forced-command SSH handler, transaction runner, watch loop and reflector. There are eight library crates, plus the test-only `mooring-fixtures`. |
| Swift | `Mooring.app` provides the menu bar, SMAppService registration, a status stream read from the CLI, and notifications. `mooring-power`, a child of the daemon, holds NetworkClientActive and PreventUserIdleSystemSleep and reports sleep and wake events. Swift never handles secrets. |
| CFM export | One file per user. The default is sing-box `{"outbounds":[...]}` with an SPKI pin. Clash YAML containing only `proxies:` with a DER `fingerprint` is optional. REALITY always carries `utls` or `client-fingerprint`. URIs are never exported. Shapes are selected by each user's CFM client line. |
| VPS | London, Debian 13 amd64, 1 vCPU and 1 GiB, with a dedicated public IPv4 configured on the interface. There is one primary node plus a standby on a different ASN. |

---

## 1. Threat model and trust boundaries

### 1.1 Assets

| Asset | Where it exists | Level |
|---|---|---|
| User traffic content and metadata | The VPS terminates the proxies, the Mac sees only destination IPs, and EE sees the exit flows | 2 |
| Users' China source IPs | VPS only. The inner source on the tunnel is always 10.77.k.1, and the Mac's peer accepts only that source (`allowed_ips` /32) | 2 |
| SIM-holder attribution (all exit traffic is legally the SIM holder's) | The Mac deny list (authoritative) and VPS policy | 2 |
| Node keys: REALITY private key, Hysteria2 TLS key, the VPS's WireGuard key | Mac Keychain and that VPS | 2 |
| Per-user, per-node credentials | Mac Keychain, that VPS, and that user's export file | 2 |
| SSH operations key | A file on the Mac, mode 0600, excluded from backups | 2 |
| The operator's Mac: files, Keychain, other keys, LAN | Mac | Impact equivalent to Level 3 |
| Engine and blob hashes | Both | 1 (detects accidental corruption) |
| Accounting and status | Both | 0 |

### 1.2 Adversaries

**A compromised VPS or a malicious provider**
- *Can:*
  - see the flows and China IPs of that node's users;
  - impersonate that node to its users;
  - push public-destination TCP and UDP out of the EE IP, limited by the Mac's deny list and the SIM cap.
- *Cannot:*
  - use credentials on the other node, because all credentials are per node;
  - reach the Mac's loopback, the LAN, the M7 admin page or EE's CGNAT range, because the Mac rejects them by final IP and that rejection is tested directly over `wgexit` (T-deny-mac);
  - learn users' real names, which exist only on the Mac;
  - learn the home broadband IP, unless the operator chose `Separate` mode;
  - reach the Mac's files: its only surface is a userspace WireGuard and gVisor stack inside `mooring-exit`, sandboxed if the M5 spike passes.

**The GFW, or anyone holding a user's export file**
- *Can:* identify and block that node, or use that one user's credentials on that node.
- *Mitigations:* revoke the user, rotate the node, keep a standby.

**A malicious user**
- *Can:*
  - use the exit within policy;
  - saturate the shared uplink (neither engine supports per-user rate limits, which is an accepted risk);
  - open many flows, up to the node-wide flow cap (§8.5).
- *Cannot:* chain through a node to multiply SIM usage, because node IPs are denied to every identity except the probe (§8.2), and cannot reach VPS-local services.

**CFM running on the same Mac.** CFM's NetworkExtension sets `includeAllNetworks=false` and `enforceRoutes=false` (CFM `HostBridge.swift:1603-1608`). Interface-bound sockets should therefore bypass its tunnel *(inference; proven in M2 and L6-bypass)*. If that ever changes, the carrier check fails and the exit stops.

**EE** sees WireGuard metadata and the exit flows. This is inherent to the design.

**Same-user processes on the Mac, or a compromised Mac.** Either means total compromise. The data-protection keychain gives no prompts and keeps secrets out of backups, but the entitled `mooringctl` will export secrets for any process running as the same user. The forced-command SSH key is a robustness control (typed operations, no ad-hoc drift), not a boundary against the operator's own machine.

**Failure domains.** Hysteria2 reaches the exit through Xray over loopback, so an Xray outage takes down both protocols on that node. The standby node is the redundancy.

### 1.3 Controls deliberately not added

| Not added | Reason |
|---|---|
| WireGuard pre-shared key | It protects tunnel metadata against a future quantum attacker, but EE already sees the same destinations in clear on the exit leg. |
| HMAC or signatures on bundles and agent messages | SSH already authenticates both ends. |
| Key generation on the VPS (other than its SSH host key) | It gains nothing against a compromised Mac, which holds root SSH, and it would need a second renderer. |
| Encryption at rest on the VPS | The provider has root. |
| fail2ban, port knocking, SSH 2FA, GeoIP allowlists for SSH | OpenSSH has had PerSourcePenalties on by default since 9.8, and the Mac's CGNAT source changes. |
| Rate limits on TCP/443 | They are themselves a fingerprint (REALITY README). Only TCP/80, UDP/443 and the reflector port are limited per source, at levels far above browser use. |
| Blocking ICMP | It breaks path-MTU discovery. |
| nft block of the metadata service (169.254.169.254) | Bootstrap replaces the SSH host key that was injected through user-data (§13.2), so user-data holds no live secret afterwards. |
| LocalAuthentication gating of `user export` | Any same-user process can already read the operations key file. The gate would add a prompt without creating a boundary. |
| Restricting the reflector to EE source prefixes | A Wi-Fi offload on the M7 would then show up as a timed-out probe rather than as `OutsideCarrierPrefixes`, which turns a detectable violation into an ambiguous one. A per-source limit is used instead (§11.4). |
| Regex log redactor | Engines run at log levels that do not emit per-flow lines. The canary lane checks this, and stderr tails are scrubbed by exact substring against the bundle's known secrets (§15). |
| CAP_NET_ADMIN or SO_MARK for Xray | The owner guard enforces the same thing with no privilege on the internet-facing process. |
| Provider API token (v1) | It would be a long-lived credential able to create and destroy servers. |

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
                                ▼ USB-C or 2.5GbE (never Wi-Fi) → M7 Pro (offload off) → EE 5G (CGNAT) → internet
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

---

## 3. Performance budget

Everything in this section is *(inference)* unless a source is cited.

**Assumptions.** Round-trip times: China↔London C ≈ 280 ms (WonderNetwork: 260–268 ms typical, 315 ms peak); VPS↔Mac over EE M ≈ 40 ms; Mac↔destination D ≈ 20 ms. The VPS↔REALITY target RTT T must be at most 2 ms; this is a hard requirement.

**Time to first byte.** For an HTTPS GET with a warm DNS cache:
- REALITY: about 1.30 s, or about 1.42 s at peak. REALITY dials the target on every connection (`REALITY tls.go:168`), so a target 20 ms away would add about 40 ms to every connection.
- Hysteria2 with a warm session: about 0.74 s.

**Throughput in `SameAsExit` mode.**
- The 5G uplink is about 16 Mbps median for EE 5G (Opensignal, Q4 2025); p10 may be about 5 Mbps.
- At MTU 1280, payload efficiency is 1228/1340, about 91.6%.
- That leaves about 12–14 Mbps of user payload **in total**, shared by every user's downloads *and* uploads.

**SIM volume.**
- In `SameAsExit` mode each byte served costs about 2.1× on the SIM, so EE's roughly 600 GB threshold is reached at about 280 GB served per month.
- In `Separate` mode the factor is about 1.04×, or about 575 GB served per month. This is the largest available gain.
- Probing costs about 1 GB per month: in-chain probes every 300 s, direct probes every 30 s.

**MTU.** The MTU is fixed at **1280** in v1. M2 only confirms that the outer path MTU is at least 1340.

**Keepalive.** The keepalive is **10 s** (about 1 MB per day) until M2 measures EE's UDP NAT timeout. After that it must lie in [5 s, NAT_timeout/2], and never above 60 s, which keeps three keepalives inside the watch's 180 s handshake window (`Keepalive`, §7). Measured cellular CGNAT UDP timeouts have a median of 65 s and a range of 10–200 s (arXiv 1605.05606).

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
| Go | **1.27.x**: the newest patch at M0, tarball sha256 pinned. CFM pins 1.27.1 and builds the same gVisor fork with `with_gvisor` (CFM `scripts/dependency_pins.env:40,68`). | All engine builds |
| govulncheck | Newest stable at M0, version and module sum pinned (CFM pins v1.6.0, `dependency_pins.env:45-46`) | Vulnerability gate |
| Geodata | `geoip.dat` and `geosite.dat` from the official `Xray-linux-64.zip` of v26.9.30, sha256 recorded in `engines.lock.toml` at the first build (Level 1) | `geoip:cn` / `geosite:cn` |
| RealiTLScanner | v0.2.3, built from a pinned commit with the same Go, sha256 in `engines.lock.toml` | Operator-run target discovery |
| Debian | 13 (trixie), the current point release at M2; kernel 6.12 series | VPS OS |
| Rust | 1.98.1 (`rust-toolchain.toml`) | All Rust |
| Swift | 6.4 via `xcrun` (Xcode 27), never the bare `swift` on PATH | App and power helper |

### 4.1 Build recipes

All builds run through `cargo xtask engines build`, with `GOTOOLCHAIN=local`, `-mod=readonly`, `CGO_ENABLED=0` and `-trimpath`.

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
- `go version -m <bin>` shows the pinned Go version, `-trimpath`, `CGO_ENABLED=0`, the exact tag set (including `badlinkname,tfogo_checklinkname0` for sing-box), and the ldflags (`godebugDefault`, `-checklinkname=0`).
- Upstream package tests pass under the pinned Go: Xray `proxy/vless` and `transport/internet/reality`; sing-box `protocol/hysteria2` and `protocol/wireguard`. If either fails, a reviewed commit pins Go 1.26.8 and records the reason.
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
- A reachable govulncheck finding is fixed by a reviewed bump of that module to its latest stable version (`go get <module>@<stable>`). The `go.mod`/`go.sum` diff is recorded as a patch under `engines/patches/` with its sha256 in `engines.lock.toml`, in the same way CFM carries `sing-box-v1.14.1-security-dependencies.patch`.
- A Go point release with security fixes triggers a rebuild of every engine.
- `cargo xtask engines audit` runs monthly and before every release.

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
| `mooringctl daemon` (Rust LaunchAgent) | launchd | Interface resolution, preflight, rendering, supervising both engines, probes and verdicts, latches, the SIM meter, the sleep drain, the control socket. It is the **only** process besides the CLI that reads secrets (same binary, same keychain identity). |
| `mooring-exit` | daemon | Receives its config on stdin (`check -c stdin`, then `run -c stdin`; `cmd/sing-box/cmd_run.go:53`). Runs the WireGuard endpoints (one per node, at most 2) and the bound `egress`. |
| `mooring-probe` | daemon | Receives its config on stdin. Runs the loopback probe inbounds and the exported probe outbounds. A failure here maps only to `NodeProbeFailed`; it never takes the exit down. |
| `mooring-power` (Swift) | daemon; stdin is its lifetime pipe | While the exit is enabled and the Mac is on AC, holds `NetworkClientActive` and `PreventUserIdleSystemSleep`. `PreventSystemSleep` is not used: the macOS 27 SDK `IOPMLib.h:1014-1023` marks it deprecated and unsupported. Emits `will_sleep`, `did_wake` and `power_source`, and calls `IOAllowPowerChange` when the daemon acknowledges. Releases everything and exits at EOF. |

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

The exit runs only while the operator is logged in. After a FileVault reboot, someone must log in first.

### 5.2 VPS units

| Unit | User | Capabilities | Content |
|---|---|---|---|
| `mooring-xray.service` | `mooring-xray` | `CAP_NET_BIND_SERVICE` | `xray run -c /etc/mooring/current/xray.json`, `XRAY_LOCATION_ASSET=/opt/mooring/engines/geodata/current`. `BindsTo=` and `After=wg-quick@wgexit.service nftables.service`. `ExecCondition=agent halted-check`. |
| `mooring-hy2.service` | `mooring-hy2` | none (port 61000) | `mooring-hy2 run -c /etc/mooring/current/hy2.json`. `After=mooring-xray.service nftables.service`. `ExecCondition=agent halted-check`. |
| `wg-quick@wgexit.service` | root | — | `/etc/wireguard/wgexit.conf` → `current/` |
| `nftables.service` | root | — | `/etc/nftables.conf` → `current/` |
| `mooring-watch.service` | `mooring-watch` (group `mooring`) | `CAP_NET_ADMIN` only | The **only** process that opens the gate. Holds, accounting, target checks, status. 5 s loop. `Restart=always`, `RestartSec=2`, `StartLimitIntervalSec=0`, `ExecStopPost=agent gate-close`. |
| `mooring-reflect.service` | `DynamicUser=yes` | none | `agent reflect` on `<VPS4>:27900` |
| sshd | root, forced command only | — | `restrict,command="/usr/local/lib/mooring/agent/current serve-ssh --role ops"` |
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
                                      the VPS contract names (src/vps.rs), StderrTail
    render/      mooring-render       pure: VPS bundle, Mac exit config, Mac prober config (MacProbeOutbound), cloud-init;
                                      the model <-> agent-proto conversions (src/wire.rs)
    store/       mooring-store        state.json (shared read lock, exclusive write lock + CAS + atomic write + migration chain);
                                      SecretStore trait; in-memory impl (the Keychain impl is M5)
    fixtures/    mooring-fixtures     (test-only) four deterministic fixture deployments with their secrets and resolved
                                      interfaces, for goldens; never a normal or build dependency
    macsys/      mooring-macsys       cfg(macos), the ONLY crate with unsafe: NET_RT_IFLIST2 (if_data64, AF_LINK), gateway lladdr, PF_ROUTE monitor
    daemon-core/ mooring-daemon-core  daemon state machine, verdicts, probe primitive, latches, control protocol; traits for interfaces,
                                      engines, clock, power, secrets, ssh
    mooringctl/  (bin) cli, daemon wiring, supervise, ssh (incl. dial-bound), provision, usage, status stream
    mooring-agent/ (bin, x86_64/aarch64-unknown-linux-musl) bootstrap, serve-ssh, txn, watch, reflect, target-check, accounting, self-test
    e2e/         (dev-only) netns harness and lab harness; never built for release
    fieldkit/    (dev-only bin, darwin + linux-musl) M2 field measurements; never shipped
  xtask/         M1: ci, graph-check, kinds-coverage, deny-skips, acceptance, release-acceptance, clean.
                 Later: engines {build,verify,upstream-tests,audit}, govulncheck, cfm-client, lane <name>, m0 …, release, release-verify
  apple/         project.yml (XcodeGen); Packages/MooringKit (swift-tools 6.2, macOS 15, .v6); App/; Power/; Tests/
  contract/      golden/<fixture>/…, cfm-acceptance.toml, cfm-manifest.toml, status-fixtures/*.json, cli-fixtures/*.json, agent-proto-golden/*
  lanes/         netns/{topology.sh, impair.sh, nat-profiles.sh, ablation.toml}, vm/{qemu-debian13-amd64/, lima-debian13-arm64-lab.yaml}, staging/checklist.md
  docs/          design.md threat-model.md performance.md engines.md cfm-contract.md measurements/
                 runbooks/{provision,rotate,revoke,retire,incident,console-recovery,mac-loss,delivery}.md
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
| `macsys` | — | |
| `daemon-core` | `model`, `render`, `export`, `agent-proto` | |
| `mooringctl` | `model`, `keys`, `render`, `export`, `agent-proto`, `store`, `macsys`, `daemon-core` | |
| `mooring-agent` | `agent-proto` only, plus std, serde, serde_json, thiserror and sha2. **The VPS never renders.** | |
| `e2e` | `model`, `keys`, `render`, `export`, `agent-proto`, `daemon-core` | |
| `fieldkit` | `model` | |

**The cost of xtask's product edges (D-9).** The xtask edges are normal dependencies, so every `cargo xtask` command, `clean` and `graph-check` included, first compiles `export` and `model` and their dependencies (x509-parser among them; about 60 crates instead of serde, serde_json and thiserror), and stops if they do not compile. While the tree does not build, free the disk with `rm -rf target` instead of `cargo xtask clean`. x509-parser is also built a second time with xtask's narrower feature set, which costs space in the bounded `target/` (D-7).

`render` is the one Mac-side crate that sees both the model and the wire types, so every model ↔ agent-proto conversion lives in `crates/render/src/wire.rs` (adoption site, `Apply` header facts, target facts, SSH host-key lines). Rules that both sides validate (interface names, DNS names, port ranges, certificate names, HTTP statuses) are the same rule on each side, which a cross-crate property test in `crates/render/src/tests/wire_rules.rs` proves.

Once `daemon-core` exists (M3), the same check also builds `model`, `keys`, `export`, `agent-proto`, `render` and `daemon-core` for `x86_64-unknown-linux-gnu`, because the Linux e2e lane runs the real daemon-core. M1 does not implement this part.

### 6.2 Workspace policy

- Edition 2024 with `resolver = "3"`.
- `[workspace.lints]` sets `unsafe_code = "forbid"` everywhere except `macsys`, which uses `deny(unsafe_op_in_unsafe_fn)` and `// SAFETY:` comments. It also denies `missing_debug_implementations`, `unused_qualifications` and `unreachable_pub`, and the clippy lints `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout` and `print_stderr` (test code may unwrap, expect, panic and print: `clippy.toml`). No crate carries an `allow` or `expect` attribute.
- `clippy -D warnings`.
- `cargo deny --all-features --locked check -D warnings`: GPL-compatible licences only, and only those the graph uses (`unused-allowed-license = "deny"`); `multiple-versions = "deny"`; warn-level lints promoted to deny.
- No `*` versions. Every file carries an SPDX header. JSON goldens, which cannot hold a comment, have a REUSE `.license` sidecar; insta snapshots carry it in their description line.
- The agent links with `rust-lld` for musl *(inference; accepted in M0)*.

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

Added with the crates that need them (later milestones):
- tokio 1.53.2 (current-thread runtime; `mooringctl` and `daemon-core` only)
- socket2 0.6.5 with `features = ["all"]` (`bind_device_by_index_v4`, i.e. IP_BOUND_IF)
- clap, tracing
- security-framework 3.7 (data-protection keychain support confirmed in M5)
- libc (`macsys` only)

**Deliberately absent.**
- No `ssh-key` crate: its latest stable release, 0.6.7, needs sha2 0.10 and ed25519-dalek 2, which would duplicate the crypto stack. A small OpenSSH encoder is golden-tested against `/usr/bin/ssh-keygen -y -f` and `-l` instead.
- No TLS stack in our Rust code, because the reflector is plain TCP.
- No gRPC: accounting shells out to the pinned `xray api`.
- No YAML library at runtime.

---

## 7. Data model and migrations

Non-secret state lives in `~/Library/Application Support/Mooring/state.json`; lab builds use `Mooring-Lab/`. `mooring-store` (`crates/store/src/store.rs`, `ordered.rs`, `durable.rs`) is rooted at a directory the caller passes in; it never reads `HOME` and never creates the directory. Writes follow four rules:
- An exclusive lock is taken on `state.lock` (`std::fs::File::lock`, mode 0600) for the whole read-modify-write. Reads take a shared lock on the same file, so a reader never sees a state that was renamed into place before its directory was fsynced. The lock has no timeout.
- Compare-and-swap is done on `config_generation` or `runtime_revision`.
- Each write goes temp file (mode 0600) → fsync → rename → fsync of the directory (`F_FULLFSYNC` on Apple targets).
- The CLI is the only writer of `state.json`. The daemon writes only `run/` (control socket, `latch.json`, `engine-*.pid`), `status.json` and `usage/`.

`state.json` is pretty-printed JSON with a trailing newline, with the fields in the order `version`, `deployment`, `runtime`. Nodes and users are serialised as lists in id order, so a duplicate id is a decode error (`DuplicateId`). Two golden files pin the V1 on-disk format: `crates/store/src/tests/golden/state-v1.json` (an `Adopted` node) and `state-v1-every-variant.json` (the `Applied`, `Retiring`, `RetiredPendingProviderDeletion` and `Retired` stages, every user status, a `Separate` uplink, both selector variants and two Hysteria2 listeners). Only the `Planned` stage is pinned by neither: the every-variant document cannot hold it beside `Applied` and `Retiring` under the two-node cap. A serialisation change therefore needs a new version and a migration step.

```rust
pub enum StateFile { V1(StateV1) /* , V2(..) when introduced */ }
pub struct StateV1 {                            // on disk: {"version": 1, "deployment": …, "runtime": …}
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
    nodes: BTreeMap<NodeId, Node>,              // at most MAX_ACTIVE_NODES = 2 active (Planned..=Retiring); retired nodes stay
    users: BTreeMap<UserId, User>,
    next_wg_index: WgIndex,                     // monotonic, never reused
}
pub struct ExitSite {
    pub egress: InterfaceSelector,              // the wired NIC facing the M7
    pub uplink: Uplink,                         // SameAsExit | Separate(InterfaceSelector)
    pub egress_check: EgressCheck,              // fixed from M2 data; changed only by explicit operator action
    pub sim: SimPolicy,                         // cycle_day 1..=28, warn_bytes (450e9) < hard_stop_bytes: Option<u64> (560e9)
    pub probe: ProbePolicy,                     // direct 30 s, in-chain 300 s, base_port 47101
    pub flow_cap: FlowCap,                      // node-wide new-flow cap into wgexit; sized from M2
}
pub struct EgressCheck {
    pub carrier_prefixes: NonEmpty<CarrierPrefix>, // the EE public pool prefixes observed in M2 (RIPE inetnum evidence),
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
    pub status: UserStatus,                     // Active | RevokePending | Revoked
    pub per_node: BTreeMap<NodeId, UserNodePublic>,   // { short_id: ShortId }; while RevokePending, exactly the nodes
                                                      // that still have to commit the revocation
}
pub enum Capability { RealityMlkemOptIn /* emits support_x25519mlkem768; accepted by ClientLine::Cfm05 only */ }
pub enum Bookkeeping {                          // the only changes that keep config_generation (below)
    Applied { node: NodeId, applied: AppliedConfig },
    RevocationCommitted { user: UserId, node: NodeId },
    RetirementShutDown { node: NodeId },
}
pub enum SecretRef {
    NodeRealityPrivate(NodeId), NodeWgVpsPrivate(NodeId), NodeWgMacPrivate(NodeId),
    NodeHy2Key(NodeId), NodeHy2Obfs(NodeId, ListenerIdx), NodeSshBootstrapPrivate(NodeId) /* deleted at adoption */,
    UserVlessUuid(UserId, NodeId), UserHy2Password(UserId, NodeId), UserLoopUuid(UserId, NodeId),
    ProbeVlessUuid(NodeId), ProbeHy2Password(NodeId), ProbeLoopUuid(NodeId),
}
```

**Where node facts live.** A node's address and host facts are unknown before adoption, so they belong to the lifecycle (`NodeSite`) rather than to `Node`. `Adopted`, `Applied` and `Retiring` carry the site; `RetiredPendingProviderDeletion` keeps only the address, which every renderer still denies; `Planned` and `Retired` carry nothing.

**Cross-entity invariants** are checked in one place, whenever a `Deployment` is built from `DeploymentParts`, including on decode (`crates/model/src/deployment.rs`):
- node and user ids are unique;
- at most `MAX_ACTIVE_NODES` (2) nodes are active, counting `Planned` through `Retiring` (`TooManyNodes`). The bound is two because the Mac exit carries one WireGuard endpoint per node, at most two (§5.1), and the probe port span is sized for two nodes (`PROBE_PORT_SPAN`: 2 nodes × 2 protocols below the macOS ephemeral range). Rotation is ordered around it (§13.4, D-8);
- WireGuard indices are unique and below `next_wg_index`, and live node addresses are unique;
- an adopted node's port plan was checked against its host's live range (`PortPlanConflict{EphemeralRangeChanged}`);
- an `Applied` node has a target, and its applied generation is no newer than the deployment's (`GenerationAhead`);
- users hold credentials only on active nodes; a `RevokePending` user holds them on at least one node, and a `Revoked` user on none;
- REALITY short ids are unique per node, the probe's included.

**Newtypes.** Each enforces its rule in its constructor, and deserialisation goes through the same check.
- `PublicIpv4` rejects every `SPECIAL_V4` range. CFM accepts RFC1918 and CGNAT addresses, so this is stricter.
- `ShortId`: exactly 16 lowercase hex characters, not all zero. Xray decodes `"0000000000000000"` to the same bytes as the empty short id, which any client matches.
- `X25519Pub`: 43 characters of unpadded base64url, not all zero.
- `DnsName`: lowercase ASCII LDH labels, at most 253 bytes, no trailing dot, and a top label that is not all digits.
- `PortPlan`: all ports and ranges are disjoint, including the system ports 22, 80, 443, 10085 and 10443 (`SYSTEM_PORTS`); fixed ports lie outside `ip_local_port_range`; hop and reserved ranges lie above it. A plan holds at most 2 Hysteria2 listeners and 2 reserved ranges, and records the ephemeral range it was checked against.
- `Hy2Listener`: the hop range starts at `port + 1`, because exports emit one contiguous client range (`61000:62999`). Listeners live only in `PortPlan`, so the Hysteria2 ports have a single owner, and each listener carries its own `HopInterval`.
- `HopInterval`: 5..=3600 seconds. The floor is the pinned sing-quic dialer's (`hysteria/hop.go:55-57`, "hop interval must be at least 5 seconds") and CFM 0.5's import bound (`crates/cfw-singbox-config/src/profile_validation.rs:17-18,611-647`); CFM 0.4 accepts 1..=3600. So 5..=3600 is the range every client line both imports and dials, and a plan the exports could not serve cannot be built.
- `Keepalive`: 5..=60 seconds. 5 s is the §3 floor; 60 s keeps three keepalives (the watch's rx-growth window) inside the watch's 180 s handshake limit.
- `LanSubnet` (the subnet in an `InterfaceSelector`): canonical, and wholly inside one private LAN class of `SPECIAL_V4` (`LAN_CLASSES`: 10/8, 100.64/10, 169.254/16, 172.16/12, 192.168/16). The Mac exit's `SPECIAL_V4` reject (§8.7) therefore always covers the M7 and home LANs.
- `LinuxIfName`: the kernel's rule (`dev_valid_name`, Linux v6.12 `net/core/dev.c`): 1..=15 bytes of printable ASCII, not `.` or `..`, without `/`, `:` or whitespace. It is exactly agent-proto's `IfName`, so a name `Hello` reports converts both ways.
- `Uuid`: canonical lowercase, non-nil, version 4, RFC 9562 variant. Every UUID is a credential, so `Uuid` has no `Serialize`, `Deserialize` or `Display`, its `Debug` is redacted, and it is zeroized on drop. A test stops compiling if it ever gains either serde trait.
- The REALITY ClientHello is export's `ClientHello { Chrome, ChromeX25519Mlkem768 }` (§9.2), not a model type.

**Missing keys are decode errors.** Every `Option` in the state (`sim.hard_stop_bytes`, `reality.target`) must be present: an explicit `null` means none, and a missing key fails to decode. A lost key therefore never silently disables the SIM hard stop or drops a target.

**`Lab` variants.** Lab addresses exist only behind `cfg(feature = "lab")`, which arrives with the lab lanes (M5); M1 has no `lab` feature. There is no runtime "private address in release" error. Instead, the release verifier asserts that `cargo tree -e features -p mooringctl` contains no `lab`, and that no shipped binary contains the lab marker string.

**`ConfigGeneration` versus `RuntimeRevision`.** The two counters change for different reasons:
- Enabling or disabling the exit bumps `RuntimeRevision` only (`Store::set_exit_enabled`). Nodes never appear stale because of it.
- Every other change bumps `ConfigGeneration` (`Store::update_config`, `update_config_with_secrets`), except the three `Bookkeeping` records, which the store commits with the generation unchanged (`Store::record`, `record_with_secrets`). None of the three changes any rendered VPS bundle or any export, which `crates/render/src/tests/bookkeeping.rs` checks byte for byte:
  - `Applied{node, applied}` records the generation and bundle digest a node confirmed (§11.2). While a node stays `Applied`, its applied generation is monotonic: a lower one is refused (`GenerationRegressed`), and one ahead of the deployment is refused (`GenerationAhead`). An equal one is recorded again with the digest the node confirmed: an unchanged re-apply repeats the digest, and a re-apply of the same generation after an app upgrade with new engines (§13.3) replaces it.
  - `RevocationCommitted{user, node}` drops a `RevokePending` user's credentials on a node that committed the revocation; with none left the user becomes `Revoked` (§13.5).
  - `RetirementShutDown{node}` moves a `Retiring` node to `RetiredPendingProviderDeletion` and drops every user's credentials on it (§13.4).
- Only that record sets a confirmed generation. A configuration change (`update_config`, `update_config_with_secrets`) is refused with `AppliedEdited{node}` if, after the closure, any node holds an `AppliedConfig` it did not hold before, whether newly set, lowered, raised or with another digest (`crates/store/src/store.rs`, `change_config`); moving a node out of `Applied` (to retire it) is allowed, since it only withdraws a confirmation and exports then refuse the node. A closure therefore cannot forge a confirmation, even at the generation the store is about to stamp.
- Exports refuse a node whose applied generation is older than the deployment's (`NodeNotApplied{Stale}`, §9.2), so an export always matches what every node in it has confirmed. Any generation bump, including one with no VPS-visible effect, therefore needs a `node apply` of each node a user holds credentials on before that user's file can be exported again.
- The daemon restarts an engine only if the digest of that engine's rendered config changes. Adding a user changes the VPS bundle but not `mooring-exit`'s config, so it does not drop the exit.
- **Note for the daemon (M5):** a `Bookkeeping` record changes `state.json` while keeping both counters, so neither `config_generation` nor `runtime_revision` alone detects every state change.

**`State` holds no `Secret` fields,** so no secret can be written to disk by construction: neither `Secret<T>` nor `Uuid` implements `Serialize`. Secrets are written before any state that references them. On deletion, state is updated before the secrets are removed. The store enforces this order by structure (`crates/store/src/ordered.rs`):
- `update_config` and `record` refuse any change to the set of referenced secrets (`SecretRefsChanged`).
- `update_config_with_secrets` requires the supplied secrets to be exactly the newly referenced ones (`SecretPlanMismatch`, `DuplicateSecret`) before anything is written. It writes them (a failure leaves the state unchanged: `SecretWrite`), commits the state, and then deletes the dropped secrets while still holding the lock. A failed deletion is reported as `SecretCleanup{committed, failures}`: the state is committed, and every other deletion is still attempted.
- `record_with_secrets` commits a `Bookkeeping` record and then deletes the secrets it stopped referencing, in the same way.

The model's `SecretEntry` (one variant per `SecretRef`) pairs each reference with the right kind of material, and both `SecretSnapshot::insert` and `SecretStore::put` take it. `mooringctl doctor` lists orphaned keychain items.

**Migrations.**
- `store::migrate` is a chain of pure functions (`V1 → V2 → …`), each golden-tested. V1 is the only version, so the chain has no steps yet.
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
- `render::vps::bundle(&Deployment, &NodeId, &SecretSnapshot, &EngineCatalog) -> VpsBundle { node, config_generation, files, host_profile: HostProfileVersion, engines: EngineSet, site: NodeSite, digest }`. The node must be `Adopted` or `Applied` with a target. `files` holds all five `ManagedFile`s (`xray.json`, `hy2.json`, `wgexit.conf`, `nftables.conf`, `watch.json`), none optional, each a `RenderedFile`: exact-capacity zeroizing bytes plus their SHA-256, which is that engine's config digest. `EngineCatalog` holds the amd64 and arm64 artifacts, and the node's recorded architecture picks one. `VpsBundle::header(&hello)` builds the `Apply` header from the recorded site plus the unrecorded facts of the `Hello` just before it (§11.2).
- `render::vps::cloud_init(&Deployment, &NodeId, &CloudInitKeys) -> UserData` (§8.9).
- `render::mac::exit(&Deployment, &ResolvedInterfaces, &SecretSnapshot) -> ExitConfig`
- `render::mac::prober(&Deployment, &ResolvedInterfaces, &SecretSnapshot) -> ProberConfig`

**The bundle digest** is the SHA-256 of a documented, length-prefixed encoding (`docs/engines.md`, "Digests") of the host-profile version, the architecture, the uplink interface, VPS4, the ephemeral range, the four engine digests and the five files in `ManagedFile::ALL` order. It includes the engines and the host-profile version, so an `Apply` after an engine or host-profile upgrade is never answered `Unchanged`. It excludes the generation, so a generation bump with no VPS-visible change is `Unchanged`.

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
- **Node IPs.** Only the probe identities may reach node IPs, and only the reflector port. This blocks a user from chaining a node through itself (a sing-box `detour`, or Clash `dialer-proxy`, which CFM maps to a detour), which would multiply SIM usage. It also blocks users from reaching VPS4:22 from the EE IP. In lab builds the node IP is private, and rule 4 still admits the probe because it precedes the SPECIAL_V4 deny.
- **`domainStrategy: AsIs`.** The final inbound rule matches every user flow, so `IPIfNonMatch` would never trigger. IP rules therefore apply to IP-literal destinations. Domain destinations are protected by the DoH `unexpectedIPs` filter and, authoritatively, by the Mac's check on final IPs.
- **`ForceIPv4`, as `streamSettings.sockopt.domainStrategy`.** It errors on DNS failure; `UseIPv4` would fall back to the system resolver (`transport/internet/dialer.go:251-262`; freedom takes its strategy from the sockopt, `proxy/freedom/freedom.go:55-58,293-302`). The freedom `settings.targetStrategy` form logs a WARNING at load in v26.9.30 ("The `freedom.domainStrategy` setting is deprecated…", `infra/conf/xray.go:362-368`), because it fills the same deprecated field (`infra/conf/freedom.go:62-66`), and an outbound-level `targetStrategy` warns too (`:363-364`). Either would break the zero-WARN validation gate, so `exit` has no `settings`.
- **DoH.** It keeps the EE leg from tampering with DNS.
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
PostUp = ip -4 rule add pref 10000 oif %i lookup 77
PostUp = ip -4 route replace default dev %i table 77
PreDown = ip -4 rule del pref 10000 oif %i lookup 77
PreDown = ip -4 route flush table 77

[Peer]
PublicKey = <mac>
AllowedIPs = 0.0.0.0/0          # replies arrive from arbitrary sources; no Endpoint (learned by roaming)
```

`ListenPort` is the node's `PortPlan` WireGuard port. The interface name, table 77 and rule priority 10000 come from agent-proto's `WG_INTERFACE`, `EXIT_ROUTE_TABLE` and `EXIT_RULE_PRIORITY`. The comment on `AllowedIPs` is not rendered.

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

The rendered file puts one statement per line; it is shown compactly here. Every port comes from the node's `PortPlan` (defaults shown), and the table, set, counter and user names from `crates/agent-proto/src/vps.rs`.

```
flush ruleset
define VPS4 = <vps4>
define FLOW_CAP = <from M2 port-ceiling estimate minus headroom>
table inet mooring {
  counter xray_guard { packets 0 bytes 0 }                              # named counters are declared before use
  counter hy2_guard  { packets 0 bytes 0 }
  counter flow_cap   { packets 0 bytes 0 }
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
    ct state new ct count over $FLOW_CAP counter name flow_cap reject
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

**Flow cap.** `$FLOW_CAP` is sized from the CGNAT port-ceiling estimate made in M2, minus headroom. Its purpose is to keep exit flows from exhausting EE's port allocation, which would also break the tunnel's own mappings and the probes. Hits are counted and surface as `ExitFlowCapHit`.

### 8.6 Host profile (versioned, owned by the agent)

`HostProfile{version}` holds the host constants. They are compiled into the agent and converged idempotently in every transaction (§11.2). `Hello` reports `host_profile_version`, and `node apply` refuses a node whose version is older than the bundle requires until the converging transaction commits.

`HostProfile::CURRENT` (version 1) is data plus the exact file text, defined once in `crates/agent-proto/src/profile.rs` for the agent and the renderer. Its files are `/etc/sysctl.d/60-mooring.conf`, `/etc/modules-load.d/mooring.conf`, `/etc/ssh/sshd_config.d/10-mooring.conf`, `/etc/systemd/journald.conf.d/60-mooring.conf`, `/etc/tmpfiles.d/mooring.conf` and `/etc/apt/apt.conf.d/52mooring-unattended-upgrades`. The systemd units and chrony are not part of the profile data. The unattended-upgrades text and the effective `sshd -T` spellings that `Hello` compares are *(inference until L2/L5)*.

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
  - `MaxAuthTries 3`, `AllowUsers root`
- **`authorized_keys`**: one line per role, each with `restrict,command="… serve-ssh --role <bootstrap|ops>"`. The agent refuses requests its role does not permit (`RoleNotPermitted`).
- **journald**: `Storage=persistent`, `SystemMaxUse=200M`, `MaxRetentionSec=14day`.
- **unattended-upgrades**: security origin only (`origin=Debian,codename=${distro_codename}-security,label=Debian-Security`), with automatic reboot at 20:00 in the host's time zone, assumed UTC.
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

**These rules are the Level 2 boundary.** They check the **final destination IP** of every flow, so DNS rebinding cannot race them. They protect the M7 admin page, the home LAN, EE's CGNAT range and the Mac's loopback; `LanSubnet` (§7) guarantees that every configured LAN lies inside a rejected `SPECIAL_V4` class. Node IPs are reachable only on the reflector port, matching Xray's rule.

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

Revision 3 showed `type: vless` unquoted, against its own rule that every string scalar is JSON-encoded; the emitter quotes it, and CFM accepts both. CFM maps Clash `fingerprint` to a DER `certificate_sha256` pin (0.4 `subscription_import/clash/tls.rs:144-146`; 0.5 `:259-261`). The comment at `clash.rs:17-18` that says otherwise is stale. The pin stays valid because the certificate is never re-issued within a node's lifetime.

**Never emitted:** URIs (they cannot carry a pin), subscriptions, QR codes, or CFM's internal typed JSON.

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

A user export is also refused when the user is not `Active` (`UserNotActive`), holds no credentials (`NothingToExport`), has a capability its line does not accept (`CapabilityUnsupported`), or holds credentials on a node that is not `Applied` at the deployment's current generation (`NodeNotApplied{Stage | Stale}`, §7).

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

### 9.4 Delivery (runbook `delivery.md`)

- `mooringctl user export <uid> --format singbox|clash --out <path>` writes the file with mode 0600, and warns if the path is under iCloud Drive.
- **Allowed channels:**
  - in person (AirDrop or USB);
  - iMessage;
  - an AES-256 encrypted disk image (`hdiutil create -encryption AES-256`; CFM users are on macOS), sent over any channel, with the passphrase given by voice.
- **Forbidden:** plain WeChat, QQ or email.
- Import by file only. CFM's paste field is single-line (CFM `app.js:2071`).
- Exports are rendered on demand and never cached.

---

## 10. Mac runtime

### 10.1 Daemon loop

The daemon runs on a tokio current-thread runtime with a 2 s tick. Its state machine lives in `daemon-core` and is driven through traits, so the Linux L4 harness runs the same code.

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
6. **Latches and status.**
   - Violation latches persist in `run/latch.json`, so they survive daemon restarts.
   - Status is written atomically to `status.json` (a snapshot for diagnosis) and pushed to `status --follow` subscribers.

**Control channel.** The socket is `run/control.sock` (mode 0600, inside the 0700 Application Support directory). It speaks `DaemonRequest = ProbeNow | Retry{scope} | WaitVerdicts{config_generation, timeout} | Status | Subscribe`, defined in `daemon-core::control`.
- The CLI is the only client.
- The Swift UI calls the CLI.
- No signals or pid files are used for control.

### 10.2 Preflight, probes and verdicts

**The probe primitive.** A TCP connect, then read one line `<IPv4>\n` from a node's reflector (§11.4) within 5 s.

| Probe | Path | Purpose |
|---|---|---|
| `direct` | A socket with IP_BOUND_IF on the egress interface → each node's VPS4:27900 | The EE public IP as the internet sees it |
| `uplink` (`Separate` only) | The same, bound to the uplink interface | The home IP, which must differ |
| `in-chain` per node × {reality, hy2} | 127.0.0.1:4710x → `mooring-probe` → VPS → Xray `exit` → `wgexit` → `mooring-exit` → `egress` → VPS4:27900 | Proves the export shape, the live server, the tunnel, the Mac exit binding and the egress IP together |

**Preflight** runs before the engine starts. It requires all of the following:
- the egress interface resolves;
- at least one `direct` probe succeeds;
- the returned IP is inside `carrier_prefixes` (otherwise `OutsideCarrierPrefixes`) and is not any node's IP;
- in `Separate` mode, `uplink` succeeds and returns a different IP.

Any failure keeps the engine stopped, with a typed reason.

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

**Retry flow** (`mooringctl exit retry`): preflight, then `ClearHold{EgressViolation}` to each node, then start the engine, then probes.

**Calibration of the gap before the first verdict** (about 10 s). In that window a user flow can leave only through the IP_BOUND_IF `egress`, whose carrier IP preflight has just checked. VPS-IP leaks are prevented by the owner guard.

**ReachabilitySuspect.** A node is marked `Degraded(ReachabilitySuspect{node})` when all of these hold:
- it had user (not probe) bytes in the last 7 days;
- it has had zero user bytes for 6 hours between 08:00 and 24:00 China time;
- its probes pass.

This is the only signal that a node may be blocked in China. Nothing happens automatically.

**WatchStale.** If a node's watch status is older than 30 s at a `Status` poll, the node is `Degraded(WatchStale)`.

### 10.3 Power and sleep

**Assertions.** `mooring-power` holds `NetworkClientActive`, which keeps the system awake in dark and full wake on AC (`IOPMLib.h:344-380`), and `PreventUserIdleSystemSleep`, but only while the exit is enabled and the Mac is on AC.
- On battery, the status is `Degraded(OnBattery)` and sleep is allowed.
- Mooring never changes `pmset` or any system setting.

**Will sleep:**
1. The helper sends `will_sleep`.
2. The daemon **stops `mooring-exit` first**. This is local; management SSH is dial-bound and does not depend on the engine.
3. The daemon sends `GateSet{Closed, MacDrain}` to every node, with a 4 s total budget.
4. The daemon acknowledges, and the helper calls `IOAllowPowerChange` well inside IOKit's 30 s acknowledgement window.
5. If the budget is exceeded, the daemon records `DrainTimedOut` and sleep proceeds. The VPS detects the outage by liveness within about 30 s.

**Drain semantics on the VPS.** `MacDrain` records the `latest-handshake` value at drain time. It clears only when that value *changes*, meaning a handshake completed after the drain, and rx has grown. Because the engine is stopped before the drain, no handshake can complete in between. Comparing for change avoids the one-second resolution of `wg show dump`.

**Did wake:** re-resolve interfaces → preflight → start → probes. **Target: `Serving` within 10 s of wake.**

**Lid closed.** Clamshell sleep without an external display is unknown on macOS 27; M2 and M7 measure it. The documented options are closed-display mode on AC, or the operator's own `pmset` choice.

**A crashed daemon** closes the helper's stdin, and the assertions are released.

### 10.4 CFM coexistence

Every socket the Mac exit opens is interface-bound: the WireGuard endpoint, `egress`, the probe outbounds, the direct probes and management SSH. CFM sets `includeAllNetworks=false` and `enforceRoutes=false`, so these sockets should bypass its default route *(inference)*.

Two lanes prove this, both with tcpdump showing zero exit or probe packets on CFM's utun:
- **L6-bypass** (this Mac, today): Wi-Fi stands in for the physical interface, with a public destination, CFM's TUN on, in system-proxy mode, and with both off.
- **M2** (the real M7).

The L7 lab cannot prove the bypass, because a VM subnet is a connected route that is more specific than any TUN default. If CFM ever enables `includeAllNetworks`, the carrier check turns into a violation and the exit stops.

### 10.5 Management SSH from the Mac

```
/usr/bin/ssh -F /dev/null -i <ssh/<node>/ops_ed25519> -o IdentitiesOnly=yes
  -o ProxyCommand="<mooringctl> dial-bound --selector uplink %h %p"
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
  - a `Status`/`Usage` poll every 10 minutes.

  Everything else is an explicit CLI action.

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

**Roles.** The forced command passes `--role bootstrap|ops` (`Role::permits`, which names every request kind).
- The bootstrap role may send only `Bootstrap`.
- Everything else, `RevokeBootstrap` included, is `ops`-only.

**Frozen upgrade core.** `Hello`, `HaveBlobs`, `PutBlob`, `ActivateAgent` and `Confirm`, **and their success replies** (`Hello(HelloInfo)`, `Blobs{present}`, `BlobStored{sha256}`, `AwaitingConfirm{generation}`, `Confirmed{generation}`), never change across protocol versions: a newer Mac decoding with `deny_unknown_fields` must parse an older agent's replies. Through `HelloInfo` this also freezes the shapes of `HostFacts`, `Holds`, `Halt`, `SshdDirective` and `AcceptLocal`; a later protocol adds a request rather than changing them. Requests and replies have byte-exact wire goldens in `contract/agent-proto-golden/`, and a cross-version test runs against the previous release's agent binary, which is kept as a fixture (M4). `AgentError` is not frozen: a Mac that meets an error variant it does not know reports a protocol mismatch.

**Requests:**
- **`Hello`** returns `HelloInfo`:
  - `protocol`, `agent_sha`, `host_profile_version`;
  - `host: HostFacts`: the uplink interface, `vps4` (the single IPv4 on the uplink, which the Mac compares with the address it dialled, proving VPS4 is on it), arch, `ip_local_port_range`, Debian major release, kernel, congestion control and qdisc;
  - `wgexit_accept_local`: `NoInterface | Disabled | Enabled`;
  - `sshd_mismatches`: the profile's sshd directives whose effective `sshd -T` value differs (empty when sshd enforces all of them);
  - the halt marker, if any, and the current holds;
  - `client_ip`, the Mac's IPv4 from `SSH_CONNECTION`.
- **`HaveBlobs{blobs}`** returns `Blobs{present}`, the stored and verified subset; an agent defect therefore leads to a re-upload rather than a skipped upload. **`PutBlob{sha256, len}`** returns `BlobStored{sha256}`.
- **`Bootstrap{expected_agent_sha, ops_pubkey}`** (bootstrap role): returns `BootstrapDone{host_pubkey}`.
- **`RevokeBootstrap`** (ops role): returns `BootstrapRevoked`.
- **`Apply(BundleHeader{config_generation, digest, host_facts, host_profile_version, files, engines})`** returns `TxnLaunched{generation}`, or `Unchanged{generation}` (§11.2). `files` is `BundleFiles`, every `ManagedFile` mandatory; its JSON equals a `ManagedFile` → SHA-256 map. Then `TxnStatus{generation}` returns `TxnStatus{generation, state}`, `Confirm{generation}` returns `Confirmed{generation}`, and `Rollback` returns `Reverted{generation}`.
- **`ActivateAgent{sha}`** returns `AwaitingConfirm{generation}` (§11.2).
- **`Status`**, **`Usage{month}`**, **`TargetCheck{host}`** return `StatusV1`, `UsageV1` and `TargetFacts` (§11.7).
- **`GateSet{reason: MacDrain | EgressViolation | Operator}`** only closes the gate and records the hold; no request opens it. It returns `GateClosed{holds}`. **`ClearHold{hold: EgressViolation | Operator}`** returns `HoldCleared{holds}`, whether or not the hold was present.
- **`Shutdown{reason: EgressIsNodeAddress | Operator | Retire}`** returns `Halted(Halt)`, and **`Resume{config_generation}`** returns `Resumed{generation}`. Each response answers exactly one request kind, and the Mac treats any other pairing as a protocol error.

**Paths never appear in requests.** `ManagedFile` is a closed enum: `XrayConfig`, `Hy2Config`, `WgConf`, `Nftables`, `WatchConfig`. The agent maps each variant to a fixed path (`/etc/mooring/current/…`; `wgexit.conf` and `nftables.conf` are reached through `/etc/wireguard/wgexit.conf` and `/etc/nftables.conf`).

**One definition of the VPS names.** `crates/agent-proto/src/vps.rs` defines `WG_INTERFACE` (`wgexit`), `NFT_TABLE` (`mooring`), `NFT_GATE_SET` (`exit_closed`), `NftCounter` (`xray_guard`, `hy2_guard`, `flow_cap`), `EngineUser` (`mooring-xray`, `mooring-hy2`), `EXIT_ROUTE_TABLE` (77) and `EXIT_RULE_PRIORITY` (10000). The renderer writes them and the agent acts on them, so neither side can rename one alone.

**Blobs** are content-addressed in `/var/lib/mooring/blobs/<sha256>`, and each hash is verified on receipt (Level 1).

**Concurrency.** A second transaction while one runs gets `Busy{generation}` (flock on `/run/mooring/txn.lock`).

### 11.2 Transactions with commit-confirm

`Apply` returns `TxnLaunched{generation}` as soon as the work is launched. The work runs as `systemd-run --unit=mooring-txn-<gen> --collect agent txn <gen>`, so a dropped 5G link or SSH session cannot leave a half-applied state. `TxnStatus{generation}` reports `TxnState`: `Running{stage}` (`Preconditions`, `Stage`, `Validate`, `Swap`, `Apply`, `HealthGate`), `AwaitingConfirm`, `Committed`, `Reverted`, or `Failed{error: AgentError}`. A launched transaction that fails reports its `AgentError` inside `Failed`: a precondition or validation error (nothing was switched), `RolledBack`, `RollbackFailed` or `RevertedUnconfirmed`. There is therefore one error vocabulary, at the cost of allowing pairs the agent never produces (for example `Failed{RoleNotPermitted}`).

The header's host facts are the node's recorded site (uplink, VPS4, arch, port range) plus the unrecorded facts of the `Hello` just before the `Apply` (`VpsBundle::header`). The bundle carries no port plan, so the agent checks the plan's premise, the port range, instead.

1. **Preconditions:**
   - the node is not halted → otherwise `NodeHalted`;
   - the live host facts equal `BundleHeader.host_facts` → otherwise `HostFactsChanged{field}`, naming the first differing fact;
   - the live `ip_local_port_range` equals the range the port plan was checked against → otherwise `PortPlanConflict{recorded, live}`;
   - every blob is present and its hash matches.
2. **Stage** into `/etc/mooring/gen-<N>/` and `/opt/mooring/engines/store/<sha>/`, including the files of the host profile version.
3. **Validate.** Any failure → `StageValidation{tool, stderr_tail}` and nothing is switched.
   - `xray run -test -c` with `XRAY_LOCATION_ASSET` set to the **staged** geodata, run on a copy forced to `loglevel: warning`;
   - `mooring-hy2 check -c` on a copy forced to `level: warn`;
   - `nft -c -f`;
   - `wg-quick strip`;
   - `sshd -t -f <staged config>`;
   - `systemd-analyze verify <staged units>`;
   - a check that every staged sysctl key exists under `/proc/sys`.

   **Zero WARN or ERROR lines** are allowed.
4. **Swap** the symlinks atomically with `rename`: `current` → `gen-<N>`, plus the engine and geodata links. Install the host-profile files. Keep two previous generations.
5. **Apply only what changed:**
   - `nft -f`, which leaves the gate closed until the watch reopens it;
   - `wg syncconf`, or a restart if Address or MTU changed;
   - `daemon-reload`;
   - `sysctl --system`;
   - an sshd reload;
   - restart `mooring-xray` and `mooring-hy2`.
6. **Local health gate,** with a 20 s budget:
   - units are active;
   - `ss -Hltnu` shows the expected listeners;
   - `xray api statssys` responds;
   - `nft -j list set inet mooring exit_closed` succeeds;
   - the owner-guard rules are present;
   - `net.ipv4.conf.wgexit.accept_local = 1`.
7. **Arm the confirm timer** (`systemd-run --on-active=120 agent txn-revert <gen>`) and report the state `AwaitingConfirm`. The Mac opens a **new** SSH session and sends `Confirm{generation}`, answered `Confirmed{generation}`. That session proves reachability through the new nftables rules and sshd configuration. If the timer fires first, the agent reverts exactly as for a rollback → `RevertedUnconfirmed{generation}`.
8. **If steps 5–6 fail:** swap back, restart and re-check → `RolledBack{generation, cause}`. If that also fails, stop both engines and close the gate → `RollbackFailed{generation, cause}`. The cause is `Swap{errno} | Apply{step, stderr_tail} | HealthGate{failed}`; the failed stage follows from it, so an inconsistent stage/cause pair cannot be expressed.
9. **An `Apply` whose digest equals the current generation's** returns `Unchanged{generation}` with the node's current generation. It restarts nothing, and **never changes holds or the halted state**. The bundle digest excludes the generation (§8.1), so a generation bump with no VPS-visible change is answered this way, and the Mac records it as an `Applied` bookkeeping entry at the new generation (§7).

**`Rollback`** reverts the change awaiting confirmation at once, exactly as the confirm timer would, and returns `Reverted{generation}`; with nothing awaiting confirmation it fails with `NotAwaitingConfirm`.

**`ActivateAgent{sha}`:**
1. Run `<new> self-test`: parse its embedded host profile, open its state, print `PROTOCOL`. A failure → `AgentSelfTestFailed`.
2. Swap the forced-command symlink.
3. Arm the same 120 s revert timer and reply `AwaitingConfirm{generation}`. Activation changes no configuration, so `generation` is the node's current one: `Generation::ZERO` before the first `Apply`. `ConfigGeneration` starts at 1 (§7), so every real `Apply` generation is newer.
4. The Mac's `Confirm{generation}` must be served by the new agent.

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

**Halt.** `Shutdown{reason}` works in this order:
1. It writes `/var/lib/mooring/halted.json` atomically, without taking `txn.lock`.
2. It closes the gate.
3. It stops both engines.

The engine units' `ExecCondition=agent halted-check` then prevents any restart: by systemd, by a reboot, or by a running transaction's rollback. Transactions check the marker before restarting anything. `Apply` returns `NodeHalted`, and only an explicit `Resume{config_generation}` clears the marker. The runbook requires investigating the cause first.

**Watch loop (every 5 s):**
1. Read the latest handshake, rx and tx from `wg show wgexit dump`.
2. **The gate opens** only if all of these hold:
   - the handshake is at most 180 s old;
   - rx grew within 3 × keepalive;
   - there are no holds;
   - the node is not halted.

   Otherwise the gate stays closed. Set membership is re-read with `nft -j` every 60 s.
3. Any failure to read WireGuard state closes the gate and records `WgReadFailed`. An `nft` failure is fatal; the unit restarts, without limit, and `ExecStopPost` closes the gate.
4. Every 60 s, accounting runs (§11.5). Every hour, the target check runs: `xray tls ping`, the h2 check, and re-resolving the target name. A failure, or an IP change, records `TargetDegraded`.
5. Write `/var/lib/mooring/status.json` atomically, with a timestamp the Mac uses for `WatchStale`.

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
- The Mac merges usage from all nodes next to the SIM meter.
- **Quotas** are enforced by revocation.

### 11.6 Host-profile convergence

Host-profile changes travel in ordinary transactions: they are staged, validated (`sshd -t`, `systemd-analyze verify`, sysctl keys), applied and confirmed. Changes to sshd or nftables are therefore protected by commit-confirm. L5 upgrades a node adopted at profile N to N+1.

### 11.7 REALITY target selection

**Where policy runs.** The agent's `TargetCheck{host}` returns raw `TargetFacts` (`crates/agent-proto/src/target.rs`). `render::target_facts` converts the report into the model's `TargetFacts` (`crates/model/src/target.rs`), refusing a report about any host other than the one requested (`TargetFactsForOtherHost`). Every wire outcome has a model counterpart, so nothing is invented to fill a value the agent did not measure. `mooring-model::target::qualify(facts, attestation)`, on the Mac, then evaluates the rules and reports every failed rule, not just the first. Failures are listed in a fixed order: the TLS rules, the HTTP rules, the deny list, the resolved address, then the attestation (`crates/model/src/target.rs`, `qualify`).

**Discovery.** The operator runs the pinned RealiTLScanner from the Mac, never from the VPS. The scan is limited to the VPS's /24 and its neighbours, at a low rate.

**`TargetCheck` on the VPS collects:**
- the resolved IPv4s (possibly none);
- the TLS outcome against port 443, `TlsProbe`: `ConnectFailed`, `HandshakeFailed`, or `Completed(TlsSession{version, group, chain_bytes, chain_certs, leaf_names, handshake_p95_micros, first_flight_bytes})`. `xray tls ping <host>` supplies the version, the negotiated group (recorded as its IANA code point; none for TLS 1.2 RSA key transport), the chain's length and certificate count, and the leaf's DNS names (Xray v26.9.30 `main/commands/all/tls/ping.go:125-170`). It measures neither latency nor the first flight, and it exits on a failed dial, so the p95 handshake latency over 20 handshakes (`TARGET_HANDSHAKE_SAMPLES`) and the first-flight size are measured separately by the agent's handshake sampler (`TargetTool::HandshakeSampler`, M4);
- `curl --http2 -sS -o /dev/null -w '%{http_code} %{http_version} %{redirect_url}' https://<host>/`, as `HttpProbe`: `Failed` (status `000`) or `Responded{status, version, redirect}`.

A collector that cannot run fails the request with `TargetFactsUnavailable{tool: Resolver | XrayTlsPing | Curl | HandshakeSampler, stderr_tail}`.

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
| User VLESS UUID, Hysteria2 password, loopback UUID (per user, per node) | 2 | Unauthorised use of the exit | Data-protection Keychain; VPS configs (0640 root:service); that user's export |
| REALITY private key, salamander password, Hysteria2 key (per node) | 2 | Server impersonation; probe classification | Keychain; VPS configs |
| WireGuard keys (one VPS and one Mac key per node) | 2 | Tunnel impersonation | Keychain; `wgexit.conf` 0600; the Mac key reaches the engine only on stdin |
| SSH operations key | 2 | VPS takeover | `~/Library/Application Support/Mooring/ssh/<node>/ops_ed25519` (0600, excluded from Time Machine); VPS `authorized_keys` with `restrict,command=` |
| SSH bootstrap key and injected host key | 2, short-lived | Spoofing of the first contact | User-data file until adoption. The host key is replaced on the VPS at Bootstrap. |
| Engine and blob sha256 | 1 | Accidental corruption or the wrong artifact | `engines.lock.toml`, `MANIFEST.json` |
| Mac exit deny list | 2 (a security boundary) | A VPS or user reaching the M7 admin page, LAN, CGNAT range or loopback | Mac engine rules (authoritative), Xray rules and the owner guard (defence in depth) |
| VPS owner guard | 2 | User traffic leaving from the VPS IP; reaching VPS-local services | nftables |
| Accounting and status | 0 | — | Plain files |

**Keychain.**
- `kSecUseDataProtectionKeychain`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrSynchronizable=false`, access group `<TEAM>.com.bill.mooring.secrets`. These are the same attributes as CFM's `CredentialVaultStorage.swift:133-150`.
- Only the bundled `mooringctl` holds the entitlement. Development lanes use the in-memory `SecretStore`.
- Optional M5 spike: a non-exportable Secure Enclave SSH key via `sc_auth` and `ssh-keychain.dylib`. Adopt it only if a LaunchAgent can use it unattended.

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
- The final choice goes to whichever shows less peak-hour loss (19:00–23:00 China time) to the users' carriers in M8. **The user rents and pays for these;** Mooring holds no provider token.

### 13.2 Provisioning (about 15 minutes hands-on)

1. **`node new lon1 --role primary`.** Generates the node's secrets, the one-time host key and the bootstrap key, and writes `cloud-init-lon1.yaml` (0600). The node is `Planned`, with no address; its `SshPin` is the one-time host key, and the user-data render refuses any other host key (`HostKeyNotPinned`, §8.9). Two active nodes already present make this fail with `TooManyNodes` (§13.4).
2. **The operator creates the VPS** in the provider's console.
3. **`node adopt lon1 --address <ipv4>`.** Over SSH, using the pinned one-time host key and the bootstrap key (unrestricted root for this window only):
   1. upload the agent and run `Bootstrap{expected_agent_sha, ops_pubkey}`. This installs packages, users, units, the host profile, and `authorized_keys` with role-restricted lines. It **generates a new ed25519 host key** and removes the other host-key types, then returns `BootstrapDone{host_pubkey}`;
   2. re-pin the host key, then connect with the operations key: `ssh … true` must return the agent's typed `UnknownRequest`, which proves the forced command is active (otherwise `ForcedCommandNotActive`);
   3. reboot. `Hello` asserts Debian 13, a 6.12-series kernel, bbr, fq, the arch, VPS4 on the uplink interface, and the port range. The node's site comes from it (`render::adoption_site`): the address, which must be the single IPv4 `Hello` reports on the uplink (`AddressNotOnUplink`), the uplink interface, the arch and the port range. Debian, kernel, bbr and fq are asserted, not recorded; each `Apply` header carries the values of the `Hello` before it;
   4. `RevokeBootstrap`. The node is then recorded `Adopted` with its site, which stops referencing the bootstrap key, so the store deletes the Mac-side bootstrap key after that state commit (§7); the user-data file is deleted too.
4. **`node target check lon1 <host>`,** then `node target set` with the attestation. Only a target that passes `qualify` (§11.7) can be stored.
5. **`node apply lon1`.** Missing blobs are uploaded, the agent is activated (and confirmed) if newer, and the transaction runs and is confirmed; the Mac records the confirmed generation and digest (`Bookkeeping::Applied`, §7). The daemon adds `wg-lon1`, which restarts `mooring-exit` for 1–2 s. The probes must report `Verified`.
6. **`user export …`.** Every node in the file must have confirmed the current generation (§9.2).

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
1. Retire the blocked node (lon1) first. It carries no China traffic anyway, and the standby serves the users meanwhile. A `Retiring` node still counts as active, so the next step needs lon1 to have reached `RetiredPendingProviderDeletion` (retirement step 3); deleting its VM can wait.
2. `node new lon2`, then adopt, set the target, apply.
3. Apply the standby as well: its Xray rules list every node address, so its bundle changed, and exports refuse a node that has not confirmed the current generation (`NodeNotApplied{Stale}`).
4. Re-export every user with the new node plus the standby, and deliver the files out of band.

**With a single node and no standby,** the order is reversed: `node new lon2`, adopt, set the target, apply lon2 and re-apply lon1, re-export and deliver every user's file, and only then retire lon1.

**With both nodes blocked,** users have no working node anyway: retire one, provision its replacement (new, adopt, target, apply, export), then retire the other and provision its replacement the same way.

Every step that changes the configuration bumps `config_generation`, so `node apply` runs on every node a user holds credentials on before that user's file is exported (§7). **Target: 20 minutes or less hands-on (M9).**

### 13.5 Revocation

1. The user moves to `RevokePending`, a configuration change: from then on the user is served on no node and exported nowhere. The nodes still to revoke are not stored separately; they are exactly the nodes in the user's `per_node` (`User::revocation_remaining`).
2. `Apply` runs on each of those nodes.
3. After a node commits, a `RevocationCommitted{user, node}` record removes that node from `per_node`. Only after that state is committed are the user's keychain items for that node deleted (§7).
4. When `per_node` is empty, the same record makes the user `Revoked`. Retiring a node drops the user's credentials there too (`RetirementShutDown`, §13.4).

A failing node stays in `per_node`, and the operator retries it explicitly.

**Runbook for a seized device:** revoke the user, then rotate every node that user held.

### 13.6 Live changes

User changes re-render the VPS configs and restart the engines. Existing connections drop for a few seconds; restarts are scheduled for 03:00–06:00 China time. `mooring-exit` restarts only if its own rendered digest changed.

### 13.7 Recovery runbooks

- **`console-recovery.md`.** The provider's rescue boot is used when SSH is lost despite commit-confirm. The steps: mount the disk, restore `authorized_keys` and `/etc/nftables.conf` from `gen-<N-1>`, and reboot.
- **`mac-loss.md`.** Keychain items are `ThisDeviceOnly`, and the operations key is excluded from backups. Losing or replacing the Mac therefore means rotating every node and reissuing every user file. Theft needs the same response in any case. This is the accepted recovery model.

---

## 14. Typed error taxonomy

Errors are per-crate `thiserror` enums. Each public error enum has a companion `<Name>Kind` enum with an exhaustive `ALL` list, generated from the same tokens as the kinds (`model`'s single `kinds!` macro, used by every Mac-side crate, and agent-proto's `closed_enum!`), so `ALL` cannot fall out of step. `xtask kinds-coverage` finds every public enum whose name ends in `Kind` and fails if any variant is not named as `<Enum>::<Variant>` by at least one test. xtask's own errors are `pub(crate)` in a binary and have no `Kind`.

The CLI maps errors to `{"error":{"kind","detail"}}` with a stable exit code, fixed by `contract/cli-fixtures`. There is no `Other(String)`, no `unwrap` or `expect` outside tests, and no path that defaults to success.

| Domain | Variants | Handled by | Retry | User sees |
|---|---|---|---|---|
| model | One variant per newtype rule (`InvalidAddress{addr,class}`, `InvalidShortId`, `InvalidDnsName`, `InvalidHopInterval`, `InvalidHy2Listener`, `InvalidKeepalive`, `InvalidInterfaceName`, …) and per cross-entity invariant (`PortPlanConflict{conflict}`, `UnknownNode`, `UnknownUser`, `DuplicateId`, `TooManyNodes`, `GenerationAhead`, `GenerationRegressed`, `TargetNotSet`, `NodeNotDeployable`, `NotRevoking`, `RevokePendingWithoutCredentials`, …); interface resolution: `InterfaceNotSelected`, `UplinkModeMismatch`, `UplinkEqualsEgress`, `InterfacesForOtherSite`. Target qualification fails separately with `TargetRejected{reasons}`, every failed rule listed (§11.7) | CLI | no | the exact field |
| keys | `Entropy`, `MaterialRejected` (a model constructor refused an all-zero draw: a broken source), `CertValidity{now}`, `CertBuild{step}`, `InvalidSshComment` | CLI | no | fatal |
| store | `StoreError`: `Io{op,path}`, `Lock{path}`, `NotInitialized`, `AlreadyInitialized`, `StateCorrupt{path}`, `DowngradeRefused{found,newest}`, `MigrationFailed{from,to}`, `Encode`, `GenerationConflict{expected,found}`, `RevisionConflict{expected,found}`, `CounterOverflow`, `GenerationEdited`, `AppliedEdited{node}`, `InvalidChange`, `SecretRefsChanged`, `SecretPlanMismatch`, `DuplicateSecret`, `SecretWrite{secret_ref}`, `SecretCleanup{committed,failures}`. `SecretStoreError`: `SecretMissing{secret_ref}`, `Keychain{op,status}`. `ChangeError<E>`: `Store` or the caller's `Refused(E)` | CLI, daemon | `GenerationConflict`/`RevisionConflict`: the user re-runs | yes |
| export | `UserNotActive`, `NothingToExport`, `NodeNotApplied{node, Stage \| Stale}`, `CapabilityUnsupported{line,cap}`, `CertUnparseable`, `CertKeyUnsupported`, `CertNotCurrent`, `CertSanMismatch`, `CertEkuMissing`, `InvalidTag`, `Model`, `Secret`, `Encode` | CLI | no | yes |
| render | `NoAppliedNodes`, `AddressNotOnUplink`, `TargetFactsForOtherHost`, `NodeNotPlanned`, `HostKeyNotPinned`, `InvalidHostKey{rule}`, `WireValue{field}` (a drift between the model and wire rules, unreachable by construction), `Model`, `Secret`, `Export`, `Encode` | CLI, daemon | no | yes |
| ssh | `Spawn`, `HostKeyMismatch{node}`, `AuthFailed`, `Transport{stderr_tail}`, `Timeout`, `ProtocolMismatch`, `Decode`, `ResponseTooLarge`, `ForcedCommandNotActive` | CLI, daemon | `Transport`/`Timeout`: user or next poll; `HostKeyMismatch`: **never** | yes; `HostKeyMismatch` as a security alert |
| agent (remote) | `BlobHash{expected,actual}`, `BlobMissing{sha256}`, `BlobTruncated{expected,received}`, `TrailingInput`, `StageValidation{tool,stderr_tail}`, `Apt{stderr_tail}`, `Systemd{unit,op}`, `HealthGate{failed}`, `RolledBack{generation,cause}`, `RollbackFailed{generation,cause}`, `RevertedUnconfirmed{generation}`, `AgentSelfTestFailed{stderr_tail}`, `AgentShaMismatch{expected,actual}`, `Busy{generation}`, `GenerationNotNewer{current}`, `GenerationMismatch{current}`, `NotAwaitingConfirm`, `UnknownTransaction{generation}`, `NodeHalted`, `NotHalted`, `HostFactsChanged{field}`, `HostFactUnavailable{field}`, `PortPlanConflict{recorded,live}`, `TargetFactsUnavailable{tool,stderr_tail}`, `NoUsageRecorded{month}`, `GateCloseFailed{stderr_tail}`, `Io{op,errno}`, `RoleNotPermitted{role,request}`, `UnknownRequest`, `RequestTooLarge`. Not frozen (§11.1) | CLI shows; the VPS stays at last-good or stopped | idempotent re-apply | yes |
| daemon: preflight | `EgressInterfaceAbsent{selector}`, `EgressAmbiguous{matches}`, `EgressNoIpv4{bsd}`, `EgressSubnetMismatch`, `UplinkAbsent`, `UplinkEqualsEgress`, `DirectProbeFailed{node,stage}`, `OutsideCarrierPrefixes{ip}`, `SecretsUnavailable`, `AgentNotEnabled{status}` | daemon | on interface events or the next tick | menu and notification |
| daemon: engine | `EngineSpawn{io}`, `EngineConfigRejected{stderr_tail}`, `EngineStartFailed{stderr_tail}`, `EngineCrashLoop{n,window}`, `StaleEngine{pid}` | daemon | backoff only for post-health crashes | yes |
| daemon: verify | Violations (engine stopped and latched): `EgressMismatch{d1,d2,observed}`, `EgressIsNodeAddress{node}` (+ `Shutdown`), `EgressEqualsUplink`, `OutsideCarrierPrefixes{ip}`. Degraded: `NodeProbeFailed{node,proto,stage}`, `ReachabilitySuspect{node}`, `WatchStale{node}` | daemon | violations: none until Retry, a config change or an interface change | red, with notification |
| daemon: budget and power | `SimWarn{used}`, `SimCapReached{used,limit}` (engine stopped until the cycle resets), `OnBattery`, `PowerHelperExited`, `DrainTimedOut`, `DrainFailed{ssh}` | daemon | per rule | yes |
| watch (VPS) | `WgReadFailed` (gate closes), `NftFailed` (unit restarts; gate closed by `ExecStopPost`), `StatsQueryFailed`, `TargetDegraded`, `ExitFlowCapHit{count}`, `StateWrite{io}` | watch → status | next tick | `node status`, menu |

---

## 15. Observability and logging

**Status stream.** `StatusV1` is emitted by `mooringctl status --follow --json` and snapshotted in `status.json`. It contains:
- `exit_state` with its reason and `since`;
- `egress{bsd, lladdr, ipv4}` and the uplink;
- per engine: `{pid, restarts, last_exit}`;
- per node: probes (`at`, `verdict`, `latency_ms`), gate state, holds, halted, handshake age, applied generation, watch age;
- `egress_ip` and `verified_at`;
- the SIM figures `{cycle_start, bytes, warn, hard_stop, accuracy: Exact|LowerBound}`;
- per-user bytes;
- power state.

Swift decodes the stream through a Codable mirror, tested against Rust-generated fixtures in `contract/status-fixtures/`.

**Logs:**
- **Xray:** `access:"none"`, `loglevel:"none"`, `dnsLog:false`, `maskAddress:"full"` at run time. `none` turns off both the error and the access log (Xray v26.9.30 `infra/conf/log.go:57-59`). At `warning`, Xray would log failed DoH lookups and resolutions at ERROR with the queried domain (§8.2), and `maskAddress` masks IPs only. Removing `disableFallback` also removes the per-lookup domain warning, and the L4 canary includes domain names. Start-up failures still reach stdout (`main/run.go:84,95`). The L2 and stage-validation copies run forced to `warning` (§11.2 step 3), so configuration warnings still fail validation.
- **All three sing-box instances:** `fatal`. Validation uses warn-level copies (§11.2, L2).
- **journald:** persistent, 200 MB, 14 days.
- **Daemon:** JSON lines in `~/Library/Logs/Mooring/daemon.log`, rotated at 2 × 5 MiB. Secret types render as `<redacted>`; destinations are never logged; engine stderr is kept in a 200-line in-memory ring for crash diagnosis and scrubbed as described in §12.

**Not included:** metrics servers, dashboards, remote log shipping, and automated reachability probing from China.

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
| **L0 static** | hosted CI (ubuntu, macos) and local | `cargo xtask ci`: fmt, clippy, deny, graph-check, kinds-coverage, deny-skips (the exact-skip check), acceptance (§9.3), nextest, doc tests; plus govulncheck, `xcodebuild`, `xcrun swift test` |
| **L1 unit/property** | same | newtype bounds (proptest); RFC 7748 X25519 vectors; key encodings; OpenSSH encoder against `/usr/bin/ssh-keygen -y -f` and `-l`, and certificate properties, DER and SPKI against `/usr/bin/openssl` at test time (these tool checks compile only on macOS); render invariants and goldens; export goldens; YAML round-trip (saphyr); acceptance file = shape enumeration × client line, and manifest client lines = enumerated client lines (xtask unit tests; `cargo xtask acceptance` in L0); agent-proto framing, limits and frozen-core goldens; watch gate, holds and drain logic (including a handshake inside the drain window and in the same second); daemon-core state machine with a fake clock, engines, probes and power (wake then sleep within 3 s, Dark Wake transitions, EE IP changing between probes, Retry after a violation, latch persistence across restart); SIM arithmetic across counter resets; store CAS, atomicity and migrations; error → UI mapping |
| **L2 engine-check** | CI, plus a Debian 13 VM locally | `xray run -test` (warn-level copies) and `xray convert pb -debug -type` semantic assertions; `mooring-hy2 check` (warn-level copies); `nft -c -f`; `wg-quick strip`; `cloud-init schema` inside Debian 13; `xray x25519 -i <priv>` equals the Rust public key; `sing-box check` of every sing-box JSON export under upstream and CFM-patched 1.14.1 and 1.14.2 (the `support_x25519mlkem768` shapes only under CFM-patched 1.14.2, §9.3); provenance via `go version -m`; **negative controls that must trip each gate:** a REALITY serverName containing "apple" (Xray warns, v26.9.30 `infra/conf/transport_security.go:163-169`), a deprecated sing-box field, a stale golden, a shape missing from the acceptance file, an undeclared crate edge |
| **L4 netns e2e** | hosted ubuntu amd64; Lima Debian 13 arm64 on this Mac | Namespaces: `cn` (CFM-patched clients fed the exports verbatim, plus Clash JSON twins); `vps` (Xray, Hysteria2, kernel `wgexit`, nft, watch, reflector); `vps2` (a second node, for isolation); `mac` (Linux build of `mooring-exit`/`mooring-probe` driven by the real `daemon-core`; `ee0` egress, plus a `home0` decoy holding the default route); `inet` (routing, a TLS 1.3 + h2 target, echo servers, a DoH stand-in whose test CA reaches Xray only through `SSL_CERT_FILE`); `prober` (active probing); `tc netem` for impairments. Cases are listed below. |
| **L4-ablation** | same | Permanent matrix; each entry names the test that must fail: drop the gate rule; unscope the hop redirect; delete table 77; remove `accept_local`; unbind `exit`; remove the owner guard; remove each deny class in each layer; raise the engine log level to info (the canary must fire) |
| **L5 vm-agent (release)** | hosted CI: QEMU/KVM amd64 (`test -c /dev/kvm` or fail), Debian 13 genericcloud with a NoCloud seed made from the **rendered** user-data, and the exact shipped linux-amd64 artifacts | adopt (including host-key regeneration and proof of the forced command), apply, unchanged re-apply, confirm, rollback, reboot (gate closed until live); failure injection listed below |
| **L5-lab** | this Mac: Lima `vz` arm64 VM with `vzNAT` and the lab agent build (the lab host profile keeps Lima's own SSH user; the release profile is tested only in CI L5) | the same flows on arm64; a host for L6/L7 |
| **L6 host-mac (lab)** | this Mac | Topology: the Mac's egress and uplink are both `bridge100`, the host side of the vzNAT network, which does not hold the default route. The node address and lab "internet" /32s are allowed only through the typed `cfg(feature="lab")` `LabAllowance{vps4, internet: Vec<Ipv4>}`, applied identically in the Xray render, the Mac render, preflight (`carrier_prefixes` = the lab /24) and export. The darwin `mooring-exit` re-asserts every other SPECIAL_V4 class. Checks: selector resolution; IP_BOUND_IF probes; `Verified` verdicts; `kill -9` of the daemon → launchd restart with no orphaned engine and the latch intact; stopping the VM (which removes `bridge100`) → `Down(EgressInterfaceAbsent)` within 4 s; data-protection Keychain read after reboot and login; sandbox spike; **T-deny-mac on darwin** (VM root originates over `wgexit`; a canary listener on the Mac's 127.0.0.1 records zero accepts); handling of the Local Network privacy prompt *(inference that it appears)* |
| **L6-bypass** | this Mac, **user present** (CFM prompts, `sudo tcpdump`) | Wi-Fi `en0` stands in for the physical interface: `curl --interface en0` and bound probes to a public host with CFM's TUN on, in system-proxy mode, and with both off; utun shows zero packets |
| **L7 lab-cfm** | this Mac, **driven by the user**. CFM 0.4, then 0.5, sequentially; the user is warned before every step that opens windows or raises prompts | Import every lab-feature shape by file. Run CFM → VM → `wgexit` → the real daemon → `bridge100`. Record `cfm-acceptance.toml`, including build numbers and the importer digest. This lane does **not** prove the TUN bypass (§10.4). |
| **L8 field** | the real M7, EE and a London VPS | measurements, a 72 h soak, peak-hour acceptance by a trusted user in China, and an offload drill (enable M7 Wi-Fi offload → `OutsideCarrierPrefixes` and the engine stops within 30 s) |

L6 and L7 run the signed lab bundle (`xtask release --lab`, signed by the user), never unsigned dev builds, so the entitlement, Keychain and sandbox paths are the shipped ones.

**L4 cases:**

| Test | Assertion |
|---|---|
| T-reality / T-hy2 (TCP and UDP) | Both client versions get through. The echo server sees the `ee0` address, never `home0` or a VPS address. Hysteria2 hopping is proven by at least 2 distinct server destination ports in conntrack over a run longer than 30 s. |
| T-large | 200 MB in each direction, sha256 equal, with the `ee0` path MTU set to 1340 |
| T-deny | Refused through the clients: 192.168.1.1, 127.0.0.1, 10.77.k.2, 10.77.k.1:22, 10.77.k.1:10443, a domain resolving to 10.77.k.1, 100.64.0.1, 224.0.0.1, an IPv6 literal, tcp/25, a domain resolving to 10.x, every node IP (including a two-layer detour chain through the same node) |
| T-deny-mac | From the `vps` namespace as root, originating directly over `wgexit` and bypassing Xray: each SPECIAL_V4 class; 10.77.k.2:<port> with a canary listener on 127.0.0.1 in `mac` (zero accepts); 224.0.0.1; tcp/25; more than `udp_nat_max` UDP flows (bound enforced) |
| T-deny-vps | A test-only render with the Mac deny list removed proves the Xray layer and the owner guard on their own |
| T-no-leak | An exact counter (`meta skuid mooring-xray`, oif eth0, destination = echo servers) stays **0** for the whole suite, including variants with table 77 deleted, `ip link del wgexit` while serving, and Xray started before `wgexit` exists |
| T-fail-closed | Stop `mooring-exit`. Within 3 × keepalive plus one tick, new connections to IP literals fail within the measured bound (about 1.0–1.5 s plus RTT); the cold-cache domain bound is recorded; the leak counter stays 0 |
| T-drain | `GateSet` → flows that send get RST within 1 s. The gate reopens only after a handshake that changes the recorded value. |
| T-reflector | In-chain probes return the `ee0` address. Negative controls: unbound VPS exit → `EgressIsNodeAddress` plus `Shutdown`; Mac egress on `home0` (outside the carrier prefix) → `OutsideCarrierPrefixes`; Mac egress on a second `ee0` pool address (Paired) → `EgressMismatch`; without `accept_local` → `NodeProbeFailed` (mutation check) |
| T-nat | Profiles: (a) SNAT address swap between the direct and in-chain probes → inconclusive, then `Verified` or `CarrierAddressUnstable`, never a violation; (b) conntrack UDP timeout below the keepalive; (c) two-address arbitrary pooling (expected verdict stated for Paired and Unpaired); (d) 200 s of 100% loss, then recovery; (e) a SNAT port remap → traffic resumes within 2 × keepalive |
| T-wg-port | A new WireGuard tuple on 27820 is never redirected to Hysteria2 |
| T-camo / T-reality-fallback / T-hy2-silence | Bytes on port 80 and UDP/443 match the target's, unchanged while the Mac is down. An unauthenticated client or wrong shortId gets the target's real certificate chain. Random UDP, and QUIC without salamander, to 61000-62999 and 27820 get zero bytes back. |
| T-revoke / T-node-isolation / T-retire | Revoked credentials are refused on both protocols; lon1 credentials are refused on `vps2`; a retired node's endpoint is gone from the Mac config |
| T-accounting | Per-user bytes within ±2% |
| T-flow-cap | N+1 flows → fast typed refusal and `ExitFlowCapHit`; other users keep working |
| T-exhaust | 60k distinct source ports to UDP/443 and a SYN flood on 27900 from `prober`; REALITY handshakes keep succeeding and preflight still passes; Xray memory stays below `MemoryMax` |
| T-log-canary | Canary hosts, domains, client IPs, UUIDs and passwords never appear in journald, engine stderr, `status.json`, `daemon.log` or SSH error JSON. Driven paths include a bad UUID, a bad shortId, a bad Hysteria2 password, a denied destination, a DoH failure, an invalid engine config containing canary secrets, and an agent `StageValidation` containing canary secrets. Also confirms Xray's run-time level `none` (chosen in M1 from the pinned source, §8.2) and checks that Xray at `none` and sing-box at `fatal` still surface start-up errors. |
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
| Reflector exposure | Open, with a per-source limit | **Restricting to EE prefixes:** offload would become an ambiguous probe failure. |
| Gate | Single owner (`mooring-watch`), persisted holds, a halted marker honoured by systemd | **Three writers and in-memory holds:** reopen races, and the kill switch would be undone by a reboot. |
| Transactions | Commit-confirm for every Apply and every agent activation | **Health checks run only on the VPS:** they cannot detect that the operator has been locked out. |
| Ports | Fixed ports below the ephemeral range, hop ranges above it, a model invariant | **47820/47900:** inside 32768-60999; bind conflicts. |
| Hop range | 61000-62999, with 63000-64999 reserved for a second listener | **61000-65000:** leaves no room for a gecko listener. |
| Camouflage | Forward TCP/80 and UDP/443 to the target IP, with per-source limits and a short-idle policy | **Unbounded:** UDP sessions can be exhausted. **Omitted:** port behaviour would differ from the target's. |
| DNS on the VPS | Cloudflare DoH through the exit, both addresses queried in parallel, serve-stale | **`disableFallback`:** one server only, plus a domain WARNING per lookup. **Plain UDP:** tamperable. |
| Export | sing-box JSON by default; Clash block YAML; shapes keyed by client line | **URIs:** cannot carry a pin. **Groups, rules, dns:** parsed strictly by CFM. |
| Contract gate | Shape enumeration × importer digest, plus acceptance records, plus a real-CFM lab | **Runtime shape checks:** a path that can never fire. **Copying or overlaying CFM's converter:** duplication. |
| Power | NetworkClientActive plus PreventUserIdleSystemSleep in a helper owned by the daemon | **PreventSystemSleep:** deprecated and unsupported (SDK). **An assertion held by the UI:** lost when the app quits. |
| Sleep drain | Stop the engine, then drain, then compare the handshake value for change | **Drain first:** a rekey in the gap reopens the gate. |
| Logs | Non-emitting levels, a canary gate, exact-substring scrubbing of stderr tails | **Regex redactor:** complex and incomplete. |
| SSH keys | ed25519-dalek 3 plus a small OpenSSH encoder tested against ssh-keygen | **ssh-key 0.6.7:** a duplicate RustCrypto generation. |
| Lab | A typed `LabAllowance` behind cfg, a separate bundle id and state directory, release verifier checks | **Ad-hoc relaxations:** the release deny list would go untested on darwin. |
| Provider API | None in v1 | A token that could create and destroy servers. |
| Shaping | Deferred until data justifies it (M10) | cake/IFB in v1 would add complexity before evidence. |
| Uplink | `SameAsExit` by default; `Separate` explicit | **Automatic switching:** a runtime fallback. |
| Active nodes and rotation | At most 2 active nodes; with a healthy standby, rotation retires the blocked node first (§13.4, D-8) | **A third active node during rotation:** the Mac exit would need a third WireGuard endpoint and a wider probe port span. |
| CFM acceptance check | In `xtask` (`cargo xtask acceptance`, a `ci` step) with the `toml` crate and xtask → `mooring-export`, `mooring-model` edges; the release gate `require_accepted` is `cargo xtask release-acceptance`, run by release verification (D-9). Cost: every xtask command compiles the two product crates first, so `rm -rf target` replaces `cargo xtask clean` while they do not build (§6.1) | **The two hand-written TOML-subset readers M1 first built** (the acceptance reader in `mooring-export`, the `deny.toml` reader in xtask): duplicated parsing, one of them in the public API of a crate the shipped binary links (review finding F16). |

---

## 18. Non-goals (v1)

- Inbound connections to the Mac; Hysteria Realm; China-facing servers on the Mac.
- Subscription URLs, QR codes, URIs, a web panel, a public admin API, provider-API automation.
- IPv6 entry or exit.
- Automatic switching between tunnels, uplinks, exits or egress-check modes.
- Per-user rate limits; live API user changes; multiple Macs or exits.
- A second carrier (for example O2 beside EE). The MR7450 has one nano-SIM slot and no eSIM (manual 202-12721-02, "Install or replace a SIM card"); NETGEAR has said eSIM may come to the M7 Pro but has not confirmed it. Even dual-SIM hotspots run one modem, so only one SIM is active at a time. If M2/M8 data show EE is inadequate at the exit site, first compare carriers by swapping the SIM in the same M7. A second cellular device with a typed, measured switching policy is a later decision, not v1 (each carrier would need its own `carrier_prefixes`, SIM meter and exit-IP change handling).
- In-house protocol implementations, C++, or Xray prerelease features (XHTTP, VLESS encryption, `finalRules`).
- Modifying CFM. Extracting its importer and changing its ML-KEM client handling are separate CFM tasks.
- Running without a logged-in session; changing system power, firewall or network settings.
- Inspecting traffic or logging destinations; automated reachability probing from China.

---

## 19. Risks and unknowns

| Risk or unknown | Impact | Mitigation, or where it is resolved |
|---|---|---|
| Carrier terms: UK consumer SIMs are personal and non-commercial, and all exit traffic is attributed to the SIM holder | Throttling, suspension, legal exposure | A few trusted users; tcp/25 and BitTorrent blocked; SIM hard stop. **D-1: the user accepts this explicitly.** |
| WireGuard (UDP) unusable on EE | No tunnel | The M2 gate. A redesign is the user's decision, never a runtime fallback. |
| EE pooling or prefix behaviour | False stops | M2 fixes the pairing and the prefixes. A new EE prefix stops the exit until the operator adds it with RIPE evidence. |
| EE CGNAT port ceiling | Flow failures | M2 estimate; `FlowCap` |
| Uplink capacity, variability and modem thermal throttling | About 5 Mbps on bad days | `Separate` mode; M10 |
| Kernel behaviour: the `oif` rule with bound sockets, the on-link branch, `accept_local`, unprivileged SO_BINDTODEVICE, owner-guard and `ct count` semantics | Leak, slow failure, broken probes | L4 on two architectures, L4-ablation, L5. The owner guard makes leak prevention independent of the steering inferences. |
| Narrow guard residual: a flow to the target IP:80/443 while `wgexit` is gone | A small VPS-IP leak | `BindsTo`; measured by the T-no-leak variants |
| Interface-bound sockets not bypassing CFM's TUN | A loop, or capture | L6-bypass and M2; in production the carrier check stops the exit |
| Xray v26.9.30 is a prerelease, and the REALITY replace departs from upstream; Hysteria2 shares Xray's failure domain | Untested upstream changes; a crash takes down both protocols on a node | Upstream package tests and T-xray-lock in M0/L2, target rules, `MemoryMax`, the standby |
| GFW blocks the VPS IP or ASN | Entry lost | Standby on another ASN; rotation drill |
| The reflector is a visible service on the REALITY IP | A small fingerprint | Per-source limit; revisit with M8 data |
| Purego darwin sing-box; sandbox; Secure Enclave key | Build or runtime surprises | M0 and M5 spikes, with recorded decisions |
| Clamshell sleep; NetworkClientActive behaviour on macOS 27; FileVault reboot needs a login | Exit down | M2/M7 behavioural tests; documented |
| The Mac is a single point of failure for every node | Outage | Accepted; visible state |
| China-leg peak loss to London | Slow peak hours | M8 measurement; M10 relay |
| `.internal` SNI accepted by CFM and by Chrome-QUIC parroting | Hysteria2 import or connect fails | L2, L4 and L7 |
| `xray api` flags; BitTorrent sniffing without a matching `destOverride` | An accounting or policy gap | M3/M4 tests |
| Mythic Beasts cloud-init; geodata licences; whether hosted runners have `/dev/kvm` | Provisioning path; notices; L5 vehicle | Checked at purchase, in M0, and in M4 (a typed failure if KVM is missing) |
| Lima vzNAT and the Local Network privacy prompt for a LaunchAgent | Lab friction | L6 checklist |
| One maintainer | Stalls | Everything driven by `xtask`; runbooks; no hidden VPS state |
| Rendered `nftables.conf`, `wgexit.conf` and cloud-init syntax, and Xray's semantic reading of `xray.json`, are covered only by goldens and Rust-side read-back until L2 runs | A config a tool or engine rejects, or reads differently | L2 on the research computer (`nft -c`, `wg-quick strip`, `cloud-init schema`, `xray convert pb`) before the M3 lanes depend on them |
| An app upgrade (§13.3) with no configuration change re-applies a node at its current generation with a new bundle digest. The agent answers that with `GenerationNotNewer` when it already runs that generation (it stays at its older generation only after an `Unchanged` reply, §11.2), while the model records a new digest at an equal generation (§7) | An engine or host-profile upgrade cannot reach a node without a configuration change | Settle the rule when the agent's transactions (M4) and `node apply` (M5) are built |

---

## 20. Decisions needed from the user

| ID | Decision | Recommendation |
|---|---|---|
| D-1 | Accept the carrier-terms and attribution exposure of serving third parties through a consumer EE SIM | Required before M8 |
| D-2 | Rent the VPS(es): an hourly London VPS for M2, then a primary and a standby | Primary on a less popular UK network (Mythic Beasts if its console path works); standby on DigitalOcean LON1 |
| D-3 | **Resolved 2026-10-08 by the user:** Xray v26.9.30 built with `replace github.com/xtls/reality => e1986a4` (§4.2). | Done; gated by L2/L4 |
| D-4 | Keep the M7's Wi-Fi offload and Ethernet offload off (and its Wi-Fi radio off, for an exact SIM meter) | Yes |
| D-5 | Whether to schedule the separate CFM tasks: importer extraction, and shipping the ML-KEM opt-in | Independent of Mooring v1 |
| D-6 | Signing identity and provisioning profile for the app. The user performs the signing. | Use the user's Apple team; no notarization unless the app is distributed |
| D-7 | **Resolved 2026-10-08 by the user:** this Mac becomes the dedicated exit server, so it must not accumulate build caches. Rust work (M0/M1 pure crates) runs here in the single repository `target/`, which `cargo xtask clean` removes at the end of every milestone. Go engine builds, govulncheck and every VM lane (Lima/QEMU) run on the research computer or in hosted CI. The exit Mac only runs signed release artifacts. | Done |
| D-8 | **Decided 2026-10-08 for the M1 close-out (review finding F24), recorded as the operator's decision; the repository keeps no record of the user's own wording, so the user confirms it with the M1 commit:** `MAX_ACTIVE_NODES` stays 2, because the Mac exit carries at most two WireGuard endpoints and the probe port span is sized for two nodes. Rotation with a healthy standby therefore retires the blocked node before `node new` (§13.4). | Implemented in M1; the user confirms it with the M1 commit |
| D-9 | **Decided 2026-10-08 for the M1 close-out (review finding F16), recorded as the operator's decision; the user confirms it with the M1 commit, as for D-8:** CFM acceptance checking lives in `xtask` (`cargo xtask acceptance`, a `ci` step), reading `contract/cfm-acceptance.toml` and `contract/cfm-manifest.toml` with the `toml` crate (xtask-only; `deny-skips` reads `deny.toml` with it too) and the shapes and SHA-256 values through xtask → `mooring-export` and `mooring-model` edges; the release gate `require_accepted` is `cargo xtask release-acceptance`, which release verification runs (§6.1, §6.3, §9.3). Accepted cost: every xtask command compiles those crates first (§6.1). | Implemented in M1; the user confirms it with the M1 commit |

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
   - `scripts/dependency_pins.env:40,45-53,68`
   - 0.5 worktree at `3157ef9`, which contains `f340fae` (2026-10-08, rejects REALITY without uTLS) and `e6c9e05` (commits `support_x25519mlkem768`: `subscription_import/sing_box.rs:252-263,788-810`; `subscription_import/clash/tls.rs:76-78`)
   - 0.4 `subscription_import/sing_box.rs:30-180,131-152,531-541` (0.5 `:131-158,558-568`); `clash/tls.rs:144-146` (0.5 `:259-261`); `HostBridge.swift:1603-1608`
   - 0.5 `crates/cfw-singbox-config/src/profile_validation.rs:17-18,611-647` (hop interval 5..=3600); CFM patch `common/tls/pinning.go:30-64` (pin verifier)
   - `docs/cfm-contract.md` cites every importer rule the exports meet, at both revisions
8. **crates.io sparse index** (2026-10-08): ssh-key 0.6.7 (sha2 ^0.10, ed25519-dalek ^2); x25519-dalek 3.0.0 and ed25519-dalek 3.0.0 (curve25519-dalek ^5, rand_core ^0.10, sha2 ^0.11); getrandom 0.4.3; uuid 1.27.0 (getrandom ^0.4); rcgen 0.14.10; ring 0.17.14 (getrandom ^0.2); socket2 0.6.5; tokio 1.53.2; security-framework 3.7.0.
9. **Providers:** [DigitalOcean per-second billing](https://www.digitalocean.com/blog/dropletplans-persecbilling-byoip-natgateway) and [user-data immutability](https://docs.digitalocean.com/products/droplets/how-to/provide-user-data/); [Mythic Beasts VPS API quickstart](https://beasts.org/support/api/vps/quickstart). All checked 2026-10-08.
10. **This Mac (2026-10-08):**
    - macOS 27.0 (26A428), MacBookPro18,2, Xcode 27.0, Swift 6.4, rustc 1.98.1, OpenSSH_10.3p1, Lima 2.1.2, Parallels `prlctl` present.
    - No Go on PATH. No QEMU. No `cargo-mutants`.
    - No M7 interface attached: the default route is Wi-Fi `en0`.

---

## 22. Implementation plan

Every milestone ends with zero errors and zero warnings in each lane it touches, every new invariant test mutation-checked, and the results recorded in the PR. "Today on this Mac" means it needs neither the M7 nor a VPS. Downloads of pinned toolchains and sources, and installing tools (`cargo-mutants`, the musl targets), still need the user's approval at the time.

| # | Milestone | Needs |
|---|---|---|
| M0 | Repository, toolchains, pinned engines | Rust skeleton on this Mac (bounded `target/`; done); engine builds on the research computer (D-7; open) |
| M1 | Pure core | This Mac (bounded `target/`, cleaned at the end): **complete, pending the operator's commit**; L2 engine checks on the research computer (open) |
| M2 | Field spike | The M7, an EE SIM, an hourly London VPS (D-2), the user present |
| M3 | Netns e2e | Research computer (Lima) and hosted CI (D-7) |
| M4 | VPS agent and VM lanes | Hosted CI (KVM) and the research computer (D-7) |
| M5 | Mac daemon and lab lanes | This Mac today; L6-bypass needs the user |
| M6 | Real CFM in the lab | This Mac today, driven by the user |
| M7 | Swift app, power helper, release lane | This Mac today; signing by the user |
| M8 | First London VPS and pilot | The M7, EE, a VPS, a trusted user in China, D-1 |
| M9 | Operations | Two VPSs |
| M10 | Shaping and placement (optional) | Field data from M8 |

M2 can run in parallel with M3–M7 as soon as the hardware is attached. Its recorded values (keepalive, `EgressCheck`, `InterfaceSelector`, `FlowCap`) are inputs to M8, not blockers for M3–M7, which use lab values.

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

**Status at revision 4.**
- *Done on this Mac:* the skeleton, `LICENSE`, `rust-toolchain.toml` (1.98.1), workspace lints, `deny.toml` with justified skips, the crates with their declared edges (now implemented, M1), `xtask ci`, `graph-check`, `kinds-coverage`, `deny-skips` and `clean`, and the input pins of `engines.lock.toml`: the Go 1.27.1 tarball digests, Xray v26.9.30 with the REALITY replace to e1986a4, and sing-box v1.14.2 with its role tags.
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

**Status at revision 4 (2026-10-08): complete, pending the operator's commit.** The repository has no commits yet. `cargo xtask clean` (D-7) runs once the work is committed.

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
- graph-check's `x86_64-unknown-linux-gnu` build of the pure crates: with `daemon-core` (M3).
- The `lab` feature and `NodeAddress::Lab`: M5.
- The macOS-gated `ssh-keygen` and `openssl` cross-checks have run only on macOS. A Linux run of equivalent checks is unverified.

**Format note.** The V1 `state.json` shape changed during M1, before any release (certificate-only `Hy2Server`, unit `RevokePending`, required `hard_stop_bytes` and `target` keys, no serialised `Uuid`), without a version bump. A `state.json` written by an earlier development build does not decode. From the operator's commit on, the V1 golden files pin the format.

### M2 — Field spike (needs the M7, the EE SIM and an hourly London VPS; user present)

**Deliverables:**
- `docs/measurements/M2.md` with the raw logs.
- `fieldkit`, a dev-only darwin and linux-musl tool.

**Recorded decisions:**
- keepalive;
- `EgressCheck{carrier_prefixes (RIPE inetnum evidence), pairing}`;
- `InterfaceSelector` variant;
- `FlowCap`;
- the go/no-go for UDP over EE.

**Checklist:**
- M7 Wi-Fi offload and Ethernet offload off; M7 Wi-Fi radio off (D-4).

**Verification commands** (the Mac is attached to the M7 over USB-C or 2.5GbE; `<bsd>` is that interface):
```
fieldkit env --json                                   # NET_RT_IFLIST2 lladdr/gateway lladdr, stability across replug and reboot
fieldkit udp-nat-timeout --bind <bsd> --echo <vps4>:27950 --min 10 --max 300
fieldkit pooling --bind <bsd> --reflectors <vpsA>:27900,<vpsB>:27900 --flows 32 --duration 1h
fieldkit public-ips --bind <bsd> --reflector <vps4>:27900 --duration 24h --interval 5m   # then `whois` each IP → prefixes
fieldkit port-ceiling --bind <bsd> --target <vps4>:27960 --max 8192
ping -b <bsd> -D -s 1312 -c 20 <vps4>                 # outer path MTU ≥ 1340 (1312 + 28)
fieldkit uplink --bind <bsd> --sink <vps4>:27970 --duration 24h --interval 15m          # p10/p50/p90
fieldkit rtt --bind <bsd> --targets <candidate provider IPs>
# WireGuard over EE: VPS kernel wg (ListenPort 27820) + mooring-exit from M0 with a test config (no egress rules):
wg show wgexit latest-handshakes                      # on the VPS: handshake < 180 s, stable for 1 h across idle periods
# CFM coexistence (user enables CFM TUN; prompts appear):
nc -b <bsd> <vps4> 27900 ; sudo tcpdump -ni <cfm utun> host <vps4>   # prints the EE IP; zero packets on utun
pmset -g log | grep -E "Sleep|Wake|DarkWake"          # clamshell on AC, with a NetworkClientActive test assertion held
```
**Stop rule:** if UDP over EE fails, stop. A redesign is the user's decision.

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
  - stderr scrubbing.
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

**Verification:**
```
cargo xtask lane l6                          # Lima vzNAT lab: Verified verdicts; T-deny-mac on darwin; kill -9 → launchd restart,
                                             # no orphan, latch intact; VM stop (bridge gone) → Down(EgressInterfaceAbsent) ≤ 4 s
cargo xtask lane l6-bypass                   # user present: CFM TUN on/system proxy/off; `sudo tcpdump -ni utunN` shows zero
mooringctl doctor --keychain --json          # entitled helper self-check: data-protection items readable after reboot + login
```
**Acceptance:** a data-protection Keychain read works after reboot and login.

### M6 — Real CFM in the lab (this Mac, user-driven)

**Deliverables:**
- `contract/cfm-acceptance.toml` entries for every enumerated shape × client line, with importer digests.
- L7 evidence files.

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

### M8 — First London VPS and pilot (needs the M7, EE, a VPS and a trusted user in China; D-1)

**Deliverables:**
- A provisioned primary node: `node new`, `adopt`, `target`, `apply`.
- Exports delivered per `delivery.md`.
- `docs/measurements/M8.md`.

**Verification and acceptance:**
- a 72 h soak with at least 99% `Verified` samples while awake on AC;
- the SIM meter within 3% of EE's usage page (with M7 Wi-Fi off);
- per-user totals within 2% of WireGuard-derived totals;
- the offload drill: `OutsideCarrierPrefixes` and the engine stopped within 30 s;
- a trusted user in China succeeds on both protocols at peak on their carrier;
- the provider choice is recorded.

Commands:
```
mooringctl node status lon1 --json
mooringctl usage --month <YYYY-MM> --json
mooringctl exit status --follow --json
```

### M9 — Operations (needs two VPSs)

**Deliverables:**
- A standby node on a second ASN.
- Runbooks: `rotate`, `revoke`, `retire`, `incident`, `console-recovery`, `mac-loss`, `delivery`.

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
