<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Engine configuration keys

Every key `mooring-render` writes, mapped to the pinned upstream source that reads it. Line numbers are at these commits:

| Tree | Commit |
|---|---|
| Xray-core v26.9.30 | `b26a91de4f3294e26a0ad0a970b81a386a41f789` |
| XTLS/REALITY (replaces the module Xray pins) | `e1986a4d31ca33c087a72ab4644aef1295693b69` |
| sing-box v1.14.2 | `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` |

**This table is documentation, not a gate (design §8.1).**
- Xray decodes its config with a plain `json.NewDecoder` and silently ignores unknown keys (`infra/conf/serial/loader.go:47-55`). L2 runs `xray run -test` on warn-level copies and asserts the semantic protobuf fields with `xray convert pb -debug -type`.
- sing-box rejects unknown keys (`option/options.go:39-41`, `DisallowUnknownFields`). L2 runs `check` on warn-level copies.
- `wgexit.conf`, `nftables.conf` and the cloud-init user-data have no pinned tree in this repository. Their syntax is *(inference)* until L2 runs `wg-quick strip`, `nft -c -f` and `cloud-init schema`.

The renderer's types are closed. Every config struct also deserialises with unknown fields rejected, and fixed strings are one-value types. The goldens in `contract/golden/<fixture>/` therefore read back into the same types (`crates/render/src/tests/roundtrip.rs`).

## `xray.json` (Xray v26.9.30)

| Key | Source | Why |
|---|---|---|
| root `log`, `api`, `stats`, `policy`, `dns`, `inbounds`, `outbounds`, `routing` | `infra/conf/xray.go:405-422` | The only sections used. |
| `log.access` = `none` | `infra/conf/log.go:19,36-37` | No access log. |
| `log.loglevel` = `none` | `infra/conf/log.go:21,49-62` (`none` sets both logs to `LogType_None`, `:57-59`) | Nothing is logged at run time. At `warning` Xray would still log each failed DoH lookup at ERROR with the queried domain (`app/dns/nameserver_doh.go:155,199,207,215`) and resolution failures (`transport/internet/dialer.go:258`); `maskAddress` masks IP addresses only, and DoH fails for every uncached domain while the gate is closed. Start-up failures still reach stdout (`main/run.go:84,95`), and the agent validates a copy forced to `warning` (design §11.2). The renderer's type has only `none`. |
| `log.dnsLog` = `false` | `infra/conf/log.go:22,33` | No per-lookup log lines. |
| `log.maskAddress` = `full` | `infra/conf/log.go:23,63`; `app/log/log.go:170-196` | `full` masks every IPv4 and IPv6 address in log lines. |
| `api.tag`, `api.listen`, `api.services` = `["StatsService"]` | `infra/conf/api.go:16-20,28-37` | Per-user counters for accounting, on `127.0.0.1:10085` only. |
| `stats` = `{}` | `infra/conf/xray.go:387-392` | An empty object enables the stats manager. |
| `policy.levels."0"`: `handshake`, `connIdle`, `uplinkOnly`, `downlinkOnly`, `statsUserUplink`, `statsUserDownlink` | `infra/conf/policy.go:7-16,73-76` | Users and the probe; per-user traffic counters. `statsUserOnline` (`:14`) stays off, because it exposes client IP lists through the API. |
| `policy.levels."1"`: the four timeouts | `infra/conf/policy.go:7-11` | Short timeouts for the camouflage forwards. |
| `dns.tag` = `dns-exit` | `infra/conf/dns.go:164`; `app/dns/dns.go:89-91,142-144`; `app/dns/nameserver.go:183` | DoH queries enter routing with this inbound tag, which routes them through `exit`. |
| `dns.queryStrategy` = `UseIPv4` | `infra/conf/dns.go:165,381-394` | IPv4 only. |
| `dns.enableParallelQuery` | `infra/conf/dns.go:171`; `app/dns/dns.go:282-283` | Both servers are queried in parallel. |
| `dns.serveStale`, `dns.serveExpiredTTL` | `infra/conf/dns.go:167-168` | Serve stale answers through brief DoH failures. |
| no `dns.disableFallback` | `app/dns/dns.go:321-344` | With no domain-scoped servers it leaves only the first server and logs a WARNING naming each domain. |
| `dns.servers[].address` = `https://1.1.1.1/dns-query`, `https://1.0.0.1/dns-query` | `infra/conf/dns.go:20`; `app/dns/nameserver.go:56` | DoH in remote mode, dialled through routing. |
| `dns.servers[].unexpectedIPs` = `SPECIAL_V4` | `infra/conf/dns.go:34,109-125` | Answers inside a special-purpose range are dropped. |
| inbound `tag`, `listen`, `port`, `protocol`, `settings`, `streamSettings`, `sniffing` | `infra/conf/xray.go:130-138` | |
| `protocol` = `vless` (inbound) | `infra/conf/xray.go:31` | |
| `protocol` = `tunnel` | `infra/conf/xray.go:25` | An alias of `dokodemo-door`. |
| VLESS `settings.decryption` = `none`, `settings.clients` | `infra/conf/vless.go:33-40,46-48,149-155` | `decryption` is mandatory; `none` disables VLESS encryption. |
| client `id`, `flow` | `proxy/vless/account.pb.go:80,82`; `infra/conf/vless.go:66-79` | The UUID is parsed and re-canonicalised. `flow` is `xtls-rprx-vision` on `reality-in` and `""` on `hy2-loop-in`. |
| client `level`, `email` | `common/protocol/user.pb.go:28-29` | `email` keys the traffic counters (`user>>>EMAIL>>>traffic>>>…`), `<id>@reality` or `<id>@hy2`. |
| `streamSettings.network` = `raw` | `infra/conf/transport_internet.go:16-19,52` | `raw` is the current name of TCP. |
| `streamSettings.security` = `reality` / `none` | `infra/conf/transport_internet.go:53,91-123` | |
| `realitySettings.show`, `target`, `xver`, `serverNames`, `privateKey`, `minClientVer`, `maxTimeDiff`, `shortIds` | `infra/conf/transport_security.go:27-52,54-153` | `target` is the target's IPv4 literal with port 443 (so no system resolver is used). `xver` 0. `serverNames` is the single exact target name; REALITY matches it exactly (REALITY `tls.go:211`). `minClientVer` 1.8.1, because sing-box clients announce 1.8.1 (REALITY `tls.go:257`). `maxTimeDiff` is in milliseconds (`transport/internet/reality/config.go:29`; REALITY `tls.go:259`). `shortIds` are 16 hex characters each. |
| — | `infra/conf/transport_security.go:163-169` | A `serverNames` entry ending in `.ru`, `.ir` or `.cn`, or containing `apple`, `icloud` or `microsoft`, logs a WARNING. `target::deny_rule` refuses such targets. |
| — | `infra/conf/transport_security.go:100-102` | An invalid `privateKey` is echoed in the error. Stderr tails are scrubbed (design §12). |
| — | `infra/conf/xray.go:181-184` | REALITY off port 443 logs a WARNING; `reality-in` is always on 443. |
| `sniffing.enabled`, `destOverride` = `http`, `tls`, `quic`, `routeOnly` | `infra/conf/xray.go:59-66,68-84` | `routeOnly` feeds routing and never rewrites the destination. The BitTorrent sniffers always run once sniffing is on (`app/dispatcher/sniffer.go:41,43`), and they set the protocol routing matches (`app/dispatcher/default.go:297,352`). |
| tunnel `settings.address`, `port`, `network`, `userLevel` | `infra/conf/dokodemo.go:10-20,23-31` | `address`/`port`/`network` are the aliases of `rewriteAddress`/`rewritePort`/`allowedNetwork` that upstream's own test uses (`dokodemo_test.go`). |
| outbound `tag`, `protocol`, `settings`, `streamSettings` | `infra/conf/xray.go:220-229` | |
| `protocol` = `blackhole` (`deny`), `freedom` | `infra/conf/xray.go:42,45` | `deny` is first, so it is the default outbound. |
| `exit` `streamSettings.sockopt.interface` = `wgexit` | `infra/conf/transport_sockopt.go:60,180`; `transport/internet/sockopt_linux.go:23-27` | SO_BINDTODEVICE. A failure is logged at Info and the dial proceeds (`transport/internet/system_dialer.go:79-80,136-137`); the nft owner guard covers that case. |
| `exit` `sockopt.tcpUserTimeout` = 30000 | `infra/conf/transport_sockopt.go:58,178`; `transport/internet/sockopt_linux.go:52-54` | TCP_USER_TIMEOUT, in milliseconds. |
| `exit` `sockopt.domainStrategy` = `ForceIPv4` | `infra/conf/transport_sockopt.go:50,96-121`; `transport/internet/dialer.go:251-262`; `proxy/freedom/freedom.go:55-58,293-302` | Resolve through Xray's DoH and fail on error, rather than fall back to the system resolver. |
| camouflage `settings.redirect`, `settings.userLevel` = 1 | `infra/conf/freedom.go:19-30,160-177`; `proxy/freedom/freedom.go:210-211` | Freedom applies its own level's timeouts, so the outbound side gets the camouflage timeouts too. |
| `routing.domainStrategy` = `AsIs` | `infra/conf/router.go:70-90` | IP rules match IP-literal destinations; domains are covered by the DoH filter and the Mac. |
| rule `inboundTag`, `user`, `ip`, `domain`, `network`, `port`, `protocol`, `outboundTag` | `infra/conf/router.go:120-124,132-153,155-277` | |
| rule `ip` entries: IPv4, IPv4 prefix, `::/0`, `geoip:cn` | `common/geodata/rule_parser.go:16-48` | |
| rule `domain` = `geosite:cn` | `common/geodata/rule_parser.go:137` | |
| rule `port` as a decimal string | `infra/conf/common.go:247-278` | |
| rule `network` | `infra/conf/common.go:92-111` | |

## `hy2.json` (sing-box 1.14.2, `mooring-hy2`)

| Key | Source | Why |
|---|---|---|
| root `log`, `inbounds`, `outbounds`, `route` | `option/options.go:14-30` | |
| `log.level` = `fatal` | `option/options.go:69-75`; `log/level.go:40-59` | Inbounds log every destination at INFO; the type has no other value. |
| inbound `type`, `tag` | `option/inbound.go:21-24` | |
| `listen`, `listen_port` | `option/inbound.go:79-81` | `<VPS4>` and the listener port from `PortPlan`. |
| `obfs.type` = `salamander`, `obfs.password` | `option/hysteria2.go:21,64-68`; `protocol/hysteria2/inbound.go:60-66` | One salamander password per listener. |
| `users[].name`, `users[].password` | `option/hysteria2.go:22,115-118`; `protocol/hysteria2/inbound.go:214-222` | The name is the opaque user id, or `probe`. |
| `ignore_client_bandwidth` = `true` | `option/hysteria2.go:23`; `protocol/hysteria2/inbound.go:204` | With no `up_mbps`/`down_mbps` the server replies "auto". |
| `tls.enabled`, `tls.alpn` = `["h3"]` | `option/tls.go:14,17`; `protocol/hysteria2/inbound.go:49-51` | TLS is mandatory for Hysteria2. |
| `tls.certificate`, `tls.key` as PEM line lists | `option/tls.go:22,28`; `common/tls/std_server.go:406-416` | Inline, so `check` of a staged generation reads that generation's own material. The lines are joined with `\n`. |
| outbound `type` = `vless`, `tag` | `option/outbound.go:23-24` | |
| `server`, `server_port` | `option/outbound.go:183-186` | `127.0.0.1:10443`, Xray's `hy2-loop-in`. |
| `uuid`, `packet_encoding` = `xudp` | `option/vless.go:17-27` | The identity's loopback UUID, so accounting stays per user. |
| rule `inbound`, `auth_user` | `option/rule.go:141,144` | |
| rule `action` = `route` / `reject`, `outbound` | `option/rule_action.go:19,174-176` | |
| final rule `{"inbound": [...], "action": "reject"}` | `route/rule/rule_default.go:15-19` | A rule without a condition fails with "missing conditions". |

## `mooring-exit` (sing-box 1.14.2, Mac)

| Key | Source | Why |
|---|---|---|
| root `log`, `endpoints`, `outbounds`, `route` | `option/options.go:14-30` | |
| endpoint `type` = `wireguard`, `tag` = `wg-<node>` | `option/endpoint.go:18-22` | |
| `system` = `false`, `mtu` = 1280, `address`, `private_key`, `peers` | `option/wireguard.go:9-16` | Userspace (gVisor) endpoint. The address is the Mac's /32. |
| `peers[].address`, `port`, `public_key`, `allowed_ips`, `persistent_keepalive_interval` | `option/wireguard.go:25-33` | `allowed_ips` is only the VPS's tunnel /32, so any other inner source is dropped. There is no `listen_port`; the Mac dials out. |
| `udp_timeout` = `5m`, `udp_nat_max` = 4096 | `option/wireguard.go:17,20`; `transport/wireguard/device_stack.go:83-88` | The gVisor UDP NAT is bounded. |
| `bind_interface` (endpoint) | `option/wireguard.go:22`; `option/outbound.go:80-86` | The tunnel uplink. |
| outbound `type` = `direct`, `tag` = `egress`, `bind_interface` | `option/direct.go:17-25`; `option/outbound.go:86` | The M7 egress. Every Mac socket is bound. |
| rule `inbound`, `ip_version`, `network`, `ip_cidr`, `port` | `option/rule.go:141-143,156,160` | |
| rule `action` = `route` / `reject`, `outbound` | `option/rule_action.go:19,174-176` | |
| `route.final` = `egress`, `auto_detect_interface` = `false`, `default_interface` | `option/route.go:10,14,16` | |
| — | `protocol/wireguard/endpoint.go:231-240,243-244` | Traffic to the endpoint's own address is rewritten to 127.0.0.1 before routing, so the 127/8 reject is load-bearing; the endpoint logs every destination at INFO. |

## `mooring-probe` (sing-box 1.14.2, Mac)

| Key | Source | Why |
|---|---|---|
| inbound `type` = `direct`, `listen` = `127.0.0.1`, `listen_port`, `network` = `tcp` | `option/direct.go:10-15`; `option/inbound.go:79-81`; `option/types.go:18-40` | One port per node and protocol, from `ProbePolicy::port_for`. |
| `override_address`, `override_port` | `option/direct.go:13-14`; `protocol/direct/inbound.go:45-50` | The node's reflector. These fields are still supported on the direct *inbound*; only the direct outbound's were removed (`option/direct.go:19-22,35-37`). |
| outbounds | `mooring-export` `SingBoxOutbound` + `bind_interface` (`option/outbound.go:86`) | `MacProbeOutbound` is the only wrapper. The VLESS and Hysteria2 outbound options embed `DialerOptions` (`option/vless.go:18`, `option/hysteria2.go:211`). |
| rule `inbound`, `action` = `route`, `outbound`; `route.auto_detect_interface` = `false`, `default_interface` | as above | |

## `wgexit.conf` (`wg-quick`), `nftables.conf`, cloud-init

There is no pinned tree for these in this repository; L2 validates them. The rendered forms follow design §8.4, §8.5 and §8.9, with the changes listed below.

## `watch.json`

`mooring_agent_proto::WatchConfig` (`keepalive_secs`, `target.host`, `target.ipv4`), serialised by its own closed type.

## Digests

- **Per-file digest.** It is the SHA-256 of the rendered bytes (`RenderedFile::sha256`). It is the blob name in the `Apply` header and the engine's config digest: an engine restarts only when its own file's digest changes. `ExitConfig::digest` and `ProberConfig::digest` are the same for the Mac engines. Users never appear in the Mac configs, so adding a user changes `xray.json` and `hy2.json` and nothing else.
- **Bundle digest** (`VpsBundle::digest`). It is the SHA-256 of this encoding, each line ending in `\n`:

  ```text
  mooring-vps-bundle/1
  host-profile <version>
  arch <amd64|arm64>
  uplink <interface name>
  vps4 <ipv4>
  ephemeral <first>-<last>
  engine xray <sha256 hex>
  engine hy2 <sha256 hex>
  engine geoip <sha256 hex>
  engine geosite <sha256 hex>
  file <name> <byte length>    then the bytes and "\n", for each managed file in ManagedFile::ALL order
  ```

  Every variable field is either a token without spaces or newlines, or a length-prefixed byte string, so the encoding is injective.
  - The engines and the host-profile version are included, so an `Apply` after an engine or host-profile upgrade is never answered `Unchanged`.
  - The generation is not included, so a generation bump with no VPS-visible change is `Unchanged`.

## Changes to the design §8 snippets

Each change below is required by the pinned source or by a defect in the snippet.

1. **`exit` resolution strategy.** §8.2 writes `"settings": {"targetStrategy": "ForceIPv4"}` on the freedom `exit`. In v26.9.30 this logs a WARNING at load ("The `freedom.domainStrategy` setting is deprecated…", `infra/conf/xray.go:362-368`), because `targetStrategy` fills the same freedom field (`infra/conf/freedom.go:62-91`). An outbound-level `targetStrategy` also warns (`:363-364`). The renderer writes `streamSettings.sockopt.domainStrategy: "ForceIPv4"` (`infra/conf/transport_sockopt.go:50,96-121`), the form the migration converts to, and `exit` has no `settings`. The fail-on-DNS-error behaviour is in `transport/internet/dialer.go:251-262`; the §3 and §8.2 citation `freedom.go:113,115-125` is now `proxy/freedom/freedom.go:293-302`.
2. **Camouflage outbounds carry `"userLevel": 1`.** Freedom applies its own `userLevel` policy (`proxy/freedom/freedom.go:210-211`). Without it, the outbound side of a camouflage flow would keep level 0's 300 s idle timeout.
3. **`flow: ""` on `hy2-loop-in` clients** is kept as in the design. It is equivalent to omitting the key (`infra/conf/vless.go:72-74`).
4. **nftables named counters are declared.** §8.5 uses `counter name xray_guard`, `hy2_guard` and `flow_cap` without declaring the named counter objects. The ruleset declares each as `counter <name> { packets 0 bytes 0 }` *(inference until L2 `nft -c`)*.
5. **Split per-source sets.** §8.5 shares one dynamic set `camo_src` between a `ct count` element expression (TCP/80) and a `limit` element expression (UDP/443). A set element keeps the expression it was created with, so a source that hit TCP/80 first would have UDP/443 judged by its connection count. The ruleset uses `camo_tcp_src` (`flags dynamic`, no timeout; connlimit elements are collected when their count drops to zero) and `camo_udp_src` (`flags dynamic,timeout`, `timeout 2m`) *(inference until L2/L4)*.
6. **Camouflage rules follow `TrafficPolicy.camo_forward`.** When it is off, the `camo-*` inbounds, outbounds and rules are absent. The nft input chain no longer opens TCP/80 and UDP/443, and the owner guard admits only TCP/443 to the target (for REALITY).
7. **The Mac TCP/25 reject follows `TrafficPolicy.deny_smtp25`**, as the Xray rule does. With the default policy the output equals §8.7.
8. **Per-node reflector ports.** The node-address allow rules in Xray and on the Mac are grouped by each node's own `PortPlan` reflector port, instead of a hard-coded 27900. Likewise, every port in hy2, nft, `wgexit.conf` and the Mac configs comes from `PortPlan`, and each Hysteria2 listener gets its own inbound (`hy2-in`, `hy2-in-<n>`) and hop redirect.
9. **Identities are opaque user ids.** The Xray emails are `<user id>@reality` and `<user id>@hy2`, built with the agent's `StatsEmail`. The hy2 user names are the user ids, and loopback outbounds are `x-<user id>` / `x-probe`. The design's `u01` was illustrative.
10. **Other design §8.2 citations, re-read at v26.9.30:**
    - `freedom.go:17-25,45-48` → `infra/conf/freedom.go:19-30,160-177`
    - `sockopt_linux.go:50-54` → `:23-27`
    - `dns.go:30-33,199-210` → `infra/conf/dns.go:19-35,160-173`
    - `xray.go:26-27` → `:25`
    - `dokodemo.go:16` → `:10-20`
    - `transport_internet.go:854` and `:913-914` (§12, §16) → `infra/conf/transport_security.go:100-102` and `:163-169`
    - `policy.go:12-14` and `api.go:18` are unchanged.
11. **The `wgexit.conf` comment** on `AllowedIPs` is not rendered.
