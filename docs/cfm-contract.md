<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# CFM import contract of `mooring-export`

This document is the value-domain table of design §9.3 item 1. It maps every field `mooring-export` emits to the type that produces it and to the rule CFM's importer applies to it. Each emitted domain is a subset of what both CFM lines accept. CFM's converter is never copied; the rules are cited at pinned revisions.

## Pinned sources

| Name | Tree | Revision |
|---|---|---|
| **0.4** | CFM 0.4 line, `/Users/bill/cfw-rs` | `ac981c3b6c3284824e1018de367335aa6d69433e` (sing-box v1.14.1). The importer files cited below are unmodified in the working tree. |
| **0.5** | CFM 0.5 line, the commit tag `v0.5.0` points to | `502adf9fd858218bb1f1cbeba738aa0b4791960d` (sing-box v1.14.2), from which CFM 0.5.0 (build 50030) was built and published on 2026-10-18. It contains `f340fae` (design §21) and `e6c9e05` (the `support_x25519mlkem768` opt-in). Until 2026-10-18 the 0.5 citations were taken at `3157ef9`; `d828f92` changed the importer since, and re-reading it found no rule that the exports no longer meet (see the note under the Clash `fingerprint` row). |
| sing-box | upstream v1.14.2 | `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` |
| sing-quic | as pinned by sing-box v1.14.2 `go.mod:53` | `v0.7.1-0.20260924092235-6a3a24d65b99` |

`contract/cfm-manifest.toml` records the same revisions, the importer digest of each line, and the CFM sing-box patches with their SHA-256.

Citations use these prefixes: `S/` is `apps/cfw-tauri-shell/src/`, `I/` is `apps/cfw-tauri-shell/src/subscription_import/`, and `V/` is `crates/cfw-singbox-config/src/`. "0.4 `x:1-2`; 0.5 `x:3-4`" means the same rule at each revision. Where the two lines differ, the stricter rule is the one the emitter meets.

## How CFM reads an export file

| Step | 0.4 | 0.5 |
|---|---|---|
| The file is first tried as CFM's own typed profile. Our files fail that schema because it holds `credential_ref` where we hold inline credentials (`V/profile.rs:145-158`), so they fall through to the converters. | `S/subscription_import.rs:153-158` | `S/subscription_import.rs:158-177`; a typed-schema rejection of a document matching the node-list schema falls through to the adapter (`:168-173`, `I/sing_box.rs:323-325`) |
| A JSON root with `outbounds` (and no `servers`, `version` or `proxies`) goes to the restricted sing-box adapter. | `S/subscription_import.rs:160-187` | `S/subscription_import.rs:179-206` |
| A YAML document with an unindented `proxies:` key goes to the Clash converter. | `S/subscription_import.rs:189-191,209-226` | `S/subscription_import.rs:208-210,228-245` |
| The adapter accepts exactly one root key, `outbounds`, and rejects unknown keys at every level (`deny_unknown_fields`). | `I/sing_box.rs:24-28,30-31,189-251` | `I/sing_box.rs:24-28,30-31,195-263` |
| The Clash converter takes `proxies`, then the provider, policy and DNS keys; every proxy key not consumed is an error unless it is a listed tuning key. | `I/clash.rs:62-117,52-59,954-967` | `I/clash.rs:90-150,80-87,1048-1061` |
| Both converters re-validate the result with CFM's closed profile validator. | `S/subscription_import.rs:399-430` | `S/subscription_import.rs:418-449` |

## sing-box JSON (`ExportFormat::SingBoxJson`, the default)

The root holds only `outbounds` (`singbox::document`). Each node contributes its REALITY outbound and then one Hysteria2 outbound per listener. Primary nodes come first, then nodes by id.

### VLESS + REALITY + Vision outbound

| Field | Emitted | Mooring type | CFM rule (0.4; 0.5) |
|---|---|---|---|
| `type` | `"vless"` | constant | adapter variant `Vless`: 0.4 `I/sing_box.rs:100-117`; 0.5 `:100-117` |
| `tag` | `<node>-reality` | `OutboundTag` (1..=64 bytes of `[a-z0-9-]`, no edge hyphen) | non-empty, at most 128 bytes, no edge whitespace or control characters, unique: 0.4 `V/profile_validation.rs:12,52-61,460-472`; 0.5 `:12,59-68,477-489`. The adapter makes a repeated tag unique (`S/subscription_import.rs:376-397`; 0.5 `:395-416`); ours are unique already. |
| `server` | node address | `PublicIpv4` (not in any `SPECIAL_V4` range) | an IP or DNS name; an IP must not be unspecified, loopback, link-local, multicast, broadcast, documentation or 198.18/15: 0.4 `V/profile_validation.rs:498-568`; 0.5 `:515-585`. `SPECIAL_V4` covers every refused class, so this is stricter (CFM accepts RFC 1918 and CGNAT addresses). |
| `server_port` | `443` | constant: the model's `SYSTEM_PORTS` `Https` port (checked at compile time) | non-zero: 0.4 `V/profile_validation.rs:498-506`; 0.5 `:515-523` |
| `uuid` | user's VLESS UUID | `Secret<Uuid>` (canonical lowercase, non-nil v4) | parses as a UUID, not nil; re-written hyphenated: 0.4 `S/subscription_import.rs:900-906`; 0.5 `:958-964` |
| `flow` | `"xtls-rprx-vision"` | constant | only `xtls-rprx-vision`: 0.4 `S/subscription_import.rs:952-960`; 0.5 `:1010-1018`. Vision requires TLS, no transport, and packet encoding omitted or XUDP: 0.4 `V/profile_validation.rs:750-782`; 0.5 `:837-869` |
| `packet_encoding` | `"xudp"` | constant | `none`/`raw`, `packetaddr`/`packet_addr` or `xudp`: 0.4 `S/subscription_import.rs:962-972`; 0.5 `:1020-1030` |
| `tls.enabled` | `true` | constant | REALITY requires enabled TLS: 0.4 `V/profile_validation.rs:350-357`, `V/profile_validation/tls.rs:135-150`; 0.5 `V/profile_validation/tls.rs:135-150` |
| `tls.server_name` | REALITY target host | `DnsName` (lowercase LDH, at most 253 bytes, non-numeric top label) | the server-name rule above: `V/profile_validation/tls.rs:47` (both) |
| `tls.utls.enabled` | `true` | constant | present uTLS must be enabled: `V/profile_validation/tls.rs:129-134` (both). 0.5 also **requires** uTLS with REALITY: `V/profile_validation/tls.rs:151-158` (added in `f340fae`) |
| `tls.utls.fingerprint` | `"chrome"` | `Fingerprint::Chrome`, via `ClientHello` | one of the uTLS presets: 0.4 `S/subscription_import.rs:1006-1024`; 0.5 `:1064-1088`, `V/profile.rs:405-418` |
| `tls.reality.enabled` | `true` | constant | `I/sing_box.rs:732-745` (0.4); `:795-817` (0.5) |
| `tls.reality.public_key` | node REALITY key | `X25519Pub` (43 characters of unpadded base64url, not all zero) | 43 characters decoding as URL-safe unpadded base64 to 32 bytes: `V/profile_validation/tls.rs:135-150,155-157` (both) |
| `tls.reality.short_id` | user's short id | `ShortId` (16 lowercase hex, not all zero) | at most 16 lowercase hex characters, even length: `V/profile_validation/tls.rs:139-144` (both) |
| `tls.reality.support_x25519mlkem768` | `true`, only for `ClientHello::ChromeX25519Mlkem768` | `Capability::RealityMlkemOptIn`, accepted only by `ClientLine::Cfm05` | **0.4 rejects the key** (`SourceReality` has no such field and denies unknown fields: `I/sing_box.rs:242-251`). 0.5 accepts it (`I/sing_box.rs:252-263,795-817`) and requires the `chrome` fingerprint (`V/profile_validation/tls.rs:159-174`). |

Not emitted: `network`, `multiplex`, `transport`, `alpn`, `min_version`, `curve_preferences`, `ech`, pins. CFM rejects `network` and `multiplex` (0.4 `I/sing_box.rs:458-459`) and refuses explicit curves with uTLS or REALITY (`V/profile_validation/tls.rs:82-87`), and pins cannot be combined with REALITY (`V/profile_validation/tls.rs:18-27`).

### Hysteria2 outbound

| Field | Emitted | Mooring type | CFM rule (0.4; 0.5) |
|---|---|---|---|
| `type` | `"hysteria2"` | constant | adapter variant `Hysteria2`: 0.4 `I/sing_box.rs:131-152`; 0.5 `:131-158` |
| `tag` | `<node>-hy2` (`<node>-hy2-<n>` for listener `n` > 0) | `OutboundTag` | as above |
| `server` | node address | `PublicIpv4` | as above |
| `server_port` | **absent** | none | optional; when absent CFM takes the first port of `server_ports`: 0.4 `I/sing_box.rs:531-541`; 0.5 `:558-568`. Upstream sing-box dials `server_ports` when set. |
| `server_ports` | `["61000:62999"]` | `ClientPorts`: the listener port through the end of its hop range; `start < end` because the model's hop range starts at `port + 1` | 1..=64 canonical, non-overlapping items, ranges `start:end` with `start < end`: 0.4 `S/subscription_import.rs:768-811`, `V/profile_validation.rs:604-657`; 0.5 `S/subscription_import.rs:799-842`, `V/profile_validation.rs:691-744` |
| `hop_interval` | `"30s"` | the model's `HopInterval`, **5..=3600** by construction | canonical `<n>` or `<n>s`: 0.4 `S/subscription_import.rs:813-820` (1..=3600), `V/profile_validation.rs:389-400`; **0.5 requires 5..=3600**: `V/profile_validation.rs:17-18,624-660`. sing-quic refuses to dial below 5 s (`hysteria/hop.go:55-57`). |
| `password` | user's Hysteria2 password | `Password` (32 random bytes as 43 characters of base64url) | any string, moved to the keychain: 0.4 `I/sing_box.rs:550` |
| `obfs.type` | `"salamander"` | `Hy2Obfs::Salamander`, the only variant | 0.4 accepts only salamander with a non-empty password: `I/sing_box.rs:572-584`; 0.5 also accepts gecko: `:616-639` |
| `obfs.password` | listener's salamander password | `Password` | non-empty: as above |
| `tls.enabled` | `true` | constant | Hysteria2 requires TLS: `I/sing_box.rs:710-713` (0.4) |
| `tls.server_name` | `n<16 hex>.internal` | `Hy2Sni` | the server-name rule: `V/profile_validation/tls.rs:47` (both) |
| `tls.certificate_public_key_sha256` | `[<SPKI SHA-256>]` | `SpkiSha256` from `CertPins` (44 characters of padded standard base64) | one pin kind, 1..=8 distinct canonical base64 SHA-256 values, no REALITY: `V/profile_validation/tls.rs:16-46` (both) |

Not emitted: `alpn` (h3 is the default on both sides), `up_mbps`/`down_mbps` (the server replies "auto" and BBR applies), `network`, `brutal_debug`, `hop_interval_max`, `bbr_profile`, `disable_chrome_parrot`, `utls`, `reality` (QUIC refuses uTLS and REALITY: 0.4 `V/profile_validation.rs:588-602`; 0.5 `:608-622`).

## Clash YAML (`ExportFormat::ClashYaml`)

The root holds only `proxies:`. The YAML is block style; every string scalar is a JSON-encoded string, which is a valid YAML 1.2 double-quoted scalar; booleans are plain `true`; integers are plain decimals; keys are plain identifiers. CFM's loader keeps every scalar's source text and decides its type per key: strings and ports are read from the text, and booleans must be plain (a quoted `"true"` is not a boolean): 0.4 `I/yaml.rs:41-78`, `I/clash.rs:879-908`; 0.5 `I/clash.rs:973-1002`. Aliases, anchors and duplicate keys are refused (`I/yaml.rs:1-17`).

### VLESS + REALITY + Vision proxy

| Key | Emitted | Mooring type | CFM rule (0.4; 0.5) |
|---|---|---|---|
| `name` | `<node>-reality` | `OutboundTag` | required, unique, not `DIRECT` or `REJECT`: 0.4 `I/clash.rs:103-107,123-124`; 0.5 `:135-139,159-160` |
| `type` | `"vless"` | constant | 0.4 `I/clash.rs:128-145`; 0.5 `:164-182` |
| `server` | node address | `PublicIpv4` | then the validator's server rule |
| `port` | `443` | constant (`SYSTEM_PORTS` `Https`) | parses as a non-zero `u16`: 0.4 `I/clash.rs:902-908`; 0.5 `:996-1002` |
| `uuid` | user's VLESS UUID | `Secret<Uuid>` | 0.4 `I/clash.rs:405-407` |
| `flow` | `"xtls-rprx-vision"` | constant | 0.4 `I/clash.rs:384-388` |
| `packet-encoding` | `"xudp"` | constant | 0.4 `I/clash.rs:400-403` |
| `tls` | `true` (plain) | constant | must be a YAML boolean; `reality-opts` requires `tls: true`: 0.4 `I/clash/tls.rs:20,66-71`; 0.5 `:54,162-168` |
| `servername` | REALITY target host | `DnsName` | `servername`/`sni` (equal if both): 0.4 `I/clash/tls.rs:21-33`; 0.5 `:55-67` |
| `client-fingerprint` | `"chrome"` | `Fingerprint::Chrome` | a uTLS preset: 0.4 `I/clash/tls.rs:35,125-129`; 0.5 `:69,233-239` |
| `reality-opts.public-key` | node REALITY key | `X25519Pub` | required: 0.4 `I/clash/tls.rs:36-44`; 0.5 `:70-85`; then the validator's REALITY rule |
| `reality-opts.short-id` | user's short id | `ShortId` | as above |
| `reality-opts.support-x25519mlkem768` | plain `true`, only for `ClientHello::ChromeX25519Mlkem768` | `Capability::RealityMlkemOptIn` on `Cfm05` | **0.4 rejects the key** (`reality.reject_leftovers()`, `I/clash/tls.rs:42`). 0.5 reads it as a YAML boolean (`I/clash/tls.rs:76-78`) and requires `chrome` (`V/profile_validation/tls.rs:159-174`). |

Not emitted: `udp`, `encryption`, `alpn`, `skip-cert-verify`, `smux`, `dialer-proxy`, `network`, transport options, `ech-opts`, groups, rules and `dns`.

### Hysteria2 proxy

| Key | Emitted | Mooring type | CFM rule (0.4; 0.5) |
|---|---|---|---|
| `name` | `<node>-hy2` | `OutboundTag` | as above |
| `type` | `"hysteria2"` | constant | as above |
| `server` | node address | `PublicIpv4` | as above |
| `port` | `61000` (the listener port) | `Port` from `ClientPorts` | required, non-zero `u16` (as above) |
| `ports` | `"61000-62999"` | `ClientPorts` | `start-end` or `start:end`, canonical, `start < end`: 0.4 `I/clash.rs:467-479`, `S/subscription_import.rs:768-811`; 0.5 `I/clash.rs:514-526`, `S/subscription_import.rs:799-842` |
| `hop-interval` | `30` | the model's `HopInterval` (5..=3600) | 0.4 1..=3600 (`I/clash.rs:480-483`, `S/subscription_import.rs:813-820`); 0.5 `N` or `N-M`, then 5..=3600 (`I/clash.rs:527-530`, `S/subscription_import.rs:855-867`, `V/profile_validation.rs:624-660`) |
| `password` | user's Hysteria2 password | `Password` | required: 0.4 `I/clash.rs:486-489` |
| `obfs` | `"salamander"` | `Hy2Obfs::Salamander` | `salamander` (0.5 also `gecko`): 0.4 `I/clash.rs:498-514`; 0.5 `:549-583` |
| `obfs-password` | listener's salamander password | `Password` | required with `obfs`: as above |
| `sni` | `n<16 hex>.internal` | `Hy2Sni` | as `servername` |
| `fingerprint` | DER SHA-256, 64 lowercase hex | `Sha256Digest` from `CertPins` | 64 hex digits (colons allowed), mapped to **`certificate_sha256`**, a DER pin: 0.4 `I/tls.rs:5-18`, `I/clash/tls.rs:14-19,144-146`; 0.5 `I/tls.rs:3-8,17-39`, `I/clash/tls.rs:48-53,252-253`. The 0.4 module comment saying `fingerprint` is refused (`I/clash.rs:17-18`) is stale; 0.5 corrects it (`I/clash.rs:28-37`). Since `d828f92`, 0.5 also accepts `skip-cert-verify: true` beside a pin and never emits it (`I/clash.rs:285-297`); the exports never send it. |

Not emitted: `tls` (optional for Hysteria2; `tls: false` is refused), `client-fingerprint` (refused for QUIC: 0.4 `I/clash/tls.rs:88-94,114-116`; 0.5 `:194-200,222-224`), `up`, `down`, `mport`, `alpn`, `bbr-profile`, `udp`.

## Client capabilities

`ClientHello::for_profile` refuses a capability the user's line does not accept (`ExportError::CapabilityUnsupported`), using the model's `ClientLine::accepts`, which matches the importers:

| Capability | `Cfm04` | `Cfm05` |
|---|---|---|
| `RealityMlkemOptIn` | refused: both converters reject the key (see above) | accepted; adds `support_x25519mlkem768: true` / `support-x25519mlkem768: true` with the chrome hello |

The CFM 0.5 sing-box patch implements the opt-in on the client: it refuses the opt-in unless the uTLS hello is chrome and sends the X25519MLKEM768 share before a separate X25519 share (`native/macos/patches/sing-box-v1.14.2-security-dependencies.patch`, `common/tls/reality_client.go` hunk, patch lines 181-276; `option/tls.go` hunk, patch lines 1197-1210). Upstream sing-box v1.14.2 has no such field (`option/tls.go:252-256`), so the Mac prober's outbounds (`probe_outbounds`) always use the classical chrome hello.

## Run-time certificate checks (`check_certificate`)

CFM's patch adds `verifyPinnedServer` to sing-box (`common/tls/pinning.go`, created by `native/macos/patches/sing-box-v1.14.1-security-dependencies.patch` lines 1-71 at 0.4 and by the identical hunk of `sing-box-v1.14.2-security-dependencies.patch` at 0.5; file line *n* is patch line *n* + 6). Both TLS clients call it whenever a pin is configured (patch lines 181-221 at 0.4, 486-509 at 0.5). `mooring-export` checks the stored certificate at every export and offers the same check to `node apply`; only the certificate is stored, and the SNI and both pins are derived from it:

| `pinning.go` (file lines) | `mooring-export` (`src/cert.rs`) |
|---|---|
| `x509.ParseCertificate(rawCerts[0])` (30-33) | `parse_x509_certificate` with nothing trailing, else `CertUnparseable` |
| `now` outside `[NotBefore, NotAfter]` fails (34-40) | `NotBefore <= now - 1 day` and `now + 1 day <= NotAfter`, else `CertNotCurrent` |
| `leaf.VerifyHostname(name)`, `name` = `tls.server_name` (41-43) | the SAN extension is exactly one DNS name of the `n<16 hex>.internal` form, which becomes the `server_name` exports send, else `CertSanMismatch` |
| if EKUs are listed, one must be serverAuth or any (44-52) | the EKU extension must exist and list serverAuth, else `CertEkuMissing` |
| DER pin = SHA-256(raw DER); SPKI pin = SHA-256(`RawSubjectPublicKeyInfo`) (53-64) | the pins are not stored: `check_certificate` (and `certificate_pins` for the prober) compute both from the stored certificate, so they cannot disagree with it |

Upstream sing-box, which the Mac prober runs, hashes `x509.MarshalPKIXPublicKey(leaf.PublicKey)` instead of the raw SPKI (`common/tls/std_client.go:137-145,278-295`). The two agree only for a canonically encoded key, so `check_certificate` also requires the SPKI to be the canonical uncompressed P-256 encoding (`CertKeyUnsupported`).

## Shapes and acceptance

`shapes()` enumerates every shape: for each client line, each accepted capability set, each format and each protocol, the emitter's template with every variable leaf replaced by a type tag, written canonically and hashed with SHA-256. `contract/cfm-acceptance.toml` must list each `(shape hash, client line)` exactly once (`require_recorded`, run by `cargo xtask acceptance`, a step of `cargo xtask ci`). xtask reads both contract files with the `toml` crate into typed serde structs that deny unknown keys (`xtask/src/acceptance/`); an entry's `status` decides which keys it must carry, the manifest's importer digests are recomputed from their importer objects, and the manifest must describe exactly the enumerated client lines. Every entry is `pending-real-cfm-import` until M6 imports each shape into real CFM. The release gate, `cargo xtask release-acceptance` (`require_accepted`), accepts only `accepted` entries whose importer digest equals the current one in `contract/cfm-manifest.toml` and whose bundle version and sing-box core are those of a build of the entry's line.

Today `Cfm04` and `Cfm05` produce identical documents for the same capability set, so their entries share hashes; `Cfm05` adds the two `chrome-x25519mlkem768` REALITY shapes.

## What this does not prove

- The tables above are a reading of CFM's source, cross-checked by tests of `mooring-export` itself (goldens, shape conformance of every fixture export, YAML read-back with saphyr). No CFM code runs in these tests.
- CFM 0.5.0's own import goldens include hand-written documents of the two default `chrome` shapes in each format (`I/tests.rs:2775-2820`, `I/goldens/sing-box-mooring-shape.json` and `clash-mooring-shape.json`). They run CFM's importer and validator, but `mooring-export` did not write them and they leave out the `chrome-x25519mlkem768` shapes, so they move no entry to `accepted`.
- A CFM-patched sing-box CLI (`xtask cfm-client`, L2/L4) stands in for CFM's engine only; it is not CFM, and it never runs CFM's importer.
- Only real CFM imports (M6, L7) can move a shape to `accepted`.
