<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# CFM first-start measurements

How long the engine start blocks while the remote rule sets of CFM's mainland China direct switch download, measured on
2026-10-15 for F10 (design §20.2) and the §19 risk row "The switch's first start can time out". CFM commit `d828f92`
(branch `feat/mainland-direct-routing`, 2026-10-16, in no release yet) sets its start limits from these results.

Nothing here names a user, a node, a device or a destination: every server was local (127.0.0.1) or under the reserved
name `rules.invalid`, and nothing left this Mac.

## Harness

A throwaway Go program (not kept), built on this Mac (macOS 27.0.1, Apple silicon) against the patched sing-box v1.14.2
source CFM pinned before `d828f92`, which carried the endpoint-conflict patch (`7ba458fb…`). It:

- serves three binary rule sets from a local HTTP server, sized like the switch's datasets on 2026-10-15: geosite-cn
  56,189 B, geosite-geolocation-!cn 168,357 B and geoip-cn 34,268 B (sizes read from raw.githubusercontent.com that
  day). They hold pseudo-random domain suffixes, so they do not compress away;
- can throttle each download (in 100 ms chunks), delay the response headers, or never answer;
- starts sing-box with those sets as remote rule sets (`download_detour` direct, `cache_file` on), either through
  `box.New` and `Start` or through `daemon.StartedService` (`StartOrReloadService`, with `CloseService` from another
  goroutine as a start watchdog would call it; libbox wraps this path), and prints when the start returns;
- can cancel the box's context, close the box, or call `CloseService` after a delay;
- for the second table, downloads the sets from https URLs, so the HTTP/2 transport is used as with
  raw.githubusercontent.com, through a proxy outbound whose local server accepts TCP, or reads UDP, and never answers.
  x/net/http2's connection pool waits on the dial without watching the request context (`client_conn_pool.go:87`), so
  these runs check that every dial and handshake layer honours cancellation.

Times are the wall-clock times the harness printed; a range covers repeated runs.

## Start with remote rule sets (`box.New` path, downloads direct)

| Scenario | Start returned after |
|---|---|
| unlimited, uncached | 150 ms |
| unlimited, cached (same URLs) | 28–54 ms |
| 50 KB/s per download, uncached | 3.405 s |
| 20 KB/s per download, uncached | 8.548–8.593 s |
| server never answers, uncached | still blocked after 60 s (no upper bound) |
| never answers; context cancelled at 3 s | 3.004 s, "context canceled" |
| never answers; `box.Close` at 3 s | 3.001 s, "use of closed network connection" for each set |
| 20 KB/s; context cancelled at 3 s | 3.004 s; the next start downloads only the unfinished set again (8.6 s) |

- A cached set whose URL changed is downloaded again ("cached rule-set was downloaded from another URL").
- The three sets download in parallel, so the total is about the largest set's time.
- Progress persists per set only: a set that cannot finish within the start limit never converges by retrying.

## Downloads through a stalled proxy outbound (daemon path)

| Detour | `CloseService` at 3 s: start returned | `CloseService` returned | No interrupt |
|---|---|---|---|
| Shadowsocks (aes-128-gcm, TCP, no handshake) | 3.006 s, nil, status STARTING | after 4 ms, status IDLE | FATAL at 15.038 s ("context deadline exceeded") |
| Trojan over TLS | 3.006 s, nil, status STARTING | after 5 ms, status IDLE | FATAL at 15.040 s |
| VLESS with REALITY (uTLS) | 3.007 s, nil, status STARTING | after 5 ms, status IDLE | FATAL at 15.053 s |
| Hysteria2 (QUIC) | 3.004 s, nil, status STARTING | after 3 ms, status IDLE | FATAL at 15.076 s |

- A stall inside the dial or the handshake ends by itself at about 15 s; a stall after the connection is up (in the
  headers or the body) has no bound.
- Both exceed the 5 s the Host then waited for a System Proxy start.

## What changed in CFM

`d828f92` interrupts every System Proxy and TUN start still running 11 s after its owner received it, and the Host
waits 18 s for a System Proxy start (up from 5 s) and 20 s for TUN readiness. Its libbox patch also changes how a start
interrupted while the instance is still being built ends, so the daemon-path rows above describe the earlier patch
set; they were not measured again on `d828f92`.

## Limits

- Synthetic rule sets of the real sizes on a loopback server: real downloads add the latency and loss of the line the
  node uses. M6 times the first start through the M7's line (§19, §22).
- One Mac, on one day; the sizes of the upstream datasets change over time.
