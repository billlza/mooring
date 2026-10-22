<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Mooring

Mooring 让少数受信任的大陆用户经运营者在英国的移动网络出口上网。流量路径：

国内 CFM 客户端 → 伦敦 VPS（VLESS+REALITY+Vision / Hysteria2）→ WireGuard 隧道（由出口 Mac 主动拨出）→ 出口 Mac → NETGEAR M7 Pro → SMARTY 5G（Three 网络）→ 互联网。

出口线路是 SMARTY 消费级数据卡（运营者决策 F1）：其 APN 仅支持 IPv4，IPv4 预计处于 CGNAT 之后（M2b 实测确认），出口 Mac 无法接受入站连接，因此由 VPS 面向国内、Mac 主动建立隧道并作为出口。完整设计、威胁模型、取舍与里程碑见 [docs/design.md](docs/design.md)。

## 当前状态

设计第 9 版（2026-10-22）落地控制台的第一块：路由器控制台。`mooringctl daemon --router-interface <接口>` 在还没有部署时作为 LaunchAgent 运行，每 60 秒读取一次 M7，在 `run/control.sock` 上提供控制台状态；`mooringctl status [--follow] [--json]` 读取它，输出的文档是 `ConsoleStatus`（无部署时只含路由器面板，有部署时为 `MacStatusV1`；样例见 `contract/console-fixtures/`）。`Mooring.app`（`apple/`，SwiftUI，英文与简体中文）显示概览和路由器页面，其余页面说明需要先有部署。解析器已能读取 SMARTY 卡上实测的 `LteService`、`4G`、`4GPLUS` 和“未分配的副载波槽位”。实测发现 macOS 的本地网络隐私对 LaunchAgent 生效：未关联 App 时连接 M7 得到 `EHOSTUNREACH`；现在 plist 用 `AssociatedBundleIdentifiers` 关联 App，App 声明 `NSLocalNetworkUsageDescription`，首次读取时需要运营者允许钥匙串和本地网络访问。使用方法见 [docs/runbooks/console.md](docs/runbooks/console.md)。

设计第 8 版（2026-10-15）记录运营者交由推荐最佳实践默认值决定的 F7、F9–F11：导出前须记录用户已接受当前版本的《Mooring 使用约定》（`mooring-export` 已强制检查，缺少或修订不符时以 `AgreementNotAccepted` 拒绝）；用户在端到端加密通话中口头确认约定；配置只以文件交付（当面 AirDrop，或 AES-256 加密磁盘映像，放在 U 盘里或发送，口令经该通话口头告知），不用二维码、HTML 页面、链接或订阅，也不经微信、QQ 或中国大陆 Apple ID 的 iMessage 传递任何与本服务有关的内容；客户端限 macOS 上带“中国大陆直连”开关的 CFM 0.5.x（该开关以 `d828f92` 实现，已随 2026-10-18 发布的 CFM 0.5.0 上线；导出合同于同日改为锁定 0.5.0 的发布提交 `502adf9`）；M8 试点只有一个节点，被封即更换节点并给每位用户重发文件；数据保存期限采用 F7 的推荐默认值：节点上的流量明细保存 48 小时、每月合计保存到次月第 7 天，已作废用户在运营者电脑上的记录在作废 13 个月后删除，或应用户要求立即删除（节点上的记录按上述期限自动过期）。交付流程、用户指南与使用约定见 [docs/runbooks/](docs/runbooks/)。Go 引擎固定为 Go 1.27.2。

设计第 7 版（2026-10-13）：M1（纯 Rust 核心，4a95ee0）以及其上的控制台基础与第 6 版落实的运营者决策（71af715）均已提交。M2a 在 SMARTY 卡到货前完成了步骤 1–3（记录见 [docs/measurements/M2.md](docs/measurements/M2.md)）：M7 的 JSON 接口为 `GET /api/model.json?internalapi=1`，状态字段需要登录，登录后的文档以明文携带管理员密码、Wi-Fi 密钥与设备和用户标识，M7 时钟不可信。`crates/daemon-core` 据此实现了 MR7450 `model.json` 的白名单解析器与脱敏器（共用一张白名单表），路由器状态类型按设备实际上报的字段重塑。`crates/macsys` 读取内核路由表与邻居表；`mooringctl` 首批路由器命令 `router pin | set-password | status | capture`（只读访问 M7，仅 macOS）已实现并在本机回环桩服务器上测试；2026-10-14 首次对真实 M7 运行 `router pin` 时，普通 `cargo` 构建的预热连接已到达 M7，但内核对它返回空的邻居表，命令因此失败；现须使用 `cargo xtask mooringctl` 签名的副本 `target/signed/mooringctl`（见“构建约定”）。同日稍后 `router pin` 已在本机记录 M7 身份；`router capture --anonymous` 与 `router status` 则在第一个请求即以退出码 8 失败：M7 对不带会话 cookie 的 JSON 请求先以 302 重定向到会话建立地址 `/sess_cd_tmp…`，再重定向回 JSON（实测记录见 M2.md）。客户端现只跟随这一会话建立序列，每次读取 JSON 至多一次、至多三个请求，其他重定向一律拒绝（设计 §15.6 规则 9）。登录被拒时 M7 以 302 跳到 `/index.html?loginfailed&errno=2&errdetail=session.password`，客户端据此直接报告密码被拒；存入正确的管理员密码后，当晚 `router status`（含 `--json`）与两种 `router capture` 均已在真实 M7 上成功运行，两份脱敏抓取经检查不含任何标识，结构与 fixture 一致（见 M2.md）。第 7 版的代码与这次实机运行记录已提交（89d2cdf，2026-10-15）。尚未构建引擎、未部署任何 VPS。

## 仓库结构

| 路径 | 职责 |
|---|---|
| `crates/model` | 纯领域类型与不变量（地址分类、端口规划、密钥新类型、判定优先级） |
| `crates/keys` | X25519 / Ed25519 / UUID / 短 ID / P-256 自签证书（钉扎值由 `crates/export` 从证书推导）、OpenSSH 编码 |
| `crates/export` | 生成 CFM 可导入的 sing-box JSON 与 Clash YAML，并做证书运行时检查 |
| `crates/agent-proto` | Mac 与 VPS 代理之间的线协议类型 |
| `crates/render` | VPS（Xray、Hysteria2、WireGuard、nftables、主机配置、cloud-init）与 Mac（出口、探测）配置渲染 |
| `crates/store` | `state.json`（锁、CAS、原子写、迁移链）与密钥存储抽象 |
| `crates/fixtures` | 仅供测试的确定性部署样例（只能作为 dev-dependency） |
| `crates/daemon-core` | 控制台纯逻辑与数据模型：`mooringctl status --follow --json` 的 `MacStatusV1`、SIM 预测、上行容量判定、按用户用量汇总（UTC 周期）、告警状态机、外部网络检查、配额与到期评估、M7 状态类型与 M7 `model.json` 白名单解析与脱敏；`contract/status-fixtures/` 为 App 解码用样例，`contract/router-fixtures/` 为脱敏后的 M2a 抓取 |
| `crates/macsys` | 仅 macOS（其他平台上为空 crate，工作区仍可在 ubuntu 上构建）、唯一允许 `unsafe` 的 crate（只依赖 libc）：接口索引、IPv4 默认网关及其链路层地址（PF_ROUTE sysctl）、终端回显开关 |
| `crates/mooringctl` | 命令行工具（仅 macOS；其他平台上只提示后以退出码 1 结束）。第 9 版：`daemon`（守护进程，部署前只读取 M7 并提供控制台状态）与 `status [--follow] [--json]`（读取守护进程的状态）。第 7 版首批命令：`router pin`（记录网关链路层地址为 M7 身份；iOS 用来代替真实地址的占位值 `02:00:00:00:00:00` 永不记录、永不匹配）、`router set-password`（管理员密码存入登录钥匙串，仅从终端或 stdin 读取）、`router status`（绑定接口的 HTTP/1.1 客户端，身份核对后才登录）、`router capture`（只写脱敏器输出；形状不符的白名单值以占位符代替，并按路径列出） |
| `xtask` | 开发任务：`ci`、`graph-check`、`kinds-coverage`、`deny-skips`、`acceptance`、`release-acceptance`（发布门槛）、`clean`、`mooringctl`（构建 `mooringctl` 并签名一份副本 `target/signed/mooringctl`，仅 macOS）；第 9 版：`app`（构建 `target/app/Mooring.app`，内含签名的 `mooringctl`；要求 Swift 测试通过、Xcode 报告零错误零警告、界面文字都有中文）、`agent-install <接口>` 与 `agent-uninstall`（开发用 LaunchAgent），均仅 macOS |
| `apple/` | `Mooring.app`：`project.yml`（XcodeGen 生成工程，工程本身不入库）、`Packages/MooringKit`（控制台文档的严格解码、状态流、测试）、`App/`（概览与路由器页面、`Localizable.xcstrings` 中文翻译） |
| `engines.lock.toml` | Go 引擎的固定输入（Xray v26.9.30 + REALITY e1986a4、sing-box v1.14.2、Go 1.27.2） |
| `docs/runbooks/` | 运维手册：`console.md`（控制台的构建、启动与排障，英文）、`delivery.md`（配置交付，英文）、`user-onboarding.md` 与 `user-agreement.md`（给用户的指南与使用约定，简体中文） |

## 构建约定

- 工具链固定为 Rust 1.98.1（`rust-toolchain.toml`）。
- 出口 Mac 将作为专用服务器：所有编译输出只写入仓库内的 `target/`，每个里程碑结束执行 `cargo xtask clean`。xtask 依赖 `mooring-export` 与 `mooring-model`，工作区无法编译时改用 `rm -rf target`（设计 §6.1）。Go 引擎构建与虚拟机测试在研究电脑或托管 CI 上进行（设计 D-7）。
- 交付门槛：`cargo xtask ci` 零错误、零警告。
- `mooringctl` 用 `cargo xtask mooringctl` 构建：它构建该包，把 cargo 报告的可执行文件复制为 `target/signed/` 下的临时文件，以 `com.bill.mooring.mooringctl` 为标识符对这份副本做 ad hoc 签名，要求 `codesign -dv` 报告的正是这个标识符，然后才把它改名为 `target/signed/mooringctl` 并打印该路径。改名之前任何一步失败，`target/signed/mooringctl` 都保持原样，临时文件被删除；若删除失败，则报告 `PartialNotRemoved`（以原失败为其原因）。改名成功后只有最后的提示信息还可能失败。运行被强行中断（Ctrl-C）时可能留下 `target/signed/mooringctl.<pid>.partial`，`cargo xtask clean` 会连同整个目标目录将其删除。只要工作区没有名为 `signed` 的 profile（`[profile.signed]`），cargo 就不写 `target/signed/`，之后的 `cargo build` 或 `cargo xtask ci` 都不会撤销这个签名。签名副本不会随之后的源代码改动更新，因此在工作区根目录、Terminal.app 自己的 shell 里按 `cargo xtask mooringctl && ./target/signed/mooringctl router …` 运行（副本启动时 xtask 已经退出，不是它的祖先进程）：不要经 `cargo run`，中间也不要隔着 ad hoc 签名的 shell 或终端复用器。原因（2026-10-14 在 macOS 27.0.1 (26A434) 上实测，规则由实测情形归纳）：内核只向签名标识符为反向 DNS 形式、且不由 ad hoc 签名进程（直接或间接）启动的进程显示邻居表；普通 `cargo build` 的产物由链接器签名为 `mooringctl-<哈希>`，读到的是空表，无法读取 M7 的链路层地址。`macsys` 只如实报告表为空；`mooringctl` 只在已连通网关之后才把空表判断为被内核隐藏：`status`、`capture` 须在匿名 `GET` 成功之后；`router pin` 须预热连接成功，且预热前后两次读取都得到空表（第一次读取不为空，说明本程序能读取该表，此时第二次读到空表报告 `GatewayUnresolved`，退出码 4）。被隐藏时以本地错误（退出码 1）说明原因、提示该命令。它只在 macOS 上运行，不属于 `cargo xtask ci`（`ci` 在各平台执行相同步骤；设计 §15.6 规则 10）。

## 许可证

GPL-3.0-or-later，见 [LICENSE](LICENSE)。Xray-core（MPL-2.0）与 sing-box（GPL-3.0-or-later，附名称使用条款）作为独立进程运行，二者名称只出现在第三方声明中。
