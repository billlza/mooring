<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Mooring

Mooring 让少数受信任的大陆用户经运营者在英国的移动网络出口上网。流量路径：

国内 CFM 客户端 → 伦敦 VPS（VLESS+REALITY+Vision / Hysteria2）→ WireGuard 隧道（由出口 Mac 主动拨出）→ 出口 Mac → NETGEAR M7 Pro → SMARTY 5G（Three 网络）→ 互联网。

出口线路是 SMARTY 消费级数据卡（运营者决策 F1）：其 APN 仅支持 IPv4，IPv4 预计处于 CGNAT 之后（M2b 实测确认），出口 Mac 无法接受入站连接，因此由 VPS 面向国内、Mac 主动建立隧道并作为出口。完整设计、威胁模型、取舍与里程碑见 [docs/design.md](docs/design.md)。

## 当前状态

设计第 6 版（2026-10-08）：M1（纯 Rust 核心）已提交（4a95ee0）。其上的控制台基础（第 5 版）与第 6 版落实的运营者决策（SMARTY 线路、试运行最多 5 名活跃用户、自动配额、远程查看角色、告警渠道）尚待提交。尚未构建引擎、未部署任何 VPS。

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
| `crates/daemon-core` | 控制台纯逻辑与数据模型：`mooringctl status --follow --json` 的 `MacStatusV1`、SIM 预测、上行容量判定、按用户用量汇总（UTC 周期）、告警状态机、外部网络检查、配额与到期评估、M7 状态类型；`contract/status-fixtures/` 为 App 解码用样例 |
| `xtask` | 开发任务：`ci`、`graph-check`、`kinds-coverage`、`deny-skips`、`acceptance`、`release-acceptance`（发布门槛）、`clean` |
| `engines.lock.toml` | Go 引擎的固定输入（Xray v26.9.30 + REALITY e1986a4、sing-box v1.14.2、Go 1.27.1） |

## 构建约定

- 工具链固定为 Rust 1.98.1（`rust-toolchain.toml`）。
- 出口 Mac 将作为专用服务器：所有编译输出只写入仓库内的 `target/`，每个里程碑结束执行 `cargo xtask clean`。xtask 依赖 `mooring-export` 与 `mooring-model`，工作区无法编译时改用 `rm -rf target`（设计 §6.1）。Go 引擎构建与虚拟机测试在研究电脑或托管 CI 上进行（设计 D-7）。
- 交付门槛：`cargo xtask ci` 零错误、零警告。

## 许可证

GPL-3.0-or-later，见 [LICENSE](LICENSE)。Xray-core（MPL-2.0）与 sing-box（GPL-3.0-or-later，附名称使用条款）作为独立进程运行，二者名称只出现在第三方声明中。
