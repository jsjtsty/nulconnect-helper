# nulconnect-helper

[![CI](https://github.com/jsjtsty/nulconnect-helper/actions/workflows/ci.yml/badge.svg)](https://github.com/jsjtsty/nulconnect-helper/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE.txt)

[English](README.md) | 简体中文

`nulconnect-helper` 是 [NulConnect](https://github.com/jsjtsty/NulConnect) 的特权辅助程序。NulConnect 是 **深信服 aTrust**（零信任接入服务）的第三方开源客户端。本程序提供本地代理、TUN/VPN 运行和特权网络配置所需的操作系统集成，让这些操作留在桌面应用进程之外。

> **声明：** 本项目为非官方项目，与深信服科技无隶属、认可或支持关系。“aTrust”“深信服”是其各自所有者的商标。

## 职责

- 为 NulConnect 提供特权 IPC 服务
- macOS 辅助守护进程，通过 Unix 域套接字通信
- Windows 辅助可执行文件，以及可选的 Windows 服务入口
- TUN 设备集成和数据包转发
- 通过 [libreatrust](https://github.com/jsjtsty/libreatrust) 接入 TCP、UDP 和 L3 隧道
- 平台相关的路由和网络配置
- 有界的传输缓冲和流量统计

本程序有意定位为平台组件，而不是通用代理。它的 IPC 接口只供 NulConnect 使用，应当视为特权接口。

## 支持的平台

CI 会产出以下平台的发布产物：

- macOS arm64
- macOS x86_64
- Windows x86_64
- Windows arm64

## 本地构建

本程序通过 path 依赖使用相邻目录里的 `libreatrust`。请把两个仓库克隆到同一目录下：

```text
Projects/Rust/
├── libreatrust/
└── nulconnect-helper/
```

然后在本仓库中构建：

```bash
cargo build --release --locked --lib --bin nulconnect-helper
```

构建 Windows 服务入口：

```bash
cargo build --release --locked --lib --bins --features windows-service
```

发布构建启用符号剥离、thin LTO、单个代码生成单元和 abort-on-panic，适合作为随应用分发的特权组件。

## 开发检查

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --lib --bin nulconnect-helper --locked -- -D warnings
```

GitHub Actions 会运行这些检查并构建各平台产物。发布标签会作为 GitHub Release 资源发布。macOS 包里包含辅助程序的可执行文件；NulConnect 不需要辅助程序的静态库，所以不打包。

## 相关项目

- [NulConnect](https://github.com/jsjtsty/NulConnect) — macOS aTrust 客户端
- [libreatrust](https://github.com/jsjtsty/libreatrust) — Rust 实现的 aTrust 协议、认证和传输库

## 许可证

`nulconnect-helper` 使用 GNU Affero General Public License v3.0 许可。见 [LICENSE.txt](LICENSE.txt)。
