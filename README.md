# nulconnect-helper

[![CI](https://github.com/jsjtsty/nulconnect-helper/actions/workflows/ci.yml/badge.svg)](https://github.com/jsjtsty/nulconnect-helper/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE.txt)

`nulconnect-helper` is the privileged platform helper of [NulConnect](https://github.com/jsjtsty/NulConnect), a third-party, open-source client for **Sangfor aTrust** (深信服 aTrust) zero-trust access services. It provides the operating-system integration required for local proxying, TUN/VPN operation, and privileged network configuration while keeping those operations outside the desktop application process.

> **Disclaimer:** This is an unofficial project. It is not affiliated with, endorsed by, or supported by Sangfor Technologies. "aTrust" and "Sangfor" are trademarks of their respective owners.

[简体中文](README.zh-CN.md)

## Responsibilities

- Privileged IPC service for NulConnect
- macOS helper daemon with Unix-domain-socket communication
- Windows helper executable and optional Windows Service entry point
- TUN device integration and packet forwarding
- TCP, UDP, and L3 tunnel integration through [libreatrust](https://github.com/jsjtsty/libreatrust)
- Platform-specific routing and network configuration
- Bounded transport buffering and traffic statistics

The helper is intentionally a platform component rather than a general-purpose proxy. Its IPC surface is consumed by NulConnect and should be treated as a privileged interface.

## Supported platforms

CI produces release artifacts for:

- macOS arm64
- macOS x86_64
- Windows x86_64
- Windows arm64

## Build locally

The helper uses a sibling checkout of `libreatrust` through its path dependency. Clone both repositories side by side:

```text
Projects/Rust/
├── libreatrust/
└── nulconnect-helper/
```

Then build from the helper repository:

```bash
cargo build --release --locked --lib --bin nulconnect-helper
```

For the Windows Service entry point:

```bash
cargo build --release --locked --lib --bins --features windows-service
```

Release builds use symbol stripping, thin LTO, one code-generation unit, and abort-on-panic settings suitable for a bundled privileged component.

## Development checks

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --lib --bin nulconnect-helper --locked -- -D warnings
```

GitHub Actions runs these checks and builds platform-specific artifacts. Release tags are published as GitHub Release assets. The macOS packages contain the helper executable; the helper's static library is not required by NulConnect and is not packaged.

## Related projects

- [NulConnect](https://github.com/jsjtsty/NulConnect) — macOS aTrust client
- [libreatrust](https://github.com/jsjtsty/libreatrust) — Rust aTrust protocol, authentication, and transport library

## License

`nulconnect-helper` is licensed under the GNU Affero General Public License v3.0. See [LICENSE.txt](LICENSE.txt).
