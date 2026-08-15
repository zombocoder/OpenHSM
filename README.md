# OpenHSM

A USB-connected Hardware Security Module appliance built on
an **STM32U585CIU6**, targeting PKCS#11 seal and general
PKCS#11 / OpenSC / p11-kit consumers.

> Work in progress. See `firmware/README.md` for the device build/flash flow and
> the technical specification for the full design.

## Documentation

- [docs/firmware.md](docs/firmware.md) — firmware architecture, USB/command
  protocol, secure session, key store, crypto, auth & audit, source map.
- [docs/ROADMAP.md](docs/ROADMAP.md) — what's done vs. what remains for a
  production-ready device (secure boot, TrustZone, tamper, manufacturing, …).
- [host/openbao/README.md](host/openbao/README.md) — OpenBao auto-unseal demo.
- [host/tools/openhsm-cli/README.md](host/tools/openhsm-cli/README.md) —
  maintenance/debug CLI (local USB or remote via openhsm-daemon).
- [host/tools/openhsm-ssh-agent/README.md](host/tools/openhsm-ssh-agent/README.md) —
  SSH agent: log in with an Ed25519 key held on the device.

## Layout

```
firmware/     STM32U585 firmware (C, STM32 HAL, CMake + arm-none-eabi)
  vendor/     CMSIS / HAL / USB Device Library / Monocypher (git submodules)
host/         host-side tools
  tools/openhsm-ping   libusb + libsodium smoke-test client
  tools/openhsm-cli    maintenance/debug CLI (USB or remote via daemon)
  tools/openhsm-ssh-agent  ssh-agent backed by a device-held Ed25519 key
  daemon/              USB↔TCP bridge for remote / Kubernetes access
  pkcs11/              PKCS#11 provider + shared transport
  openbao/             OpenBao auto-unseal integration
docs/         design notes
Makefile      top-level orchestrator (see `make help`)
```

## Quick start

```sh
git clone <repo> && cd OpenHSM
git submodule update --init --recursive   # or: make deps

make toolchain     # fetch the pinned arm-none-eabi cross compiler
make firmware      # build the device image
make flash         # board in DFU (hold BOOT0, tap RESET) -> dfu-util
make ping          # run the host smoke test against the running board
```

## Toolchain

The firmware needs **Arm GNU 15.x** (`arm-none-eabi-gcc`). The host tools need
`cmake` ≥ 3.20, `pkg-config`, `libusb-1.0`, `libsodium`, and `dfu-util` to flash.

### Cross compiler: `make toolchain`

```sh
make toolchain
```

Downloads the pinned Arm GNU **15.2.rel1** into `firmware/toolchain/`
(gitignored), verifies it against the SHA-256 Arm publishes alongside the
archive, and unpacks it. No sudo, nothing installed system-wide. `make firmware`
then prefers it over anything in `PATH`, so a machine with a wrong-version or
broken system toolchain still builds correctly.

Supported hosts — Arm ships binaries only for these:

| Host | `make toolchain` |
|------|------------------|
| Linux x86_64 | ✅ |
| Linux aarch64 | ✅ |
| macOS arm64 (Apple Silicon) | ✅ |
| macOS x86_64 (Intel) | ❌ no 15.2.rel1 build |
| FreeBSD | ❌ Arm publishes none |
| Windows | ❌ install the `.zip` manually |

On an unsupported host the target fails with an explanation instead of guessing.

### Cross compiler from a system package

Workable, but check the version first — **most distributions lag well behind
15.x**, and the build refuses to start on an older major:

| OS | Command | Version shipped |
|----|---------|-----------------|
| macOS | `brew install arm-none-eabi-gcc` | 16.x — newer than tested, allowed with a warning |
| macOS | [Arm `.pkg` installer][armdl] | 15.2.rel1 — exact match; install via the GUI so it creates the `PATH` symlinks |
| Debian / Ubuntu 24.04 | `sudo apt install gcc-arm-none-eabi` | 13.2 — **too old** |
| Fedora | `sudo dnf install arm-none-eabi-gcc-cs arm-none-eabi-newlib` | varies |
| Arch | `sudo pacman -S arm-none-eabi-gcc arm-none-eabi-newlib` | current |
| FreeBSD | `sudo pkg install arm-none-eabi-gcc arm-none-eabi-newlib` | 11.3 — **too old** |
| Windows | [Arm `.zip`][armdl] | 15.2.rel1 |

Where the packaged compiler is too old and `make toolchain` is unavailable
(FreeBSD, Intel macOS), you can override the gate — untested, at your own risk:

```sh
make firmware ARM_GCC_MAJOR=11        # accept whatever major is installed
make firmware ARM_CC=/path/to/arm-none-eabi-gcc   # or point at a specific one
```

Verify what will actually be used with `make toolchain-check`.

[armdl]: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

### Host tool dependencies

| OS | Command |
|----|---------|
| macOS | `brew install cmake pkg-config libusb libsodium dfu-util` |
| Debian / Ubuntu | `sudo apt install cmake pkg-config libusb-1.0-0-dev libsodium-dev dfu-util` |
| Fedora | `sudo dnf install cmake pkgconf-pkg-config libusb1-devel libsodium-devel dfu-util` |
| Arch | `sudo pacman -S cmake pkgconf libusb libsodium dfu-util` |
| FreeBSD | `sudo pkg install cmake pkgconf libusb libsodium dfu-util` |

## Status (verified on hardware)

| Milestone | Capability                                                                               |
| --------- | ---------------------------------------------------------------------------------------- |
| 1         | USB vendor-specific device, PING/GET_INFO, multi-packet framing                          |
| 2         | Hardware TRNG (`RANDOM`)                                                                 |
| 3         | HW crypto KAT self-test + secure session (X25519 ECDH → HKDF → AES-256-GCM, anti-replay) |
| 4         | Encrypted key store in flash (HUK→KEK→objects; GENERATE/FIND/GET/DELETE; persistent)     |

## Current security caveats

- Session handshake is **unauthenticated ECDH** (no MITM protection yet — needs
  a provisioned device identity / certificate).
- The KEK is derived from the readable device UID, so it is not yet confidential
  against an attacker who can read the chip — closing this needs RDP level 2 +
  TrustZone. No plaintext key material is ever stored in flash or exported.
- Development VID/PID `0483:5750` (ST's VID + a custom PID). Allocate your own
  before production.
