# OpenHSM

A FreeBSD-compatible, USB-connected Hardware Security Module appliance built on
an **STM32U585CIU6**, targeting HashiCorp Vault's PKCS#11 seal and general
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

## Layout

```
firmware/     STM32U585 firmware (C, STM32 HAL, CMake + arm-none-eabi)
  vendor/     CMSIS / HAL / USB Device Library / Monocypher (git submodules)
host/         host-side tools
  tools/openhsm-ping   libusb + libsodium smoke-test client
  tools/openhsm-cli    maintenance/debug CLI (USB or remote via daemon)
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

make firmware      # build the device image
make flash         # board in DFU (hold BOOT0, tap RESET) -> dfu-util
make ping          # run the host smoke test against the running board
```

Toolchain prerequisites: `arm-none-eabi-gcc` (Arm GNU 15.x), `cmake` ≥ 3.20,
`dfu-util`, and `libusb-1.0` + `libsodium` for the host tools.

## Status (verified on hardware)

| Milestone | Capability |
|-----------|------------|
| 1 | USB vendor-specific device, PING/GET_INFO, multi-packet framing |
| 2 | Hardware TRNG (`RANDOM`) |
| 3 | HW crypto KAT self-test + secure session (X25519 ECDH → HKDF → AES-256-GCM, anti-replay) |
| 4 | Encrypted key store in flash (HUK→KEK→objects; GENERATE/FIND/GET/DELETE; persistent) |

## Current security caveats

- Session handshake is **unauthenticated ECDH** (no MITM protection yet — needs
  a provisioned device identity / certificate).
- The KEK is derived from the readable device UID, so it is not yet confidential
  against an attacker who can read the chip — closing this needs RDP level 2 +
  TrustZone. No plaintext key material is ever stored in flash or exported.
- Development VID/PID `0483:5750` (ST's VID + a custom PID). Allocate your own
  before production.
