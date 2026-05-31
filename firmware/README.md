# OpenHSM Firmware (STM32U585CIU6)

Milestone 1: the device enumerates as a **USB vendor-specific** device with
EP1 bulk IN/OUT and answers the `PING` and `GET_INFO` commands of the OpenHSM
packet protocol.

> This is a *flat* (non-TrustZone) bring-up image. The Secure/Non-secure split,
> secure boot, key store, and the encrypted session layer are later milestones.
> See `../docs/` and the project spec.

## Layout

```
firmware/
  src/            application + USB glue + HSM command dispatcher
    hsm/          hsm_proto.h (shared wire protocol), command handlers
    usb/          usbd_conf/desc/vendor + device init
  include/        headers (hal_conf, usbd_conf, main, ...)
  startup/        startup_stm32u585xx.s   (from CMSIS device)
  linker/         STM32U585xx_flat.ld     (flat 2 MB flash / 768 KB RAM)
  vendor/         STM32CubeU5 components (CMSIS, HAL, USB Device Library)
  cmake/          arm-none-eabi toolchain file
```

## Prerequisites

- `arm-none-eabi-gcc` (tested with Arm GNU Toolchain 15.2)
- `cmake` ≥ 3.20, `make`
- `dfu-util` (flashing via the STM32 system bootloader)

## Dependencies

The STM32CubeU5 components and Monocypher are git submodules under `vendor/`.
Fetch them once after cloning:

```sh
git submodule update --init --recursive   # or: make deps  (from repo root)
```

## Build

From the repo root the top-level `Makefile` is the easy path:

```sh
make firmware      # configure + build (BUILD_TYPE=Release for -Os)
```

Or directly with CMake:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
```

Outputs: `build/openhsm.elf`, `build/openhsm.bin`, `build/openhsm.hex`.

## Secure boot

The flashed image is **two stages**: a stage-1 bootloader at `0x08000000` that
verifies an **Ed25519** signature over the application (relinked to `0x08012000`)
against a baked-in vendor public key, then jumps to it. A monotonic per-image
version provides **anti-rollback** (high-water version stored in bank-2 page 124;
older images are refused). Layout: BL `0x08000000` (64 KB), signed header
`0x08010000` (8 KB), app `0x08012000`. See `bootloader/`, `tools/sign_image.c`,
and `linker/STM32U585xx_{bl,app}.ld`.

**One-time:** generate the vendor signing key (writes `keys/vendor_ed25519.seed`,
gitignored, and `bootloader/vendor_pubkey.h`):
```sh
cmake --build build --target keygen
```
Build the host signing tool once: `cc tools/sign_image.c -lsodium -o tools/sign_image`.

## Flash (DFU, no debugger needed)

1. Put the board in the **system bootloader**: hold **BOOT0 = high** and tap
   **RESET** (release RESET first, then BOOT0). It should appear as
   `0483:df11 STM32 BOOTLOADER` — check with `dfu-util -l`.
2. Flash the combined, signed image:
   ```sh
   cmake --build build --target flash
   # signs (auto version = epoch) -> build/openhsm_signed.bin, then
   # dfu-util -a 0 -s 0x08000000:leave -D build/openhsm_signed.bin
   ```
   The version auto-increments (Unix epoch via `tools/sign_flash.sh`) so it always
   satisfies anti-rollback. `:leave` resets into the bootloader → app.
3. With BOOT0 back to low, the bootloader verifies + runs the app, which
   enumerates as `0483:5750 OpenHSM Token`.

> Boot indicator: the bootloader blinks the **blue user LED (PC13)** while it runs
> (~1 s blink, then solid during the signature check), then releases it so the app's
> red PA1 heartbeat takes over. A **continuous blue blink** means verification failed
> — re-enter BOOT0+DFU and flash a good `openhsm_signed.bin`. No option bytes are
> touched, so the board cannot be bricked here. (The bootloader runs sysclk at HSI16
> for a fast verify; a short delay after a DFU `:leave` is just macOS re-enumerating USB.)

## Test the round-trip

Build and run the host tool (see `../host/tools/openhsm-ping`):

```sh
cd ../host/tools/openhsm-ping && cmake -S . -B build && cmake --build build
./build/openhsm-ping
# PING  -> status=0x0000 magic=0x4F48534D (OK)
# INFO  -> proto=0x0001 fw=0.1 serial=<96-bit UID>
# RAND  -> 128 bytes: <hex from the hardware TRNG>
```

## Notes / things to adjust for your board

- **Heartbeat LED**: defaults to `PA1`. Override at configure time if your
  Mini Core Board uses a different pin:
  `-DOPENHSM_LED_PIN=GPIO_PIN_x` (and edit `OPENHSM_LED_RCC_ENABLE` /
  `OPENHSM_LED_PORT` in `include/main.h` if it's not on GPIOA).
- **VID/PID** `0483:5750` reuses ST's vendor ID with a custom product ID for
  development only. Allocate your own before any production use.
- **Clock**: 160 MHz from HSI16→PLL (VOS range 1, 4 flash wait states);
  USB clocked from HSI48 + CRS auto-trim against USB SOF — no external crystal
  required.
