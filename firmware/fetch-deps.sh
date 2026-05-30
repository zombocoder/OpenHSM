#!/usr/bin/env bash
# Fetch the STM32CubeU5 components OpenHSM firmware depends on.
# Shallow clones into firmware/vendor/. Safe to re-run (skips existing).
set -euo pipefail

cd "$(dirname "$0")/vendor"

clone() {
    local dir="$1" url="$2"
    if [ -d "$dir/.git" ]; then
        echo "== $dir already present, skipping"
    else
        echo "== cloning $dir"
        git clone --depth 1 "$url" "$dir"
    fi
}

clone cmsis_core      https://github.com/STMicroelectronics/cmsis_core.git
clone cmsis_device_u5 https://github.com/STMicroelectronics/cmsis-device-u5.git
clone stm32u5xx_hal   https://github.com/STMicroelectronics/stm32u5xx_hal_driver.git
clone usb_device      https://github.com/STMicroelectronics/stm32_mw_usb_device.git

echo "Done. Vendored SDK is in firmware/vendor/."
