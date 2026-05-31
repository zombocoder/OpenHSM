#!/bin/sh
# sign_flash.sh — sign the combined image with an auto-incrementing version.
#
# The version is the current Unix epoch (seconds), which is monotonically
# increasing by wall-clock time. Anti-rollback in the bootloader only accepts
# version >= the highest it has booted, so an epoch version is always accepted
# and bumps the stored floor — no manual version bookkeeping needed.
#
# usage: sign_flash.sh <sign_tool> <bootloader.bin> <app.bin> <seed> <out.bin>
set -e
TOOL="$1"; BL="$2"; APP="$3"; SEED="$4"; OUT="$5"
V=$(date +%s)
echo "sign_flash: version=$V (epoch)"
"$TOOL" sign "$BL" "$APP" "$SEED" "$V" "$OUT"
