#!/bin/sh
# Flash a raw .bin to 0x08000000 via DFU.
#
# dfu-util returns non-zero ("Error during download get_status", exit 74) on the
# STM32 DfuSe ":leave" step: the download succeeds, then the device resets and
# detaches before dfu-util can read the final status. We therefore gate success
# on dfu-util's own "File downloaded successfully" line, not its exit code — a
# genuine download failure omits that line and still fails the build. (The
# "Invalid DFU suffix signature" warning is harmless: we flash a raw .bin.)
set -u
BIN="$1"
out=$(dfu-util -a 0 -s 0x08000000:leave -D "$BIN" 2>&1)
echo "$out"
echo "$out" | grep -q "File downloaded successfully"
