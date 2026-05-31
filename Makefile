# OpenHSM top-level build orchestrator.
#
# Thin wrapper over the firmware (cross, CMake+arm-none-eabi) and host (CMake)
# builds. Dependencies are git submodules under firmware/vendor/.
#
#   make deps       fetch/sync vendored SDK submodules
#   make firmware   build the STM32U585 firmware (-> build/openhsm.{elf,bin,hex})
#   make host       build the host test client (openhsm-ping)
#   make cli        build the maintenance/debug CLI (openhsm-cli)
#   make all        firmware + host (default)
#   make flash      program the board over DFU (hold BOOT0, tap RESET first)
#   make ping       run the host test client against a running board
#   make clean      remove build directories
#   make distclean  clean + deinit submodules
#
# Override the build type with BUILD_TYPE=Release (default: Debug).

BUILD_TYPE ?= Debug

FW_DIR     := firmware
FW_BUILD   := $(FW_DIR)/build
HOST_DIR   := host/tools/openhsm-ping
HOST_BUILD := $(HOST_DIR)/build
CLI_DIR    := host/tools/openhsm-cli
CLI_BUILD  := $(CLI_DIR)/build

# A sentinel file that exists only once submodules are checked out.
DEPS_SENTINEL := $(FW_DIR)/vendor/cmsis_core/CMSIS/Core/Include/core_cm33.h

.PHONY: all firmware host cli flash ping clean distclean deps help

all: firmware host

# --- dependencies (git submodules) ----------------------------------------
deps:
	git submodule update --init --recursive

$(DEPS_SENTINEL):
	@echo "Vendored SDK missing; fetching submodules..."
	git submodule update --init --recursive

# --- firmware ---------------------------------------------------------------
firmware: $(DEPS_SENTINEL)
	cmake -S $(FW_DIR) -B $(FW_BUILD) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)
	cmake --build $(FW_BUILD) -j

flash: firmware
	cmake --build $(FW_BUILD) --target flash

# --- host tools -------------------------------------------------------------
host:
	cmake -S $(HOST_DIR) -B $(HOST_BUILD)
	cmake --build $(HOST_BUILD) -j

ping: host
	$(HOST_BUILD)/openhsm-ping

cli:
	cmake -S $(CLI_DIR) -B $(CLI_BUILD)
	cmake --build $(CLI_BUILD) -j

# --- housekeeping -----------------------------------------------------------
clean:
	rm -rf $(FW_BUILD) $(HOST_BUILD) $(CLI_BUILD) $(FW_DIR)/tools/gen_vectors

distclean: clean
	-git submodule deinit -f --all

help:
	@sed -n 's/^#   //p' $(firstword $(MAKEFILE_LIST))
