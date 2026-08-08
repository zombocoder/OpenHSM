# OpenHSM top-level build orchestrator.
#
# Thin wrapper over the firmware (cross, CMake+arm-none-eabi) and host (CMake)
# builds. Dependencies are git submodules under firmware/vendor/.
#
#   make deps       fetch/sync vendored SDK submodules
#   make sign-tool  build the host secure-boot signing tool (firmware/tools/sign_image)
#   make firmware   build the STM32U585 firmware (-> build/openhsm.{elf,bin,hex})
#   make host       build the host test client (openhsm-ping)
#   make cli        build the maintenance/debug CLI (openhsm-cli)
#   make ssh-agent  build the SSH agent (openhsm-ssh-agent)
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
AGENT_DIR  := host/tools/openhsm-ssh-agent
AGENT_BUILD := $(AGENT_DIR)/build

# A sentinel file that exists only once submodules are checked out.
DEPS_SENTINEL := $(FW_DIR)/vendor/cmsis_core/CMSIS/Core/Include/core_cm33.h

# Host secure-boot signing tool. The firmware CMake project cross-compiles with
# arm-none-eabi, so it cannot build this native binary itself — it just invokes
# it from the `signed`/`keygen` targets. Build it here with the host compiler.
SIGN_TOOL     := $(FW_DIR)/tools/sign_image
SIGN_TOOL_SRC := $(FW_DIR)/tools/sign_image.c
HOSTCC        ?= cc
SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS   := $(shell pkg-config --libs libsodium 2>/dev/null || echo -lsodium)

.PHONY: all firmware sign-tool host cli ssh-agent flash ping clean distclean deps help

all: firmware host

# --- dependencies (git submodules) ----------------------------------------
deps:
	git submodule update --init --recursive

$(DEPS_SENTINEL):
	@echo "Vendored SDK missing; fetching submodules..."
	git submodule update --init --recursive

# --- host signing tool ------------------------------------------------------
# Must exist before the firmware build: CMake's `signed` target shells out to it
# to sign the combined bootloader+app image.
sign-tool: $(SIGN_TOOL)

$(SIGN_TOOL): $(SIGN_TOOL_SRC) $(FW_DIR)/bootloader/image_header.h
	@echo "Building host sign tool -> $@"
	$(HOSTCC) -O2 -Wall -Wextra $(SODIUM_CFLAGS) -o $@ $(SIGN_TOOL_SRC) $(SODIUM_LIBS)

# --- firmware ---------------------------------------------------------------
firmware: $(DEPS_SENTINEL) $(SIGN_TOOL)
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

ssh-agent:
	cmake -S $(AGENT_DIR) -B $(AGENT_BUILD)
	cmake --build $(AGENT_BUILD) -j

# --- housekeeping -----------------------------------------------------------
clean:
	rm -rf $(FW_BUILD) $(HOST_BUILD) $(CLI_BUILD) $(AGENT_BUILD) $(FW_DIR)/tools/gen_vectors $(SIGN_TOOL)

distclean: clean
	-git submodule deinit -f --all

help:
	@sed -n 's/^#   //p' $(firstword $(MAKEFILE_LIST))
