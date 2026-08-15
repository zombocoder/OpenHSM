# OpenHSM top-level build orchestrator.
#
# Thin wrapper over the firmware (cross, CMake+arm-none-eabi) and host (CMake)
# builds. Dependencies are git submodules under firmware/vendor/.
#
#   make deps       fetch/sync vendored SDK submodules
#   make toolchain  fetch the pinned Arm GNU cross toolchain into firmware/toolchain/
#   make toolchain-check  verify arm-none-eabi-gcc is present and new enough
#   make sign-tool  build the host secure-boot signing tool (firmware/tools/sign_image)
#   make keygen     mint the vendor signing key + bootloader/vendor_pubkey.h (one-time)
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

# Cross toolchain. The firmware targets Arm GNU 15.x; older majors are rejected
# outright rather than left to fail deep inside the CMake build with an obscure
# message. A newer major is allowed but flagged, since it is untested here.
ARM_GCC_MAJOR ?= 15

# Pinned Arm GNU toolchain, fetched on demand by `make toolchain` into a
# gitignored directory inside the repo. Keeps every machine and CI on the exact
# same compiler with no sudo and no changes to the system PATH. Arm ships builds
# only for the hosts mapped below; everything else installs from the OS package
# manager instead (see README.md → Toolchain).
ARM_TC_VERSION ?= 15.2.rel1
ARM_TC_ROOT    ?= $(FW_DIR)/toolchain
ARM_TC_URLBASE := https://developer.arm.com/-/media/Files/downloads/gnu/$(ARM_TC_VERSION)/binrel

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    ARM_TC_HOST := darwin-arm64
  endif
else ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),x86_64)
    ARM_TC_HOST := x86_64
  else ifeq ($(UNAME_M),aarch64)
    ARM_TC_HOST := aarch64
  endif
endif

ARM_TC_NAME := arm-gnu-toolchain-$(ARM_TC_VERSION)-$(ARM_TC_HOST)-arm-none-eabi
ARM_TC_BIN  := $(ARM_TC_ROOT)/$(ARM_TC_NAME)/bin

# A fetched toolchain wins over whatever is in the system PATH, so a machine with
# a broken or wrong-version arm-none-eabi-gcc installed still builds correctly.
# Exporting PATH is what makes CMake's find_program() pick it up.
ifneq ($(wildcard $(ARM_TC_BIN)/arm-none-eabi-gcc),)
  export PATH := $(abspath $(ARM_TC_BIN)):$(PATH)
  ARM_CC ?= $(ARM_TC_BIN)/arm-none-eabi-gcc
endif
ARM_CC        ?= arm-none-eabi-gcc

# Host secure-boot signing tool. The firmware CMake project cross-compiles with
# arm-none-eabi, so it cannot build this native binary itself — it just invokes
# it from the `signed`/`keygen` targets. Build it here with the host compiler.
SIGN_TOOL     := $(FW_DIR)/tools/sign_image
SIGN_TOOL_SRC := $(FW_DIR)/tools/sign_image.c
HOSTCC        ?= cc
SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS   := $(shell pkg-config --libs libsodium 2>/dev/null || echo -lsodium)

# Vendor secure-boot identity. The seed is gitignored (never committed); the
# public key is a tracked header the bootloader bakes in at compile time. The
# two must stay in step — a bootloader carrying pubkey A will refuse an image
# signed by seed B.
VENDOR_SEED   := $(FW_DIR)/keys/vendor_ed25519.seed
VENDOR_PUBKEY := $(FW_DIR)/bootloader/vendor_pubkey.h

.PHONY: all firmware toolchain toolchain-check sign-tool keygen host cli ssh-agent flash ping clean distclean deps help

all: firmware host

# --- dependencies (git submodules) ----------------------------------------
deps:
	git submodule update --init --recursive

$(DEPS_SENTINEL):
	@echo "Vendored SDK missing; fetching submodules..."
	git submodule update --init --recursive

# --- cross toolchain --------------------------------------------------------
# Fetch and verify the pinned Arm GNU toolchain. Not wired into `firmware` as a
# dependency — downloading a compiler should be something you ask for, not a
# surprise mid-build.
#
# The download hangs off a real file target, not the phony alias, so make itself
# skips it once installed. (A `[ -x ... ] && exit 0` guard inside the recipe does
# NOT work: exit ends that recipe line's shell, and make runs the next line
# anyway — which re-downloads on every invocation.)
toolchain: $(ARM_TC_BIN)/arm-none-eabi-gcc
	@echo "toolchain: Arm GNU $(ARM_TC_VERSION) ready in $(ARM_TC_ROOT)"

$(ARM_TC_BIN)/arm-none-eabi-gcc:
	@if [ -z "$(ARM_TC_HOST)" ]; then \
	    echo "toolchain: Arm publishes no $(ARM_TC_VERSION) build for $(UNAME_S)/$(UNAME_M)."; \
	    echo "           Available: Linux x86_64, Linux aarch64, macOS arm64, Windows."; \
	    echo "           Install from your OS package manager instead — see README.md (Toolchain)."; \
	    exit 1; \
	fi
	@mkdir -p $(ARM_TC_ROOT)
	@echo "toolchain: fetching $(ARM_TC_NAME).tar.xz (~1 GB unpacked)"
	@cd $(ARM_TC_ROOT) && \
	  curl -fL --retry 3 -o "$(ARM_TC_NAME).tar.xz" "$(ARM_TC_URLBASE)/$(ARM_TC_NAME).tar.xz" && \
	  curl -fsSL -o "$(ARM_TC_NAME).tar.xz.sha256" "$(ARM_TC_URLBASE)/$(ARM_TC_NAME).tar.xz.sha256asc" && \
	  if command -v sha256sum >/dev/null 2>&1; then \
	      sha256sum -c "$(ARM_TC_NAME).tar.xz.sha256"; \
	  else \
	      shasum -a 256 -c "$(ARM_TC_NAME).tar.xz.sha256"; \
	  fi && \
	  echo "toolchain: checksum verified, extracting..." && \
	  tar -xf "$(ARM_TC_NAME).tar.xz" && \
	  rm -f "$(ARM_TC_NAME).tar.xz" "$(ARM_TC_NAME).tar.xz.sha256"
	@rm -f $(FW_BUILD)/CMakeCache.txt   # stale: cached the previous compiler path
	@echo "toolchain: installed -> $(ARM_TC_BIN)"
	@echo "toolchain: 'make firmware' will now use it automatically."

# Gate the firmware build on a present, new-enough arm-none-eabi-gcc. Only the
# firmware needs it; the host tools build with the native compiler.
toolchain-check:
	@command -v $(ARM_CC) >/dev/null 2>&1 || { \
	    echo "toolchain: '$(ARM_CC)' not found in PATH."; \
	    echo "           Run 'make toolchain' to fetch the pinned Arm GNU $(ARM_TC_VERSION),"; \
	    echo "           install it from your OS package manager (see README.md → Toolchain),"; \
	    echo "           or point ARM_CC=/path/to/arm-none-eabi-gcc at an existing install."; \
	    exit 1; }
	@v=`$(ARM_CC) -dumpversion`; major=$${v%%.*}; \
	 if [ "$$major" -lt "$(ARM_GCC_MAJOR)" ]; then \
	    echo "toolchain: $(ARM_CC) is $$v, but Arm GNU $(ARM_GCC_MAJOR).x or newer is required."; \
	    echo "           Override with ARM_GCC_MAJOR=$$major to build anyway."; \
	    exit 1; \
	 elif [ "$$major" -gt "$(ARM_GCC_MAJOR)" ]; then \
	    echo "toolchain: $(ARM_CC) $$v (newer than the tested $(ARM_GCC_MAJOR).x — proceeding)"; \
	 else \
	    echo "toolchain: $(ARM_CC) $$v"; \
	 fi

# --- host signing tool ------------------------------------------------------
# Must exist before the firmware build: CMake's `signed` target shells out to it
# to sign the combined bootloader+app image.
sign-tool: $(SIGN_TOOL)

$(SIGN_TOOL): $(SIGN_TOOL_SRC) $(FW_DIR)/bootloader/image_header.h
	@echo "Building host sign tool -> $@"
	$(HOSTCC) -O2 -Wall -Wextra $(SODIUM_CFLAGS) -o $@ $(SIGN_TOOL_SRC) $(SODIUM_LIBS)

# --- vendor signing key -----------------------------------------------------
# One-time: mint the vendor Ed25519 identity. Writes the 32-byte seed (private,
# gitignored) and regenerates the tracked vendor_pubkey.h the bootloader embeds.
#
# Refuses to clobber an existing seed. The seed is never committed, so an
# overwrite is unrecoverable, and a new identity orphans every device already
# flashed with a bootloader carrying the old public key. Pass FORCE=1 to mean it.
keygen: $(SIGN_TOOL)
	@if [ -e "$(VENDOR_SEED)" ] && [ "$(FORCE)" != "1" ]; then \
	    echo "keygen: $(VENDOR_SEED) already exists — refusing to overwrite."; \
	    echo "        The seed is not in git; replacing it is unrecoverable and"; \
	    echo "        invalidates devices flashed with the old vendor key."; \
	    echo "        Re-run as 'make keygen FORCE=1' to mint a new identity."; \
	    exit 1; \
	fi
	@mkdir -p $(dir $(VENDOR_SEED))
	$(SIGN_TOOL) keygen $(VENDOR_SEED) $(VENDOR_PUBKEY)

# --- firmware ---------------------------------------------------------------
firmware: toolchain-check $(DEPS_SENTINEL) $(SIGN_TOOL)
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
