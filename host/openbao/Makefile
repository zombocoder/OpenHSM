# OpenBao auto-unseal demo driven by the OpenHSM PKCS#11 provider.
#
# Quick start (board running firmware, not in DFU):
#   make build      # build the PKCS#11 module + provisioning tool
#   make provision  # create the seal + HMAC keys inside the HSM
#   make server     # run OpenBao in the foreground (Ctrl-C to stop)
#   # ...in another shell:
#   make init       # initialize (prints recovery key + root token -> init.json)
#   make status     # Sealed: false  (auto-unsealed by the HSM)
#
# Or the scripted end-to-end demo:
#   make demo       # provision + start + init + restart + show auto-unseal
#
# Override the OpenBao binary (must be built with PKCS#11: `-tags hsm`):
#   make server BAO=/path/to/bao-hsm

BAO       ?= /Users/zombocoder/dev/openbao-build/bao-hsm
PKCS11DIR := $(CURDIR)/../pkcs11
MODULE    := $(PKCS11DIR)/build/libopenhsm_pkcs11.dylib
PROVISION := $(PKCS11DIR)/build/p11provision
PIN       ?= 123456
export BAO_ADDR ?= http://127.0.0.1:8200

.PHONY: help build provision server server-bg debug-bg init status stop clean demo

help:
	@sed -n 's/^#   //p' $(firstword $(MAKEFILE_LIST))

# Build the provider module + helper tools (CMake).
build:
	cmake -S $(PKCS11DIR) -B $(PKCS11DIR)/build
	cmake --build $(PKCS11DIR)/build

# Create the AES-256 seal key + generic-secret HMAC key inside the HSM.
provision:
	$(PROVISION) $(MODULE) $(PIN) openbao-seal openbao-hmac

# Run the server in the foreground.
server:
	$(BAO) server -config=config.hcl

# Run the server in the background (logs to server.log).
server-bg:
	@$(BAO) server -config=config.hcl > server.log 2>&1 & echo "server pid $$!"
	@sleep 6; tail -n 15 server.log

# Background server with PKCS#11 call tracing on stderr.
debug-bg:
	@OPENHSM_DEBUG=1 $(BAO) server -config=config.hcl > server.log 2>&1 & echo "server pid $$!"
	@sleep 6; grep -E '\[p11\]|openhsm:|Auto Seal' server.log || true

# Initialize; saves recovery key + root token to init.json.
init:
	$(BAO) operator init -recovery-shares=1 -recovery-threshold=1 -format=json > init.json
	@echo "--> wrote init.json"; \
	 echo "    root token: $$(grep -o '\"root_token\":\"[^\"]*\"' init.json | cut -d'\"' -f4)"

status:
	$(BAO) status

stop:
	-@pkill -f 'bao server -config=config.hcl' 2>/dev/null && echo "stopped" || echo "not running"

clean: stop
	rm -rf data server.log server2.log init.json nohup.out

# Scripted end-to-end demo: provision, init, then prove auto-unseal on restart.
demo: clean
	@mkdir -p data
	@echo "== provisioning HSM keys =="; $(PROVISION) $(MODULE) $(PIN) openbao-seal openbao-hmac
	@echo "== starting server =="; $(BAO) server -config=config.hcl > server.log 2>&1 & sleep 6
	@echo "== init =="; $(BAO) operator init -recovery-shares=1 -recovery-threshold=1 -format=json > init.json; \
	  echo "   Sealed=$$($(BAO) status -format=json | grep -o '\"sealed\":[a-z]*' | cut -d: -f2)"
	@echo "== restart (auto-unseal test) =="; pkill -f 'bao server -config=config.hcl'; sleep 2; \
	  $(BAO) server -config=config.hcl > server2.log 2>&1 & sleep 7
	@echo "   Sealed after restart = $$($(BAO) status -format=json | grep -o '\"sealed\":[a-z]*' | cut -d: -f2)"
	@grep -i 'unsealed with stored key' server2.log && echo "== AUTO-UNSEAL OK ==" || echo "== check server2.log =="
	@echo "(server still running; 'make stop' to terminate)"
