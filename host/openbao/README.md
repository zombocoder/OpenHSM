# OpenBao auto-unseal with the OpenHSM PKCS#11 provider

End-to-end demo: OpenBao (the OSS Vault fork) auto-unseals using a physical
STM32U585 OpenHSM appliance through `libopenhsm_pkcs11`.

## Prerequisites

- OpenHSM firmware running on the board (not in DFU), default PIN `123456`.
- The PKCS#11 module built: `host/pkcs11/build/libopenhsm_pkcs11.dylib`.
- An OpenBao binary **built with PKCS#11 support** — the Homebrew binary has it
  disabled (`this build of OpenBao has PKCS#11 disabled`). Build from source:
  ```sh
  git clone --depth 1 https://github.com/openbao/openbao
  cd openbao && CGO_ENABLED=1 go build -tags hsm -o bao-hsm .
  ```

## Steps

1. **Provision the seal + HMAC keys** (the builtin seal does not auto-generate
   them even with `generate_key=true`; it expects them to pre-exist):
   ```sh
   cd ../pkcs11/build
   ./p11provision ./libopenhsm_pkcs11.dylib 123456 openbao-seal openbao-hmac
   ```
   Creates an AES-256 key `openbao-seal` (ENCRYPT|DECRYPT) and a generic-secret
   `openbao-hmac` (SIGN|VERIFY) inside the HSM.

2. **Start the server** (see `config.hcl` — `seal "pkcs11"` points at the
   module, slot 0, PIN, `CKM_AES_GCM` + `CKM_SHA256_HMAC`):
   ```sh
   bao-hsm server -config=config.hcl
   ```

3. **Initialize** (recovery keys are returned; the seal key stays in the HSM):
   ```sh
   export BAO_ADDR=http://127.0.0.1:8200
   bao-hsm operator init -recovery-shares=1 -recovery-threshold=1
   ```

4. **Auto-unseal**: restart the server — no manual unseal keys needed. The root
   key is decrypted by the HSM (`C_Decrypt`, AES-256-GCM) over the encrypted
   USB session:
   ```sh
   bao-hsm status   # Sealed: false, "unsealed with stored key"
   ```

## What this proves

- `C_Initialize → GetSlotList → OpenSession → Login` (device PIN AUTH over the
  encrypted X25519/AES-GCM session) → `FindObjects` (seal/HMAC keys by label) →
  `EncryptInit/Encrypt` (init) and `DecryptInit/Decrypt` (unseal).
- The AES-256 seal key never leaves the device; OpenBao only exchanges
  ciphertext with the HSM.

Set `OPENHSM_DEBUG=1` in the server environment to trace the module's PKCS#11
calls on stderr.

## Web UI

The Homebrew/HSM build has no UI; build and embed it from source, then rebuild
with both tags. On Node 23 two workarounds are needed:

```sh
cd openbao/ui
COREPACK_INTEGRITY_KEYS=0 pnpm install         # corepack can't verify pinned pnpm
node_modules/.bin/ember build                  # DEV build: skips CleanCSS, which
                                               # crashes on node 23 (util.isRegExp)
# outputs to ../http/web_ui (ui/.ember-cli output-path)
cd .. && CGO_ENABLED=1 go build -tags "hsm ui" -o bao-hsm .
```

Set `ui = true` in `config.hcl`, start the server, and open
<http://127.0.0.1:8200/ui/> — log in with the root token from `init.json`.
