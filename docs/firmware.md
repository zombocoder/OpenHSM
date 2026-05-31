# OpenHSM Firmware — Architecture & Protocol

STM32U585CIU6 firmware that turns the board into a USB HSM appliance: a
vendor-specific USB device speaking an encrypted command protocol, with an
on-device key store, hardware/software crypto, PIN authentication and an audit
log.

This document describes the device side. For the host stack (PKCS#11 provider,
daemon, OpenBao demo) see `host/`. For the remaining work toward production see
[ROADMAP.md](ROADMAP.md).

---

## 1. Hardware & build

- **MCU:** STM32U585CIU6 (Cortex-M33, 2 MB flash dual-bank, 768 KB SRAM, AES/PKA/
  HASH/TRNG accelerators, TrustZone-capable — currently run flat / non-secure).
- **Clock:** 160 MHz from HSI16→PLL (VOS range 1, 4 flash WS); USB clocked from
  HSI48 + CRS auto-trim — no external crystal needed.
- **Flash via DFU only** (no on-board debugger): hold BOOT0 high, tap RESET →
  `0483:df11 STM32 BOOTLOADER`; `make flash` runs `dfu-util`.
- **Build:** `make firmware` (CMake + arm-none-eabi-gcc). Dependencies (CMSIS,
  HAL, USB Device Library, Monocypher) are git submodules under
  `firmware/vendor/` (`make deps`). ROM ~53 KB, RAM ~19 KB.

---

## 2. Layered architecture

```
USB (EP1 bulk IN/OUT, vendor class)        src/usb/usbd_vendor.c, usbd_conf.c
        │   framed packets (multi-packet reassembly)
        ▼
Command dispatcher                          src/hsm/hsm_command.c
   ├── routing: encrypted envelope / session setup / plaintext
   ├── PIN-gated key operations
   └── audit logging
        │
        ├── Secure session  (X25519→HKDF→AES-256-GCM)   src/hsm/hsm_session.c
        ├── Key store       (HUK→KEK→objects in flash)  src/hsm/hsm_keystore.c
        │      └── flash    (bank-2 page, quad-word)     src/hsm/hsm_flash.c
        ├── Audit log       (append-only, chained MAC)   src/hsm/hsm_audit.c
        └── Crypto:  AES-GCM (HW)   src/crypto/hsm_aead.c
                     SHA/HMAC/HKDF (software)  src/crypto/hsm_hash.c
                     X25519, Ed25519 (Monocypher)  hsm_x25519.c / hsm_eddsa.c
                     TRNG (HW)   src/hsm/hsm_rng.c
                     KAT self-test   src/crypto/hsm_crypto.c
```

`main.c` brings up clocks, then `HSM_Rng_Init → HSM_Crypto_Init → HSM_Session_Init
→ HSM_KeyStore_Init → HSM_Audit_Init → MX_USB_Device_Init`, and services packets
from the main loop (`USBD_Vendor_Poll`) — heavy crypto runs in thread context,
not the USB ISR.

---

## 3. USB transport & framing

- Vendor-specific device, VID/PID `0483:5750` (development only — allocate your
  own for production). One interface, EP1 bulk OUT (host→device) and IN.
- A logical message = 16-byte header + payload, up to `HSM_MAX_MSG_PAYLOAD`
  (512 B). Messages larger than one 64-byte USB packet are reassembled using the
  header's `payload_length` and the terminating short packet.

### Packet header (16 bytes, little-endian)

| Off | Size | Field            | Notes                                      |
|----:|-----:|------------------|--------------------------------------------|
| 0   | 2    | `command`        | `hsm_command_t`                            |
| 2   | 2    | `flags`          | `HSM_FLAG_ENCRYPTED` (0x0001), `_RESPONSE` (0x8000) |
| 4   | 4    | `session_id`     | 0 outside a session                        |
| 8   | 4    | `counter`        | per-direction anti-replay counter          |
| 12  | 2    | `payload_length` | bytes following the header                 |
| 14  | 2    | `status`         | `hsm_status_t` (meaningful on responses)   |

---

## 4. Command set

| Code   | Command            | Auth | Notes |
|--------|--------------------|:----:|-------|
| 0x0001 | PING               | no   | echoes magic `0x4F48534D` |
| 0x0002 | GET_INFO           | no   | proto/fw version, 96-bit UID |
| 0x0003 | SELFTEST           | no   | crypto KAT (per-primitive results) |
| 0x0004 | ECHO               | no   | returns payload (test) |
| 0x0010 | OPEN_SESSION       | no   | X25519 handshake → session keys |
| 0x0011 | CLOSE_SESSION      | no   | zeroizes session keys |
| 0x0012 | AUTH               | no   | PIN login (retry counter / lockout) |
| 0x0013 | SESSION_DATA       | no   | outer cmd for an encrypted envelope |
| 0x0014 | SET_PIN            | no¹  | change PIN (old verified inside) |
| 0x0015 | INIT_PIN           | no   | set first PIN on an unprovisioned device |
| 0x0020 | GENERATE_KEY       | yes  | random key → encrypted object |
| 0x0023 | FIND_OBJECT        | no   | list object metadata (optional label) |
| 0x0024 | DELETE_OBJECT      | yes  | zeroize slot |
| 0x0025 | GET_OBJECT         | no   | one object's metadata |
| 0x0026 | GET_PUBLIC         | no   | public key of Ed25519/X25519 (32 B) or ECDSA P-256 (64 B X\|\|Y) |
| 0x0030 | HMAC               | yes  | HMAC-SHA256 with a stored key |
| 0x0031 | WRAP               | yes  | wrapped export (AES-256-GCM under wrap key) |
| 0x0032 | UNWRAP             | yes  | import a wrapped blob |
| 0x0033 | SIGN               | yes  | Ed25519 signature |
| 0x0040 | RANDOM             | no   | TRNG bytes |
| 0x0041 | ENCRYPT            | yes  | AES-256-GCM with a stored key |
| 0x0042 | DECRYPT            | yes  | AES-256-GCM decrypt + verify |
| 0x0050 | GET_AUDIT_LOG      | no   | recent audit entries |
| 0x0051 | GET_STORAGE        | no   | key-store capacity & fill level |
| 0x0021/0x0022 | IMPORT/EXPORT_WRAPPED | — | reserved (WRAP/UNWRAP used instead) |

¹ SET_PIN is self-authenticating (verifies the old PIN). "Auth: yes" commands
require a prior successful AUTH (login state is global per power cycle — see §8).

### Status codes
`OK`=0, `UNKNOWN_CMD`=1, `BAD_LENGTH`=2, `NOT_AUTHORIZED`=3, `NO_SESSION`=4,
`INVALID_PARAM`=5, `NOT_IMPLEMENTED`=6, `KEY_VERIFY`=7, `LOCKED`=8,
`STORE_FULL`=9 (no free object slot → PKCS#11 `CKR_DEVICE_MEMORY`), `INTERNAL`=0xFF.

---

## 5. Secure session

Unauthenticated ephemeral ECDH (confidentiality + integrity; device-identity /
MITM protection is a future milestone — see ROADMAP):

```
host → OPEN_SESSION { eph_pub_h(32) , nonce_h(32) }
dev  → { eph_pub_d(32) , nonce_d(32) } , session_id in header
both: shared = X25519(eph_priv, peer_pub)
      okm    = HKDF-SHA256(salt = nonce_h‖nonce_d, ikm = shared,
                           info = "OpenHSM/v1 session keys", 64)
      k_c2d  = okm[0..31]   k_d2c = okm[32..63]
```

Encrypted commands: outer command `SESSION_DATA`, flag `ENCRYPTED`, payload =
`ciphertext ‖ GCM-tag(16)`, AAD = the 16-byte outer header, AES-256-GCM, nonce =
`[dir | 0 0 0 | session_id(LE) | counter(LE)]` with a strictly-increasing
per-direction counter (anti-replay). The device decrypts the envelope, runs the
inner command as plaintext, and encrypts the response.

---

## 6. Key store & key hierarchy

```
Hardware Unique Key (HUK = HKDF(device UID))
        ↓
Key Encryption Key (KEK = HKDF(HUK))
        ↓
per-object: AES-256-GCM(KEK, random nonce, AAD = object metadata) → enc_key‖tag
```

- One 8 KB flash page (bank 2, `0x081FE000`) holds a `store_t`: header
  (magic/version, `next_id`, `next_seq`, PIN state, `audit_seq`) + up to
  `HSM_MAX_OBJECTS` (32) fixed 160-byte slots (16-byte aligned).

**Capacity.** Hard limit = **32 objects** (`HSM_MAX_OBJECTS`); the store occupies
5192 B of the 8 KB page (72 B header + 32×160 B slots). The page could
physically hold ~50 slots (`region_capacity`), so the configured 32 is the
active ceiling, not the flash. Query the live fill with `GET_STORAGE` (0x0051) —
returns used/max slots, slot size, region size, store bytes, and the region's
physical slot capacity; `openhsm-cli storage` formats it.

`FIND_OBJECT` is **paged**: a single 512 B response holds only ~9 records
(`hsm_find_resp_t` header + N×52 B `hsm_obj_info_t`), so the store can hold more
objects than one message. The request is `hsm_find_req_t {offset, max, [label]}`
(empty payload = page 0, no filter); the response header carries `count`
(this page), `total` (all matches) and `next_offset`. Clients loop, advancing
`offset` to `next_offset` until `next_offset == total`. `openhsm-cli list`, the
PKCS#11 provider's object cache, and the ping harness all page this way.
- Object types: AES-256, HMAC-SHA256, Ed25519, X25519, ECDSA P-256. Each slot stores
  immutable metadata (id, algorithm, capabilities, key_bits, exportable,
  auth_domain, created_seq, label) authenticated as the GCM AAD, then the
  mutable `usage_counter` (deliberately **outside** the AAD), nonce, tag, and
  encrypted key material.
- Persistence: RAM image → erase page → quad-word program → read-back verify.
  `GENERATE_KEY` self-verifies the stored blob by decrypting it back.
- Export policy: only `exportable` objects may be WRAPped out; **there is no
  plaintext-export command at all**.

**KEK confidentiality caveat:** the HUK is derived from the readable device UID
with an in-firmware KDF, so the KEK is recoverable by anyone who can read the
chip. "No plaintext key in flash" IS satisfied; KEK secrecy needs RDP-2 +
TrustZone + a provisioned device secret (ROADMAP §22).

---

## 7. Crypto backend

- **AES-256-GCM:** STM32 AES (HW). Key/IV loaded as big-endian words into
  KEYR/IVR (NOT affected by the DataType byte-swap, which only hits DINR/DOUTR);
  data/AAD/tag are byte arrays; IV counter word = `0x00000002`. Inputs are
  bounced through zero-padded aligned buffers so the HW's whole-word read of a
  partial final block doesn't pull in stale bytes.
- **SHA-256 / HMAC / HKDF:** software (`hsm_hash.c`). The STM32 HASH peripheral
  was dropped: it mishandled byte lengths that aren't a multiple of 4 and wedged
  on failure, which made the KEK non-reproducible.
- **X25519 / Ed25519 (RFC 8032):** Monocypher.
- **NIST P-256 ECDSA (secp256r1):** STM32U5 hardware **PKA** (`hsm_ecdsa_p256.c`) —
  public-key derivation (ECCMul), sign-a-digest (random TRNG nonce, r‖s), and a
  verify path used by the KAT. CKM_ECDSA via the PKCS#11 provider drives stock
  `ssh -I` and TLS client-cert (mTLS) use.
- **TRNG:** STM32 RNG (HW), clocked from HSI48.
- **Self-test:** `SELFTEST` runs known-answer tests for every primitive against
  vectors generated by libsodium (the same library the host uses).

---

## 8. Authentication & audit

- **PIN:** stored as `HMAC-SHA256(salt, PIN)` in the store header with a
  persistent retry counter (`HSM_PIN_MAX_TRIES`=8) and lockout. The device ships
  **unprovisioned** (no default PIN): AUTH and all gated commands are refused
  until `INIT_PIN` sets the first PIN (rejected once provisioned). `SET_PIN`
  changes it later (verifies old, fresh salt, resets the counter). Login state is
  **bound to the secure session** (`session_t.authenticated`) — a login on one
  session never unlocks another, and closing a session drops its login.
  `GET_INFO` advertises `HSM_INFO_PIN_SET` so hosts can tell an unprovisioned
  device (PKCS#11 clears `CKF_TOKEN_INITIALIZED`/`CKF_USER_PIN_INITIALIZED`).
- **Audit log:** append-only, **durable in a 2-page flash ring** (pages 125-126,
  up to 1024 × 16-byte entries) — entries are appended one quad-word at a time
  and a page is erased only when reused, so a rolling window of the most recent
  ~512-1024 events survives reboots. Each entry has a monotonic seq and an 8-byte
  HMAC chained over the previous entry (key = HKDF(KEK)) for tamper-evidence.
  Events: BOOT, AUTH_OK/FAIL, KEYGEN, KEYDEL, SIGN, HMAC, WRAP, UNWRAP, ENCRYPT,
  DECRYPT, SET_PIN. `GET_AUDIT_LOG` is paginated (reads from flash, oldest-first).
  Older history beyond the ring rolls off; the monotonic seq makes that evident.

---

## 9. Source map

| Path | Responsibility |
|------|----------------|
| `src/main.c` | clock/init, main loop |
| `src/stm32u5xx_it.c` | SysTick + USB IRQ |
| `src/usb/usbd_vendor.c` | vendor class, EP1 bulk, framing |
| `src/usb/usbd_conf.c` / `usbd_desc.c` / `usb_device.c` | USB glue/descriptors |
| `src/hsm/hsm_command.c` | dispatcher, routing, gating, audit hooks |
| `src/hsm/hsm_session.c` | secure session |
| `src/hsm/hsm_keystore.c` | objects, KEK, PIN, wrap/unwrap, encrypt/decrypt |
| `src/hsm/hsm_flash.c` | bank-2 page erase/program |
| `src/hsm/hsm_audit.c` | audit log |
| `src/hsm/hsm_rng.c` | TRNG |
| `src/crypto/hsm_aead.c` | AES-256-GCM (HW) |
| `src/crypto/hsm_hash.c` | SHA-256/HMAC/HKDF (software) |
| `src/crypto/hsm_eddsa.c` / `hsm_x25519.c` | Ed25519 / X25519 |
| `src/crypto/hsm_crypto.c` | crypto init + KAT self-test |
| `src/hsm/hsm_proto.h` | wire protocol (shared with the host) |
