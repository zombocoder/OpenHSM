# OpenHSM Roadmap — toward production-ready firmware

Status as of 2026-05-31. The **functional** production goal (spec §25 — auto-
unseal OpenBao/Vault via a custom PKCS#11 provider over a physical STM32U585,
without exposing plaintext keys) is **achieved and verified on hardware**. What
remains is mostly the **hardware-security / secure-lifecycle** half of the spec
and robustness hardening.

Legend: ✅ done · 🟡 partial · ⬜ not started · ⚠️ irreversible / can brick the
DFU-flashable dev board (do last, or on a sacrificial board).

---

## Done (verified on hardware)

- ✅ USB vendor transport + multi-packet framing (§5)
- ✅ Encrypted session: X25519 → HKDF → AES-256-GCM, anti-replay (§6)
- ✅ Crypto: AES-256-GCM (HW), SHA-256/HMAC/HKDF (sw), Ed25519/X25519, TRNG, KAT self-test (§11)
- ✅ Encrypted key store in flash, HUK→KEK→objects, wrapped-export-only (§9-10)
- ✅ Key ops: GENERATE/FIND/GET/DELETE, SIGN, HMAC, GET_PUBLIC, WRAP/UNWRAP, ENCRYPT/DECRYPT (§11,15)
- ✅ PIN auth: ships unprovisioned (C_InitPIN), per-session login binding, retry counter, lockout, SET_PIN (§16)
- ✅ Audit log: append-only, monotonic counter, chained-HMAC tamper-evidence, durable in flash (§17)
- ✅ PKCS#11 provider + OpenBao auto-unseal, incl. encrypted/PIN transport (§12-13,25)
- ✅ Network transport (openhsm-daemon, USB↔TCP) for containers/k8s (§21,23 partial)
- ✅ Tooling: openhsm-cli (maintenance/debug + `bench`/`storage`), openhsm-ssh-agent
  (SSH login with a device-held Ed25519 key — verified end-to-end into a container)
- ✅ Secure boot: stage-1 Ed25519-verifying bootloader + anti-rollback (§8,§19;
  software chain — HW root of trust / RDP-2 deferred to D)
- ✅ NIST P-256 ECDSA via HW PKA (key type, GET_PUBLIC 64-B point, sign a digest,
  KAT in self-test) + PKCS#11 CKM_ECDSA/CKM_EC_KEY_PAIR_GEN/CKA_EC_POINT — unlocks
  stock `ssh -I` and TLS-client-cert (mTLS) keys. Verified: openssl independently
  verified an HSM PKCS#11 signature. GET_PUBLIC is now an OPEN command (public
  keys aren't secret; PKCS#11 clients read CKA_EC_POINT before login).

---

## Remaining for production-ready

### A. Secure boot & firmware lifecycle (§8, §19)
- ✅ **Signed firmware** (Ed25519): a stage-1 bootloader at 0x08000000 verifies an
  Ed25519 signature over the app (relinked to 0x08012000) against a baked-in vendor
  public key before jumping; host `tools/sign_image` (libsodium) signs and assembles
  the combined image, `make flash` flashes it. Verified on hardware: valid image
  boots; tampered byte and wrong-key images are both rejected (no boot); BOOT0+DFU
  recovers.
- ✅ **Anti-rollback**: monotonic version in the header; bootloader stores a
  high-water version in a free bank-2 page (124) and refuses anything below it.
  `make flash` auto-versions with the Unix epoch (tools/sign_flash.sh) so it is
  always monotonic. Verified on hardware: v1→v2 boot, v1 downgrade rejected.
- ✅ **Secure firmware update** over the USB session — gated FW_UPDATE_BEGIN/DATA/
  APPLY (0x0060-62) stream a signed app image into a bank-2 staging region; the
  bootloader verifies it (Ed25519 + anti-rollback) and applies it to the bank-1
  app region via a RAM-resident flash routine (cross-bank rule), then boots.
  `openhsm-cli fwupdate openhsm_signed.bin`. Power-loss-safe (control flag cleared
  only after programming → interrupted apply retries from staging). Verified on
  hardware: fw 0.1→0.2 pushed over USB **with no DFU**; old-version and
  tampered-byte images both rejected (device keeps the running app); keys persist.
  Limit: the bootloader itself is not self-updatable (BL changes still via DFU).
- ⚠️ **Hardware root of trust** (RDP-2 + WRP on the bootloader, disable DFU) is the
  irreversible manufacturing step (ROADMAP D) — NOT done here, so an attacker who
  can DFU-flash can still replace the bootloader itself. The signing/verify
  infrastructure above is the safe, reversible prerequisite.

### B. TrustZone isolation (§7)
- ⬜ Split into Secure / Non-secure worlds: keys, KEK, crypto, PIN, audit,
  monotonic counters in Secure; USB/parsing/buffers in Non-secure; NSC veneers.
- ⚠️ Requires setting `TZEN` option byte (hard to undo) and a two-image build.
- This is what makes the KEK actually confidential (closes the §6/§10 caveat).
- **DEFERRED (2026-05-31):** not safe on the current single, DFU-only board (no
  debugger). Enabling `TZEN` boots Secure-first; any SAU/GTZC/secure-vector
  misconfig faults at boot with no debugger to diagnose, and reverting `TZEN`
  is an RDP regression that **mass-erases** flash (store + keys) on every failed
  iteration. Do this on a sacrificial board with SWD attached, or once a
  debugger is available.

### C. Tamper protection (§18)
- ✅ **Tamper response** (RAM-secret zeroization): `HSM_Tamper_Trip()` audit-logs
  `HSM_EV_TAMPER`, zeroizes the in-RAM KEK (so every stored key becomes unusable),
  and drops all secure sessions (zeroizes per-session transport keys + login).
  Latched until the next boot, where `HSM_KeyStore_Init` re-derives the KEK from
  the hardware HUK+UID and clears the latch — i.e. a *runtime lockdown*, power-cycle
  recovers. Triggers: the **PVD/brownout** detector (real) and a gated
  **`HSM_CMD_TAMPER_TEST`** diagnostic (`openhsm-cli tamper-test`, reproducible
  without a bench PSU). The trip is queued, never run in ISR/in-line: the PVD ISR
  and command path set a flag serviced from a safe context (main loop / after the
  encrypted ACK is built), so the audit-log flash write never runs in interrupt
  context and the ACK still reaches the host. Verified on hardware via `tamper-test`:
  audit shows TAMPER, subsequent key ops fail (not authorized), power-cycle restores.
- ⬜ Real analog **PVD/BOR threshold** trip needs a variable bench supply to dip VDD;
  the response path is proven via `tamper-test` (shared code), the PVD wiring is in.
- ⬜ **Debug-lock detection** (refuse / zeroize when a debugger is attached) — best
  tested with the incoming SWD programmer (attach → expect tamper); not yet wired.
- ⬜ Backup-domain TAMP pins / persistent secure-storage wipe → ties into RDP-2 (D).

### D. Manufacturing security (§22) ⚠️ mostly irreversible
- ⬜ RDP level 2 (readout protection) — **disables DFU/JTAG permanently**.
- ⬜ Disable SWD/JTAG.
- ⬜ Unique device identity + provisioned device secret (real HUK root, not
  UID-derived) → makes the KEK secret.
- ⬜ Inject device certificate (enables authenticated handshake, kills MITM).

### E. Key store / audit durability & correctness
- ✅ **Durable audit log**: entries persist to a 2-page bank-2 flash ring
  (pages 125-126, 1024 × 16-byte entries), appended one quad-word at a time;
  on returning to a page we erase only that page, so a rolling window of the
  ~512-1024 most recent entries always survives (no erase-everything sawtooth).
  At boot the ring is scanned to recover the chain tail (prev_mac) + write
  position and rebuild the readout ring. Verified on hardware: ~2400 events
  (>2 ring laps via `bench`) then a reboot — recent entries, the HMAC chain and
  the monotonic seq all survive cleanly. Every SIGN/HMAC/WRAP/UNWRAP/ENCRYPT/
  DECRYPT/AUTH/KEYGEN/KEYDEL/SET_PIN is logged; per-op flash write costs ~25%
  throughput (bench still PASS) and a page erase ~every 512 events.
  `GET_AUDIT_LOG` is **paginated** (`offset`/`total`/`next_offset`) and reads
  straight from flash, sorted oldest-first by seq — `openhsm-cli audit [n|all]`
  walks the pages, so the full durable log (verified: 805 entries, strictly
  monotonic, no boundary dups) is readable, not just the last ~31.
  Host-side chain verification (auditor-holding-the-key model): gated
  `GET_AUDIT_KEY` (0x0052) exports the 32-byte HMAC key over the encrypted
  session; `openhsm-cli audit-verify` fetches the key + the full durable log and
  recomputes each entry's `HMAC(key, prev_mac‖seq‖event‖arg)[0:8]`, checking it
  chains to its predecessor. Contiguous-seq links must match (a mismatch = the
  log was altered/reordered/truncated); seq gaps are expected boundaries
  (rolling-window eviction or the pre-reboot tail) and reset the anchor. Reports
  links-verified / boundaries / TAMPER-count and exits non-zero on any break.
  Remaining: optionally persist only security events (not every crypto op) to cut
  flash wear.
- ✅ **Store capacity**: `HSM_MAX_OBJECTS=32`, `FIND_OBJECT` paged
  (`offset`/`total`/`next_offset`), `GET_STORAGE` reports fill. The 8 KB page
  physically holds ~50 slots; raising the limit further is a one-line change.
- ⬜ **Multi-page store** to exceed ~50 objects (needs a second flash region).
- ⬜ **Wear levelling** for the single-page store under heavy key churn.
- ⬜ **RTC / trusted time** for real audit timestamps (currently seq-ordered only).
- ⬜ **Monotonic anti-replay counters** hardened against power-loss races.

### F. Authentication completeness (§16)
- ✅ **C_InitPIN / "no PIN until provisioned"**: the device now ships
  UNPROVISIONED (fresh store has `pin_set=0`, no default PIN) — AUTH and every
  gated command are refused until `INIT_PIN` (0x0015) sets the first PIN (no old
  PIN needed; rejected once provisioned). `GET_INFO` reports `HSM_INFO_PIN_SET`;
  PKCS#11 `C_InitPIN` is wired and `C_GetTokenInfo` clears
  `CKF_TOKEN_INITIALIZED|CKF_USER_PIN_INITIALIZED` until provisioned (0x40d after).
  `openhsm-cli initpin <pin>`. Verified on hardware end-to-end.
- ✅ **Per-session login binding**: AUTH is now bound to the secure session
  (`session_t.authenticated`), not a power-cycle-global flag — a login on one
  session never unlocks another, and closing a session drops its login.
  `HSM_ProcessPlaintext` takes an `int *auth` (the session's flag, or a separate
  global for the legacy plaintext path). Verified on hardware: a fresh session
  is denied gated ops until it AUTHs, and a new session after a logged-in one
  closed is still denied (no leak). No client changes (they already AUTH
  in-session). Remaining: explicit device-side C_Logout, idle timeout.
- ⬜ Optional: challenge-response / hardware admin token.
- ⬜ Authenticated session handshake (device cert) — depends on D.

### G. PKCS#11 provider robustness (host, production-relevant)
- ✅ **Thread safety**: a global mutex serializes every device exchange (the
  single secure-session transport) and the session table — Vault/OpenBao are
  multi-threaded. (Library does native locking regardless of `CKF_OS_LOCKING_OK`.)
- ✅ `C_DestroyObject` (maps to device DELETE; bad handle → `CKR_OBJECT_HANDLE_INVALID`),
  `C_VerifyInit`/`C_Verify` (HMAC recompute + constant-time compare; EdDSA via
  local libsodium public-key check). Init/NULL-arg guards added across crypto ops.
- ✅ **NULL-safety**: every one of the 68 `CK_FUNCTION_LIST` slots is now wired —
  unimplemented ones are explicit stubs returning `CKR_FUNCTION_NOT_SUPPORTED`
  (legacy `C_GetFunctionStatus`/`C_CancelFunction` → `CKR_FUNCTION_NOT_PARALLEL`),
  so a consumer can never jump through a NULL pointer. Init/NULL-arg guards on ops.
- ✅ **Multi-part crypto** (`*Update`/`*Final` for Encrypt/Decrypt/Sign/Verify):
  the device is single-shot, so parts accumulate host-side and one command is
  issued at `*Final` (verified multi-part == single-shot). `C_WrapKey`/`C_UnwrapKey`
  map to device WRAP/UNWRAP.
- ⬜ Fuller `C_GetAttributeValue` (e.g. `CKA_EC_POINT` for public keys); true
  streaming multi-part beyond one device message; `C_DeriveKey` (X25519 ECDH).

### H. Reliability & quality
- ⬜ **Watchdog** (IWDG) + safe recovery; brownout reset handling.
- ⬜ **Fuzz the packet parser** (host-driven) for the USB command surface.
- 🟡 **Performance benchmarks** vs §20 targets — `openhsm-cli bench` measures
  throughput over the secure session. On hardware: **AES-256-GCM ≈ 850 ops/s**
  (target >100), **HMAC-SHA256 ≈ 620 ops/s** (target >500) — both PASS. HMAC is
  software SHA-256 so it trails the HW AES path. Unseal: the HSM's per-unseal cost
  is one AES-GCM (~1.2 ms); the end-to-end <3 s is OpenBao-startup bound (measure
  with `make -C host/openbao`). Remaining: capture the full OpenBao unseal number.
- ⬜ **Automated HW-in-the-loop CI** (flash + run the host test suite).
- ⬜ Constant-time review of comparisons / no secret-dependent branches.

### I. Deployment (§21, §23)
- 🟡 **openhsm-daemon**: USB↔TCP bridge done (one client at a time, no TLS to the
  daemon). For prod: multi-client/session multiplexing, TLS or mTLS on the daemon
  socket, reconnect, metrics, systemd unit.
- ⬜ **Docker/Kubernetes**: image builds; finish the module `.so` build stage;
  Helm chart / DaemonSet for the HSM node + device plugin; example pod.
- ⬜ FreeBSD host validation (primary target OS per spec §4).

---

## Suggested next milestones (safe → risky)

1. **Provider robustness (G)** — NULL-safety + mutex + C_DestroyObject. Low risk,
   high interop value; no firmware reflash.
2. **Durable audit + per-session login + C_InitPIN (E/F)** — firmware, no brick risk.
3. **Secure-boot signing infrastructure (A, software parts)** — sign + verify in a
   second-stage bootloader; defer the irreversible ROM enablement.
4. **TrustZone split (B)** — large; makes the KEK truly secret. ⚠️ TZEN.
5. **Tamper (C)** then **Manufacturing/RDP (D)** — ⚠️ do on hardware you can
   afford to lock; this is the final lockdown before shipping a unit.
