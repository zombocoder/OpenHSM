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
- ✅ PIN auth: login, retry counter, persistent lockout, SET_PIN (§16)
- ✅ Audit log: append-only, monotonic counter, chained-HMAC tamper-evidence (§17, partial — see below)
- ✅ PKCS#11 provider + OpenBao auto-unseal, incl. encrypted/PIN transport (§12-13,25)
- ✅ Network transport (openhsm-daemon, USB↔TCP) for containers/k8s (§21,23 partial)

---

## Remaining for production-ready

### A. Secure boot & firmware lifecycle (§8, §19)
- ⬜ **Signed firmware** (Ed25519): build-time signing + a verifying bootloader.
- ⬜ **Anti-rollback**: monotonic firmware version (option-byte / secure counter),
  reject downgrades.
- ⬜ **Secure firmware update** over the USB session: signed + version-checked.
- ⚠️ Enabling the STM32 ROM secure-boot / RDP boot chain is irreversible-ish and
  removes plain DFU; do the signing/verify infrastructure first (safe), gate the
  ROM enablement for a provisioning/sacrificial board.

### B. TrustZone isolation (§7)
- ⬜ Split into Secure / Non-secure worlds: keys, KEK, crypto, PIN, audit,
  monotonic counters in Secure; USB/parsing/buffers in Non-secure; NSC veneers.
- ⚠️ Requires setting `TZEN` option byte (hard to undo) and a two-image build.
- This is what makes the KEK actually confidential (closes the §6/§10 caveat).

### C. Tamper protection (§18)
- ⬜ Hardware: TAMP pins, voltage/clock anomaly detection, brownout (PVD), backup-
  domain tamper → zeroize session keys / KEK / optionally secure storage.
- ⬜ Software: debug lock state, memory zeroization on tamper, active-tamper response.

### D. Manufacturing security (§22) ⚠️ mostly irreversible
- ⬜ RDP level 2 (readout protection) — **disables DFU/JTAG permanently**.
- ⬜ Disable SWD/JTAG.
- ⬜ Unique device identity + provisioned device secret (real HUK root, not
  UID-derived) → makes the KEK secret.
- ⬜ Inject device certificate (enables authenticated handshake, kills MITM).

### E. Key store / audit durability & correctness
- 🟡 **Durable audit log**: persist the full entry stream (dedicated flash log
  region / external sink), not just the monotonic counter (today entries are a
  RAM ring; only the counter survives reboot).
- 🟡 **Store capacity**: `HSM_MAX_OBJECTS=8` (FIND response must fit one message);
  paginate FIND and/or grow the store for more objects.
- ⬜ **Wear levelling** for the single-page store under heavy key churn.
- ⬜ **RTC / trusted time** for real audit timestamps (currently seq-ordered only).
- ⬜ **Monotonic anti-replay counters** hardened against power-loss races.

### F. Authentication completeness (§16)
- ⬜ **C_InitPIN / "no PIN until provisioned"**: ship with no default PIN, require
  first-use provisioning (today `123456` is baked in).
- ⬜ **Per-session login binding**: auth is global per power cycle; bind it to the
  secure session and clear on close/timeout.
- ⬜ Optional: challenge-response / hardware admin token.
- ⬜ Authenticated session handshake (device cert) — depends on D.

### G. PKCS#11 provider robustness (host, production-relevant)
- ⬜ **NULL-safety**: fill all unimplemented `CK_FUNCTION_LIST` slots with stubs
  returning `CKR_FUNCTION_NOT_SUPPORTED` (a consumer calling a NULL slot crashes).
- ⬜ **Thread safety**: honor `CKF_OS_LOCKING_OK` / add a mutex around the single
  transport (Vault/OpenBao are multi-threaded).
- ⬜ `C_DestroyObject` (device DELETE exists), `C_Verify`, multi-part crypto
  (`*Update`/`*Final`), `C_WrapKey`/`C_UnwrapKey`, fuller `C_GetAttributeValue`.

### H. Reliability & quality
- ⬜ **Watchdog** (IWDG) + safe recovery; brownout reset handling.
- ⬜ **Fuzz the packet parser** (host-driven) for the USB command surface.
- ⬜ **Performance benchmarks** vs §20 targets (AES-GCM >100/s, HMAC >500/s,
  unseal <3 s) — measure on hardware.
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
