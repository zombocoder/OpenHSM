# openhsm-cli

Maintenance & debugging CLI for OpenHSM devices. Works **locally over USB** or
**remotely via openhsm-daemon** (for devices on another host / in Kubernetes).
It reuses the shared transport, so the encrypted X25519/AES-GCM session and PIN
login are handled automatically (gated commands auto-login with `--pin`).

## Build
```sh
cmake -S host/tools/openhsm-cli -B host/tools/openhsm-cli/build
cmake --build host/tools/openhsm-cli/build
```

## Usage
```sh
openhsm-cli [--addr host:port] [--pin PIN] <command> [args]
```
- `--addr host:port` (or env `OPENHSM_ADDR`) → talk to an openhsm-daemon instead
  of direct USB. `OPENHSM_DEBUG=1` traces the session.

| Command | Description |
|---------|-------------|
| `ping` | liveness check |
| `info` | proto/fw version + device serial |
| `selftest` | crypto known-answer self-test |
| `storage` | key-store capacity & fill (used/max slots, region bytes) |
| `random <n>` | `n` random bytes (hex) |
| `list` | list key objects (id, type, caps, usage, label) |
| `get <id>` | one object's metadata |
| `pubkey <id>` | public key of an Ed25519/X25519 object |
| `gen <type> <label> [caps]` | type `aes\|hmac\|ed25519\|x25519`; caps `enc,dec,sign,verify,wrap,unwrap,derive,exp` |
| `del <id>` | delete an object |
| `sign <id> <msg>` | Ed25519 signature |
| `hmac <id> <msg>` | HMAC-SHA256 |
| `encrypt <id> <hex>` | AES-256-GCM → prints `nonce` and `ct+tag` |
| `decrypt <id> <noncehex> <ct+taghex>` | AES-256-GCM decrypt |
| `wrap <wrapid> <targetid>` | wrapped export (blob hex) |
| `unwrap <wrapid> <label> <blobhex>` | import a wrap blob |
| `audit [n]` | recent audit-log entries |
| `initpin <pin>` | set the first PIN on a fresh (unprovisioned) device |
| `setpin <old> <new>` | change the login PIN |
| `bench [seconds] [payload]` | throughput benchmark (AES-GCM, HMAC) vs spec §20 targets |

## Examples
```sh
openhsm-cli info
openhsm-cli gen ed25519 my-signing-key sign
openhsm-cli sign 3 "hello"
openhsm-cli list
# remote maintenance through a daemon on the HSM node:
openhsm-cli --addr 10.0.0.5:11700 selftest
```
