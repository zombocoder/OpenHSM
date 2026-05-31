# openhsm-ssh-agent

An [ssh-agent](https://man.openbsd.org/ssh-agent) that keeps your SSH private
key **inside the OpenHSM device**. It advertises the device's Ed25519 public key
to OpenSSH and forwards every signing request to the HSM (`HSM_CMD_SIGN`) — the
private key never touches the host.

OpenSSH's own PKCS#11 path (`ssh -I`) only drives RSA / NIST-ECDSA tokens, so it
can't use our Ed25519 keys. The agent protocol, by contrast, works natively with
Ed25519, which is why this is the supported path today.

## Build
```sh
make ssh-agent          # or: cmake -S host/tools/openhsm-ssh-agent -B .../build && cmake --build .../build
```
Needs `libusb-1.0` and `libsodium`.

## Run
```sh
openhsm-ssh-agent [-a <socket>] [-k <key-id> | -l <label>] [-c <comment>]
                  [--pin <pin>] [--addr <host:port>]
```
- `-l <label>` pick the Ed25519 key by label (default `myssh`); `-k <id>` by id.
- `-a <socket>` unix socket path (default `/tmp/openhsm-ssh-agent.<pid>.sock`).
- `--pin` device PIN (or env `OPENHSM_PIN`; default `123456`).
- `--addr host:port` talk to an `openhsm-daemon` instead of direct USB
  (or env `OPENHSM_ADDR`) — lets the key live on a remote HSM node.

The agent runs in the foreground and prints the socket path. In another shell:
```sh
export SSH_AUTH_SOCK=/tmp/openhsm-ssh-agent.<pid>.sock
ssh-add -l                  # lists the device key
ssh-add -L                  # prints the public key line for authorized_keys
ssh user@server             # logs in; the signature is computed on the HSM
```

> Don't pass `ssh -o IdentitiesOnly=yes` without `-i`: it makes OpenSSH ignore
> agent keys and use only on-disk identity files.

## Provisioning a server

Add the device's public key to the target's `~/.ssh/authorized_keys`:
```sh
ssh-add -L >> ~/.ssh/authorized_keys      # via a running agent
# or directly from the device:
openhsm-cli pubkey <id>                    # raw 32-byte hex (then wrap as ssh-ed25519)
```

If you don't have a signing key yet, create one on the device:
```sh
openhsm-cli gen ed25519 myssh sign
```

## Local end-to-end test (`docker/`)

A throwaway Alpine `sshd` container that trusts only the device key:
```sh
cd host/tools/openhsm-ssh-agent
openhsm-cli pubkey 45 | tail -1 | \
  python3 -c 'import sys,base64,struct;p=bytes.fromhex(sys.stdin.read().split()[-1]);\
print("ssh-ed25519",base64.b64encode(struct.pack(">I",11)+b"ssh-ed25519"+struct.pack(">I",32)+p).decode(),"openhsm")' \
  > docker/authorized_keys
docker build -t openhsm-sshtest docker/
docker run -d --name openhsm-sshtest -p 2222:22 openhsm-sshtest

openhsm-ssh-agent -a /tmp/ohsm-agent.sock -l myssh &
SSH_AUTH_SOCK=/tmp/ohsm-agent.sock ssh -p 2222 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  tester@localhost 'id'        # -> uid=...(tester); signed on the HSM
```
Cleanup: `docker rm -f openhsm-sshtest; pkill -f openhsm-ssh-agent`.

## Notes / limits
- One key per agent instance (run several for several keys).
- The data to sign must fit one device message (≤ ~500 B). SSH user-auth blobs
  are well under that.
- Unsupported agent ops (add/remove/lock, `session-bind@openssh.com`) return
  failure; OpenSSH proceeds without them.
