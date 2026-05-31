# OpenBao + OpenHSM PKCS#11 provider, reaching a USB-attached HSM over the
# network via openhsm-daemon (no USB passthrough needed → container/k8s ready).
#
# Build from the repo root (build context = repo root):
#   docker build -f host/openbao/Dockerfile -t openhsm/openbao .

# ---- stage 1: build OpenBao with the PKCS#11 (hsm) build tag --------------
FROM golang:1.24-bookworm AS bao
RUN apt-get update && apt-get install -y --no-install-recommends \
        git gcc libc6-dev && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/openbao/openbao /src
WORKDIR /src
RUN CGO_ENABLED=1 go build -tags hsm -o /bao-hsm .

# ---- stage 2: build the OpenHSM PKCS#11 module as a Linux .so --------------
FROM debian:bookworm-slim AS module
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev cmake pkg-config libusb-1.0-0-dev libsodium-dev \
        && rm -rf /var/lib/apt/lists/*
COPY firmware/src/hsm /src/firmware/src/hsm
COPY host/pkcs11      /src/host/pkcs11
WORKDIR /src/host/pkcs11
RUN cmake -S . -B build && cmake --build build --target openhsm_pkcs11

# ---- stage 3: runtime ------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libusb-1.0-0 libsodium23 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=bao    /bao-hsm /usr/local/bin/bao
COPY --from=module /src/host/pkcs11/build/libopenhsm_pkcs11.so /usr/local/lib/
COPY host/openbao/config.docker.hcl /etc/openbao/config.hcl
RUN mkdir -p /openbao/data

# Reached via openhsm-daemon; override for your daemon host/port.
ENV OPENHSM_ADDR=host.docker.internal:11700
EXPOSE 8200
ENTRYPOINT ["bao", "server", "-config=/etc/openbao/config.hcl"]
