/**
 * @file    openhsm_transport.h
 * @brief   USB transport for the OpenHSM host stack (libusb).
 *
 * Phase A: plaintext command exchange (multi-packet framed). The encrypted
 * session (X25519/AES-GCM) layers on top of this later for command privacy.
 */
#ifndef OPENHSM_TRANSPORT_H
#define OPENHSM_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

typedef struct ohsm_ctx ohsm_ctx;

/** @brief Open the first OpenHSM device. Returns NULL on failure. */
ohsm_ctx *ohsm_open(void);

/** @brief Close and free the context. */
void ohsm_close(ohsm_ctx *c);

/**
 * @brief Send a plaintext command and read the response.
 * @param command  hsm_command_t
 * @param payload  request payload (may be NULL)
 * @param plen     payload length
 * @param resp     response buffer (full packet incl. 16-byte header)
 * @param resp_cap capacity of resp
 * @param resp_len out: bytes received
 * @return 0 on USB success (check the response header status separately).
 */
int ohsm_cmd(ohsm_ctx *c, uint16_t command,
             const uint8_t *payload, uint16_t plen,
             uint8_t *resp, int resp_cap, int *resp_len);

#endif /* OPENHSM_TRANSPORT_H */
