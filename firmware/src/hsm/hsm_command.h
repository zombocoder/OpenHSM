/**
 * @file    hsm_command.h
 * @brief   OpenHSM command dispatcher (transport-agnostic).
 */
#ifndef OPENHSM_HSM_COMMAND_H
#define OPENHSM_HSM_COMMAND_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Process one request packet and build a response packet.
 *
 * @param req      Pointer to the received packet (header + payload).
 * @param req_len  Number of valid bytes in @p req.
 * @param resp     Output buffer for the response packet (>= HSM_MAX_PACKET).
 * @param resp_cap Capacity of @p resp in bytes.
 * @return Number of bytes written to @p resp, or 0 if no response should be
 *         sent (e.g. malformed packet too short to even hold a header).
 */
size_t HSM_ProcessPacket(const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t resp_cap);

/**
 * @brief Process a plaintext (already-decrypted) command packet.
 *        Used directly for plaintext commands and by the session layer for the
 *        inner command of an encrypted envelope.
 * @param auth  Pointer to the caller's login flag — per-session for an encrypted
 *              envelope, or a process-global flag for the plaintext path. AUTH
 *              sets it; gated commands require it. Binding it to the session
 *              means a login on one session does not unlock another.
 */
size_t HSM_ProcessPlaintext(const uint8_t *req, size_t req_len,
                            uint8_t *resp, size_t resp_cap, int *auth);

/** @brief Build a response header in @p resp; returns total packet length. */
size_t HSM_BuildResponse(uint8_t *resp, const uint8_t *req_hdr,
                         uint16_t status, uint16_t payload_len);

#endif /* OPENHSM_HSM_COMMAND_H */
