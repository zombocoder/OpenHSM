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

#endif /* OPENHSM_HSM_COMMAND_H */
