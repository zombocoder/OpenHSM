/**
 * @file    hsm_session.h
 * @brief   Secure session layer: X25519 ECDH -> HKDF -> AES-256-GCM transport.
 */
#ifndef OPENHSM_HSM_SESSION_H
#define OPENHSM_HSM_SESSION_H

#include <stdint.h>
#include <stddef.h>

#define HSM_MAX_SESSIONS 4u

/** @brief Reset the session table (e.g. at boot or on tamper). */
void HSM_Session_Init(void);

/** @brief Handle an OPEN_SESSION request (plaintext ECDH handshake). */
size_t HSM_Session_Open(const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_cap);

/** @brief Handle a CLOSE_SESSION request; zeroizes session keys. */
size_t HSM_Session_Close(const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t resp_cap);

/**
 * @brief Decrypt an encrypted envelope, run the inner command as plaintext,
 *        and return an encrypted response. Enforces the anti-replay counter.
 */
size_t HSM_Session_Unwrap(const uint8_t *req, size_t req_len,
                          uint8_t *resp, size_t resp_cap);

#endif /* OPENHSM_HSM_SESSION_H */
