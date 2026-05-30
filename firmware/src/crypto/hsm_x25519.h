/**
 * @file    hsm_x25519.h
 * @brief   X25519 ECDH (Monocypher), with the curve clamping per RFC 7748.
 */
#ifndef OPENHSM_HSM_X25519_H
#define OPENHSM_HSM_X25519_H

#include <stdint.h>

#define HSM_X25519_LEN 32u

/** @brief Derive the public key for a secret scalar. */
void HSM_X25519_PublicKey(uint8_t public_key[HSM_X25519_LEN],
                          const uint8_t secret_key[HSM_X25519_LEN]);

/**
 * @brief Compute the X25519 shared secret.
 * @return 0 on success, -1 if the result is all-zero (low-order point).
 */
int HSM_X25519_Shared(uint8_t shared[HSM_X25519_LEN],
                      const uint8_t secret_key[HSM_X25519_LEN],
                      const uint8_t their_public[HSM_X25519_LEN]);

#endif /* OPENHSM_HSM_X25519_H */
