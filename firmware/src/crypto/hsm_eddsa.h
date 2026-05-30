/**
 * @file    hsm_eddsa.h
 * @brief   Ed25519 signing (RFC 8032 / SHA-512) via Monocypher.
 *
 * Compatible with libsodium's crypto_sign verification using the matching
 * public key.
 */
#ifndef OPENHSM_HSM_EDDSA_H
#define OPENHSM_HSM_EDDSA_H

#include <stdint.h>
#include <stddef.h>

#define HSM_ED25519_SEED_LEN 32u
#define HSM_ED25519_PUB_LEN  32u
#define HSM_ED25519_SIG_LEN  64u

/** @brief Derive the public key from a 32-byte seed. */
void HSM_Ed25519_Public(const uint8_t seed[HSM_ED25519_SEED_LEN],
                        uint8_t pub[HSM_ED25519_PUB_LEN]);

/** @brief Sign @p msg with the key derived from @p seed. */
void HSM_Ed25519_Sign(const uint8_t seed[HSM_ED25519_SEED_LEN],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t sig[HSM_ED25519_SIG_LEN]);

#endif /* OPENHSM_HSM_EDDSA_H */
