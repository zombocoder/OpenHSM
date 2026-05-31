/**
 * @file    hsm_ecdsa_p256.h
 * @brief   NIST P-256 (secp256r1) ECDSA via the STM32U5 hardware PKA.
 *
 * Keys are a 32-byte big-endian private scalar; the public key is the affine
 * point X||Y (64 bytes). Signing operates on a 32-byte message digest (the
 * caller hashes, matching PKCS#11 CKM_ECDSA) and returns r||s (64 bytes).
 */
#ifndef OPENHSM_HSM_ECDSA_P256_H
#define OPENHSM_HSM_ECDSA_P256_H

#include <stdint.h>

/** @brief Public key X||Y (64 B) from a 32-byte private scalar. @return 0 ok. */
int HSM_EcdsaP256_Public(const uint8_t priv[32], uint8_t pub[64]);

/** @brief Sign a 32-byte digest; output r||s (64 B). Uses a fresh TRNG nonce.
 *  @return 0 on success, non-zero on failure. */
int HSM_EcdsaP256_Sign(const uint8_t priv[32], const uint8_t digest[32], uint8_t sig[64]);

/** @brief Verify r||s (64 B) over a 32-byte digest with public key X||Y (64 B).
 *  @return 0 if the signature is valid, non-zero otherwise. */
int HSM_EcdsaP256_Verify(const uint8_t pub[64], const uint8_t digest[32], const uint8_t sig[64]);

#endif /* OPENHSM_HSM_ECDSA_P256_H */
