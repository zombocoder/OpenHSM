/**
 * @file    hsm_hash.h
 * @brief   SHA-256 / HMAC-SHA256 / HKDF-SHA256 (STM32 HASH hardware).
 */
#ifndef OPENHSM_HSM_HASH_H
#define OPENHSM_HSM_HASH_H

#include <stdint.h>
#include <stddef.h>

#define HSM_SHA256_LEN 32u

/** @brief SHA-256 digest of @p data. @return 0 on success. */
int HSM_Sha256(const uint8_t *data, size_t len, uint8_t out[HSM_SHA256_LEN]);

/** @brief HMAC-SHA256 with an arbitrary-length key. @return 0 on success. */
int HSM_HmacSha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[HSM_SHA256_LEN]);

/**
 * @brief HKDF-SHA256 extract + expand (RFC 5869).
 * @param out_len  desired output length (<= 255*32).
 * @return 0 on success.
 */
int HSM_HkdfSha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len);

/** @brief HKDF-Extract only: PRK = HMAC(salt, IKM). */
int HSM_HkdfExtract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t prk[HSM_SHA256_LEN]);

#endif /* OPENHSM_HSM_HASH_H */
