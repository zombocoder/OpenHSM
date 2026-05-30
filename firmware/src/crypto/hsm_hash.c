/**
 * @file    hsm_hash.c
 * @brief   SHA-256 / HMAC-SHA256 / HKDF-SHA256 via the STM32 HASH peripheral.
 *
 * The HASH block is single-context here: each call fully (re)initialises it,
 * which is fine for our sequential, non-interrupt crypto use.
 */
#include "hsm_hash.h"
#include "stm32u5xx_hal.h"

#include <string.h>

static HASH_HandleTypeDef hhash;

int HSM_Sha256(const uint8_t *data, size_t len, uint8_t out[HSM_SHA256_LEN])
{
    hhash.Init.DataType = HASH_DATATYPE_8B;
    hhash.Init.pKey     = NULL;
    hhash.Init.KeySize  = 0;
    if (HAL_HASH_Init(&hhash) != HAL_OK) {
        return -1;
    }
    if (HAL_HASHEx_SHA256_Start(&hhash, (uint8_t *)data, (uint32_t)len,
                                out, HAL_MAX_DELAY) != HAL_OK) {
        return -1;
    }
    return 0;
}

int HSM_HmacSha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[HSM_SHA256_LEN])
{
    hhash.Init.DataType = HASH_DATATYPE_8B;
    hhash.Init.pKey     = (uint8_t *)key;
    hhash.Init.KeySize  = (uint32_t)key_len;
    if (HAL_HASH_Init(&hhash) != HAL_OK) {
        return -1;
    }
    if (HAL_HMACEx_SHA256_Start(&hhash, (uint8_t *)data, (uint32_t)data_len,
                                out, HAL_MAX_DELAY) != HAL_OK) {
        return -1;
    }
    return 0;
}

int HSM_HkdfExtract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t prk[HSM_SHA256_LEN])
{
    static const uint8_t zero_salt[HSM_SHA256_LEN] = {0};
    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    return HSM_HmacSha256(salt, salt_len, ikm, ikm_len, prk);
}

int HSM_HkdfSha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len)
{
    uint8_t prk[HSM_SHA256_LEN];
    if (HSM_HkdfExtract(salt, salt_len, ikm, ikm_len, prk) != 0) {
        return -1;
    }

    /* Expand: T(i) = HMAC(PRK, T(i-1) || info || i) */
    uint8_t t[HSM_SHA256_LEN];
    uint8_t block[HSM_SHA256_LEN + 256 + 1];
    size_t  t_len = 0;
    size_t  done = 0;
    uint8_t counter = 1;

    if (info_len > 256) {
        return -1; /* keep the temp block bounded */
    }

    while (done < out_len) {
        size_t off = 0;
        memcpy(block + off, t, t_len); off += t_len;          /* T(i-1) */
        if (info_len) { memcpy(block + off, info, info_len); off += info_len; }
        block[off++] = counter;

        if (HSM_HmacSha256(prk, sizeof(prk), block, off, t) != 0) {
            return -1;
        }
        t_len = HSM_SHA256_LEN;

        size_t chunk = (out_len - done) < HSM_SHA256_LEN ? (out_len - done)
                                                         : HSM_SHA256_LEN;
        memcpy(out + done, t, chunk);
        done += chunk;
        counter++;
    }
    return 0;
}
