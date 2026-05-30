/**
 * @file    hsm_aead.h
 * @brief   AES-256-GCM authenticated encryption (STM32 AES hardware).
 *
 * Buffers passed here must be 4-byte aligned (the HAL accesses them as
 * 32-bit words). The session/command buffers and KAT scratch satisfy this.
 */
#ifndef OPENHSM_HSM_AEAD_H
#define OPENHSM_HSM_AEAD_H

#include <stdint.h>
#include <stddef.h>

#define HSM_GCM_KEY_LEN   32u
#define HSM_GCM_NONCE_LEN 12u
#define HSM_GCM_TAG_LEN   16u

/**
 * @brief AES-256-GCM encrypt. @p ct_out may alias @p pt (same length).
 * @return 0 on success.
 */
int HSM_AesGcmEncrypt(const uint8_t key[HSM_GCM_KEY_LEN],
                      const uint8_t nonce[HSM_GCM_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *pt, size_t pt_len,
                      uint8_t *ct_out, uint8_t tag_out[HSM_GCM_TAG_LEN]);

/**
 * @brief AES-256-GCM decrypt + verify tag (constant-time compare).
 * @return 0 on success, -1 on authentication failure or error.
 */
int HSM_AesGcmDecrypt(const uint8_t key[HSM_GCM_KEY_LEN],
                      const uint8_t nonce[HSM_GCM_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      const uint8_t tag[HSM_GCM_TAG_LEN],
                      uint8_t *pt_out);

#endif /* OPENHSM_HSM_AEAD_H */
